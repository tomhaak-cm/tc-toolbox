#!/usr/bin/env node
// @ts-check
/**
 * Report npm/pnpm vulnerabilities and try to fix high and critical findings.
 *
 * Node.js standard library, git, the tools named in package.json engines, and (for --push) gh.
 * CVE lookups require GH_TOKEN, GITHUB_TOKEN, or an authenticated gh.
 * Use --dryrun for a terminal report without repository or Git changes.
 */

import { spawnSync } from "node:child_process";
import {
  accessSync,
  appendFileSync,
  constants,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";

/** @typedef {"npm" | "pnpm"} Manager */
/** @typedef {"patch" | "minor" | "major"} Risk */
/** @typedef {"solved" | "persisting" | "deferred"} Status */
/** @typedef {[number, number, number]} Version */
/** @typedef {Map<string, Set<string>>} VersionMap */

/**
 * @typedef {Object} Advisory
 * @property {string} id Advisory key (GHSA id or advisory id)
 * @property {string} package
 * @property {string} severity
 * @property {string} title
 * @property {string} url
 * @property {string[]} cves
 * @property {string} vulnerable
 * @property {string} patched
 * @property {string[]} versions
 * @property {string[]} paths
 */

/** @typedef {Advisory & { status: Status, detail: string, workspace?: string, error?: string }} Result */

/**
 * @typedef {Object} PackageJson
 * @property {string} [name]
 * @property {string} [packageManager]
 * @property {unknown} [workspaces]
 * @property {Record<string, string>} [scripts]
 * @property {Record<string, unknown>} [engines]
 */

/**
 * @typedef {Object} DependencyNode
 * @property {string} [name]
 * @property {string} [version]
 * @property {Record<string, DependencyNode>} [dependencies]
 * @property {Record<string, DependencyNode>} [devDependencies]
 * @property {Record<string, DependencyNode>} [optionalDependencies]
 */

/**
 * @typedef {Object} WhyEntry
 * @property {Record<string, DependencyNode>} [dependencies]
 * @property {Record<string, DependencyNode>} [devDependencies]
 * @property {Record<string, DependencyNode>} [optionalDependencies]
 * @property {string} [name]
 * @property {Array<{ name: string, depField?: string, from?: { name?: string, isWorkspace?: boolean, location?: string } }>} [dependents]
 */

/**
 * @typedef {Object} RawVia
 * @property {string | number} source
 * @property {string} severity
 * @property {string} [name]
 * @property {string} [title]
 * @property {string} [url]
 * @property {string} [range]
 */

/**
 * @typedef {Object} RawVulnerability
 * @property {Array<string | RawVia>} [via]
 * @property {boolean} [fixAvailable]
 * @property {string[]} [nodes]
 */

/**
 * @typedef {Object} RawAdvisory
 * @property {string | number} [id]
 * @property {string} [github_advisory_id]
 * @property {string} [module_name]
 * @property {string} [severity]
 * @property {string} [title]
 * @property {string} [url]
 * @property {string[]} [cves]
 * @property {string} [vulnerable_versions]
 * @property {string} [patched_versions]
 * @property {Array<{ paths?: string[], version?: string }>} [findings]
 */

/**
 * @typedef {Object} AuditReport
 * @property {Record<string, RawAdvisory>} [advisories]
 * @property {Record<string, RawVulnerability>} [vulnerabilities]
 */

/**
 * @typedef {Object} FixArgs
 * @property {boolean} auditOnly
 * @property {boolean} commit
 * @property {boolean} push
 * @property {string} registry
 * @property {boolean} allowMajor
 * @property {boolean} allowOverride
 */

const REGISTRY = "https://registry.npmjs.org/";
const GITHUB_GRAPHQL = "https://api.github.com/graphql";
const SEVERE_LEVELS = ["high", "critical"];
/** @type {readonly Risk[]} */
const RISKS = ["patch", "minor", "major"];
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".turbo", ".oci-build", "ai-foundation"]);
const LOCKFILES = ["pnpm-lock.yaml", "package-lock.json", "npm-shrinkwrap.json"];
const MANIFESTS = ["package.json", "pnpm-workspace.yaml", ...LOCKFILES];
const PACKAGE_MANAGERS = ["npm", "pnpm", "yarn"];
const PACKAGE_NAME = /^(?:@[a-z0-9._~-]+\/)?[a-z0-9][a-z0-9._~-]*$/;
const WILDCARDS = new Set(["", "x", "X", "*"]);
const COMPARATOR = /(<=|>=|<|>|=|\^|~)?\s*([0-9A-Za-z.*+-]+)/g;
const OVERRIDE_NOTE =
  "Override from `pnpm audit --fix`. It breaks semver. Tell the maintainers, " +
  "create a follow-up CMS issue with advisory links to remove the override, and add a release note.";
const EXIT_ENGINE_MISMATCH = 3;

const USAGE = `Usage: fix_cves.mjs [options]

Report npm/pnpm vulnerabilities and try to fix high and critical findings.

Options:
  --repo DIR              Git repository (default: current directory)
  --base BRANCH           Base branch name (default: current branch; required on a detached HEAD)
  --workspace PATH        npm/pnpm root relative to the repository (repeatable; default: discover roots)
  --dryrun, --audit-only  Audit only. No pull, repository dependency changes, or report files
  --commit                Create a fix branch and commit dependency changes
  --checks JSON           Override build/lint/test commands: {"<workspace>": {"<name>": ["argv", ...]}}
  --out DIR               Report directory (default: ./cache/fix-cves-report)
  --registry URL          npm registry (default: ${REGISTRY})
  --allow-major           Permit major upgrades (explicit approval)
  --allow-override        Last resort: permit pnpm audit --fix overrides (explicit approval)
  --push                  Push the branch and create a PR with gh
  -h, --help              Show this help
`;

class Failure extends Error {}

class EngineMismatch extends Failure {}

class HttpError extends Error {
  /**
   * @param {number} status
   * @param {string} statusText
   */
  constructor(status, statusText) {
    super(`HTTP Error ${status}: ${statusText}`);
    this.status = status;
  }
}

/** @typedef {{ write: (message: string) => void }} Sink */
/** @type {Sink[]} */
const sinks = [];

/** @param {string} message */
function info(message) {
  for (const sink of sinks) sink.write(message);
}

/** @param {string} line @returns {[string, string]} */
function labelOf(line) {
  if (line.startsWith("$ ")) return ["RUN", "36"];
  if (line.startsWith("UPGRADE ")) return ["FIXED", "32"];
  if (line.startsWith("NOT FIXED ")) return ["BLOCKED", "33"];
  if (line.startsWith("ERROR") || line.startsWith("Workspace repair failed:")) return ["ERROR", "31"];
  if (line.startsWith("SUMMARY")) return ["SUMMARY", "35"];
  if (line.startsWith("SOLVED (")) return ["SOLVED", "32"];
  if (line.startsWith("PERSISTING (")) return ["OPEN", "31"];
  if (line.startsWith("DEFERRED (")) return ["DEFERRED", "33"];
  if (line.startsWith("Reports:")) return ["REPORT", "36"];
  if (line.startsWith("Last resort") || line.startsWith("CVE lookup failed:")) return ["WARN", "33"];
  return ["INFO", "2"];
}

/** @param {number} n */
const pad2 = (n) => String(n).padStart(2, "0");

/**
 * @param {string} message
 * @param {boolean} color
 */
function formatLog(message, color) {
  const now = new Date();
  const clock = `${pad2(now.getHours())}:${pad2(now.getMinutes())}:${pad2(now.getSeconds())}`;
  return message
    .split("\n")
    .map((line, index) => {
      const [label, code] = labelOf(line);
      const stamp = index === 0 ? clock : " ".repeat(8);
      if (!color) return `${stamp}  ${label.padEnd(7)}  ${line}`;
      return `\x1b[2m${stamp}\x1b[0m  \x1b[${code}m${label.padEnd(7)}\x1b[0m  ${line}`;
    })
    .join("\n");
}

/** @param {boolean} color @returns {Sink} */
const consoleSink = (color) => ({
  write: (message) => {
    process.stdout.write(formatLog(message, color) + "\n");
  },
});

/** @param {string} file @returns {Sink} */
const fileSink = (file) => ({
  write: (message) => {
    appendFileSync(file, formatLog(message, false) + "\n");
  },
});

/** @param {unknown} error */
function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Errors that the repair loop reports instead of crashing on.
 * @param {unknown} error
 */
function isExpected(error) {
  return error instanceof Failure || error instanceof SyntaxError || (error instanceof Error && "code" in error);
}

/**
 * @param {string} tool
 * @returns {NodeJS.ProcessEnv}
 */
function childEnv(tool) {
  if (tool === "git" || tool === "gh") return process.env;
  /** @type {NodeJS.ProcessEnv} */
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => key !== "GH_TOKEN" && key !== "GITHUB_TOKEN"),
  );
  if (tool === "pnpm") env.pnpm_config_verify_deps_before_run = "false";
  return env;
}

/**
 * @param {string[]} args
 * @param {string} cwd
 * @param {number[]} allowed
 * @returns {{ stdout: string, stderr: string }}
 */
function execute(args, cwd, allowed) {
  info(`$ ${args.join(" ")}    [${cwd}]`);
  const [tool, ...rest] = args;
  const result = spawnSync(tool, rest, {
    cwd,
    env: childEnv(tool),
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
  });
  if (result.error) throw new Failure(`Cannot run ${tool}: ${result.error.message}`);
  const status = result.status ?? -1;
  if (!allowed.includes(status)) {
    const output = (result.stderr.trim() || result.stdout.trim()).slice(-2000);
    info(`  exit ${status}: ${output}`);
    throw new Failure(`\`${args.slice(0, 4).join(" ")}\` failed (exit ${status}): ${output}`);
  }
  return { stdout: result.stdout, stderr: result.stderr };
}

/**
 * @param {string[]} args
 * @param {string} cwd
 * @param {number[]} [allowed]
 * @returns {string}
 */
function run(args, cwd, allowed = [0]) {
  const { stdout, stderr } = execute(args, cwd, allowed);
  if (stdout.trim()) info(stdout.trim());
  if (stderr.trim()) info(stderr.trim());
  return stdout;
}

/**
 * @param {string[]} args
 * @param {string} cwd
 * @param {number[]} [allowed]
 * @returns {unknown}
 */
function runJson(args, cwd, allowed = [0]) {
  const { stdout } = execute(args, cwd, allowed);
  if (!stdout.trim()) throw new Failure(`\`${args.slice(0, 3).join(" ")}\` returned empty JSON output`);
  try {
    return JSON.parse(stdout);
  } catch {
    throw new Failure(`\`${args.slice(0, 3).join(" ")}\` did not return JSON`);
  }
}

/**
 * @template T
 * @param {() => T} action
 * @param {(detail: string) => string} describe
 * @returns {T}
 */
function orEngineMismatch(action, describe) {
  try {
    return action();
  } catch (error) {
    if (error instanceof Failure) throw new EngineMismatch(describe(error.message));
    throw error;
  }
}

/**
 * @param {string} base
 * @param {Date} date
 * @returns {string}
 */
export function branchName(base, date) {
  const yymmdd = `${pad2(date.getFullYear() % 100)}${pad2(date.getMonth() + 1)}${pad2(date.getDate())}`;
  return `venus/fix-cves-${yymmdd}-${base.replaceAll("/", "-")}`;
}

/** @param {string} file */
const isFile = (file) => existsSync(file) && statSync(file).isFile();

/** @param {string} file */
function resolvePath(file) {
  try {
    return realpathSync(file);
  } catch {
    return path.resolve(file);
  }
}

/**
 * @param {string} child
 * @param {string} parent
 */
function isInside(child, parent) {
  const prefix = parent.endsWith(path.sep) ? parent : parent + path.sep;
  return child === parent || child.startsWith(prefix);
}

/**
 * @param {string} file
 * @returns {PackageJson}
 */
function readManifest(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

/**
 * @param {PackageJson} manifest
 * @returns {boolean}
 */
function hasWorkspaces(manifest) {
  const value = manifest.workspaces;
  if (Array.isArray(value)) return value.length > 0;
  return value !== null && typeof value === "object" && Object.keys(value).length > 0;
}

/**
 * Yield each directory under root (root first), skipping SKIP_DIRS and not following symlinks.
 * @param {string} root
 * @returns {Generator<{ dir: string, files: string[] }>}
 */
function* walk(root) {
  const entries = readdirSync(root, { withFileTypes: true });
  yield { dir: root, files: entries.filter((entry) => !entry.isDirectory()).map((entry) => entry.name) };
  const subdirs = entries
    .filter((entry) => entry.isDirectory() && !SKIP_DIRS.has(entry.name))
    .map((entry) => entry.name)
    .sort();
  for (const name of subdirs) yield* walk(path.join(root, name));
}

/** @param {string} repo */
function findWorkspaces(repo) {
  /** @type {string[]} */
  const found = [];
  /** @type {string[]} */
  const workspaceRoots = [];
  for (const { dir, files } of walk(repo)) {
    if (!files.includes("package.json")) continue;
    const manifest = readManifest(path.join(dir, "package.json"));
    const isWorkspace = files.includes("pnpm-workspace.yaml") || hasWorkspaces(manifest);
    const isMember = workspaceRoots.some((root) => isInside(dir, root));
    if (isWorkspace || LOCKFILES.some((name) => files.includes(name)) || !isMember) found.push(dir);
    if (isWorkspace) workspaceRoots.push(dir);
  }
  return found;
}

/**
 * @param {string} workspace
 * @returns {Manager}
 */
function manager(workspace) {
  const declared = (readManifest(path.join(workspace, "package.json")).packageManager ?? "").split("@")[0];
  if (declared === "npm" || declared === "pnpm") return declared;
  const pnpm =
    existsSync(path.join(workspace, "pnpm-lock.yaml")) || existsSync(path.join(workspace, "pnpm-workspace.yaml"));
  return pnpm ? "pnpm" : "npm";
}

/**
 * @param {string} repo
 * @param {string[]} selected
 */
function candidateWorkspaces(repo, selected) {
  return selected.length ? selected.map((w) => resolvePath(path.resolve(repo, w))) : findWorkspaces(repo);
}

/* ---------- semver and engines ---------- */

/** @param {string} text @returns {number[]} */
function versionParts(text) {
  const core = text.trim().replace(/^v+/, "").split(/[-+]/)[0];
  /** @type {number[]} */
  const parts = [];
  for (const part of core.split(".").slice(0, 3)) {
    if (WILDCARDS.has(part)) break;
    if (!/^\d+$/.test(part)) throw new Failure(`Cannot read version or range bound: ${text}`);
    parts.push(Number(part));
  }
  return parts;
}

/** @param {string} text @returns {Version} */
function parseVersion(text) {
  return padded(text.split(".").map(Number));
}

/** @param {number[]} parts @returns {Version} */
function padded(parts) {
  return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
}

/**
 * @param {number[]} parts
 * @param {number} index
 * @returns {Version}
 */
function bump(parts, index) {
  return padded([...parts.slice(0, index), (parts[index] ?? 0) + 1]);
}

/**
 * @param {Version} a
 * @param {Version} b
 * @returns {number}
 */
function compareVersions(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

/**
 * @param {string} operator
 * @param {string} text
 * @param {Version} installed
 * @returns {boolean}
 */
function comparatorMatches(operator, text, installed) {
  const parts = versionParts(text);
  if (!parts.length) return true;
  const low = padded(parts);
  const partial = parts.length < 3;
  const last = parts.length - 1;
  switch (operator) {
    case "":
    case "=":
      return partial
        ? compareVersions(low, installed) <= 0 && compareVersions(installed, bump(parts, last)) < 0
        : compareVersions(installed, low) === 0;
    case "^": {
      const firstNonZero = parts.findIndex((part) => part !== 0);
      const index = firstNonZero === -1 ? last : firstNonZero;
      return compareVersions(low, installed) <= 0 && compareVersions(installed, bump(parts, index)) < 0;
    }
    case "~":
      return (
        compareVersions(low, installed) <= 0 &&
        compareVersions(installed, bump(parts, parts.length === 1 ? 0 : 1)) < 0
      );
    case ">=":
      return compareVersions(installed, low) >= 0;
    case ">":
      return partial
        ? compareVersions(installed, bump(parts, last)) >= 0
        : compareVersions(installed, low) > 0;
    case "<":
      return compareVersions(installed, low) < 0;
    case "<=":
      return partial
        ? compareVersions(installed, bump(parts, last)) < 0
        : compareVersions(installed, low) <= 0;
    default:
      throw new Failure(`Unknown operator in engines range: ${operator}`);
  }
}

/**
 * @param {string} installedText
 * @param {unknown} requirement
 * @returns {boolean}
 */
export function satisfies(installedText, requirement) {
  if (typeof requirement !== "string") {
    throw new Failure(`Engines range must be a string: ${JSON.stringify(requirement)}`);
  }
  const installed = padded(versionParts(installedText));
  for (const alternative of requirement.split("||")) {
    /** @type {Array<[string, string]>} */
    let pairs;
    if (/\s-\s/.test(alternative)) {
      const range = alternative.trim().match(/^(.*?)\s+-\s+(.*)$/);
      if (!range) throw new Failure(`Cannot read version range: ${alternative}`);
      pairs = [
        [">=", range[1]],
        ["<=", range[2]],
      ];
    } else {
      pairs = [...alternative.matchAll(COMPARATOR)].map((match) => [match[1] ?? "", match[2]]);
    }
    if (pairs.every(([operator, text]) => comparatorMatches(operator, text, installed))) return true;
  }
  return false;
}

/**
 * @param {string} repo
 * @returns {Array<{ file: string, engines: Record<string, unknown> }>}
 */
function findProjects(repo) {
  const found = [];
  for (const { dir, files } of walk(repo)) {
    if (!files.includes("package.json")) continue;
    const engines = readManifest(path.join(dir, "package.json")).engines;
    if (engines && Object.keys(engines).length) {
      found.push({ file: path.relative(repo, path.join(dir, "package.json")), engines });
    }
  }
  return found;
}

/** @param {string} command @returns {string | null} */
function which(command) {
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, command);
    try {
      accessSync(candidate, constants.X_OK);
      if (statSync(candidate).isFile()) return candidate;
    } catch {
      // Not an executable in this directory.
    }
  }
  return null;
}

/**
 * @param {string} output
 * @param {(version: string) => boolean} accept
 * @returns {string[]}
 */
function nodeVersionsIn(output, accept) {
  /** @type {Set<string>} */
  const found = new Set();
  for (const line of output.split("\n")) {
    const match = /^\s*(?:->\s*)?v(\d+\.\d+\.\d+)(?=\s|$)/.exec(line);
    if (match && accept(match[1])) found.add(match[1]);
  }
  return [...found].sort((a, b) => compareVersions(parseVersion(b), parseVersion(a)));
}

/**
 * @param {string} repo
 * @param {string} tempDir
 * @returns {boolean} true when Corepack shims were enabled
 */
function configureEngines(repo, tempDir) {
  /** @type {Map<string, Array<{ project: string, requirement: unknown }>>} */
  const declared = new Map();
  for (const { file, engines } of findProjects(repo)) {
    for (const [tool, requirement] of Object.entries(engines)) {
      const list = declared.get(tool) ?? [];
      list.push({ project: file, requirement });
      declared.set(tool, list);
    }
  }
  const requirementsOf = (/** @type {string} */ tool) => declared.get(tool) ?? [];
  const matches = (/** @type {string} */ tool, /** @type {string} */ version) =>
    requirementsOf(tool).every(({ requirement }) => satisfies(version, requirement));

  if (declared.has("node")) {
    const nvmDir = process.env.NVM_DIR ?? path.join(os.homedir(), ".nvm");
    const nvmScript = path.join(nvmDir, "nvm.sh");
    if (!isFile(nvmScript)) {
      throw new EngineMismatch(`NVM not found: ${nvmScript}. Set NVM_DIR to its installation directory.`);
    }
    /**
     * @param {string} command
     * @param {string[]} args
     * @param {number[]} [allowed]
     */
    const nvm = (command, args = [], allowed = [0]) =>
      orEngineMismatch(
        () => run(["bash", "-c", '. "$1" --no-use && shift && nvm "$@"', "nvm", nvmScript, command, ...args], repo, allowed),
        (detail) => `NVM ${command} failed: ${detail}`,
      );
    const accept = (/** @type {string} */ version) => matches("node", version);

    const installed = nodeVersionsIn(nvm("ls", ["--no-colors"], [0, 3]), accept);
    /** @type {string} */
    let version;
    if (installed.length) {
      version = installed[0];
    } else {
      const available = nodeVersionsIn(nvm("ls-remote", ["--no-colors"]), accept);
      if (!available.length) {
        throw new EngineMismatch(
          `No Node.js version satisfies all engine requirements: ${JSON.stringify(requirementsOf("node").map((r) => r.requirement))}`,
        );
      }
      version = available[0];
      nvm("install", [version]);
    }
    const nodePath = orEngineMismatch(
      () =>
        run(
          ["bash", "-c", '. "$1" --no-use && nvm use --silent "$2" && printf "%s" "$PATH"', "nvm", nvmScript, version],
          repo,
        ).trim(),
      (detail) => `NVM could not switch to Node.js ${version}: ${detail}`,
    );
    process.env.PATH = nodePath;
    const actual = orEngineMismatch(
      () => run(["node", "--version"], repo).trim(),
      (detail) => `Cannot run Node.js after NVM switch: ${detail}`,
    );
    if (compareVersions(padded(versionParts(actual)), parseVersion(version)) !== 0) {
      throw new EngineMismatch(`NVM selected Node.js ${version}, but PATH resolves to ${actual}`);
    }
    info(`Using Node.js ${version}`);
  }

  let corepackEnabled = false;
  let shimDir = "";
  for (const tool of [...declared.keys()].sort()) {
    if (tool === "node") continue;
    const isPackageManager = PACKAGE_MANAGERS.includes(tool);
    /** @type {string | null} */
    let installed = null;
    if (which(tool)) {
      try {
        installed = run([tool, "--version"], repo).trim();
      } catch (error) {
        if (!(error instanceof Failure)) throw error;
      }
    }
    let compatible = installed !== null && matches(tool, installed);
    if (compatible && isPackageManager) {
      for (const { project, requirement } of requirementsOf(tool)) {
        try {
          const projectVersion = run([tool, "--version"], path.join(repo, path.dirname(project))).trim();
          if (!satisfies(projectVersion, requirement)) {
            compatible = false;
            break;
          }
        } catch (error) {
          if (!(error instanceof Failure)) throw error;
          compatible = false;
          break;
        }
      }
    }
    if (!compatible && isPackageManager) {
      if (!which("corepack")) throw new EngineMismatch(`Corepack is not on PATH. Install Corepack to switch ${tool}.`);
      if (!corepackEnabled) {
        const cache =
          process.env.COREPACK_HOME ||
          path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache"), "node", "corepack");
        mkdirSync(path.join(cache, "v1"), { recursive: true });
        const home = path.join(tempDir, "home");
        mkdirSync(home);
        symlinkSync(path.join(cache, "v1"), path.join(home, "v1"), "dir");
        process.env.COREPACK_HOME = home;
        process.env.COREPACK_ENABLE_STRICT = "0";
        shimDir = path.join(tempDir, "bin");
        mkdirSync(shimDir);
        process.env.PATH = shimDir + path.delimiter + (process.env.PATH ?? "");
        corepackEnabled = true;
      }
      const values = [...new Set(requirementsOf(tool).map((r) => String(r.requirement)))];
      const combinations = values
        .map((value) => value.split("||"))
        .reduce(
          (/** @type {string[][]} */ prefixes, options) =>
            prefixes.flatMap((prefix) => options.map((option) => [...prefix, option])),
          /** @type {string[][]} */ ([[]]),
        );
      const requirement = combinations.map((parts) => parts.join(" ")).join(" || ");
      const activated = orEngineMismatch(
        () => {
          run(["corepack", "enable", "--install-directory", shimDir, tool], repo);
          run(["corepack", "prepare", `${tool}@${requirement}`, "--activate"], repo);
          return run([tool, "--version"], repo).trim();
        },
        (detail) => `Corepack could not install or activate ${tool} ${requirement}: ${detail}`,
      );
      installed = activated;
    }
    if (installed === null) {
      throw new EngineMismatch(`${tool} is not on PATH, but ${requirementsOf(tool)[0].project} requires it`);
    }
    for (const { project, requirement } of requirementsOf(tool)) {
      if (!satisfies(installed, requirement)) {
        throw new EngineMismatch(`Installed ${tool} ${installed} does not satisfy "${requirement}" from ${project}`);
      }
    }
    if (!compatible && isPackageManager) {
      for (const { project, requirement } of requirementsOf(tool)) {
        const projectVersion = orEngineMismatch(
          () => run([tool, "--version"], path.join(repo, path.dirname(project))).trim(),
          (detail) => `Corepack could not activate ${tool} for ${project}: ${detail}`,
        );
        if (!satisfies(projectVersion, requirement)) {
          throw new EngineMismatch(`${tool} ${projectVersion} does not satisfy "${requirement}" from ${project}`);
        }
      }
    }
  }
  return corepackEnabled;
}

/**
 * @param {string} repo
 * @returns {{ cleanup: () => void } | null}
 */
function requireEngines(repo) {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), "fix-cves-corepack-"));
  const cleanup = () => rmSync(tempDir, { recursive: true, force: true });
  let used;
  try {
    used = configureEngines(repo, tempDir);
  } catch (error) {
    cleanup();
    throw error;
  }
  if (used) return { cleanup };
  cleanup();
  return null;
}

/* ---------- workspace state ---------- */

/**
 * @param {string} workspace
 * @param {boolean} [frozen]
 */
function install(workspace, frozen = true) {
  if (manager(workspace) === "pnpm") {
    run(["pnpm", "install", frozen ? "--frozen-lockfile" : "--no-frozen-lockfile"], workspace);
  } else {
    run(["npm", frozen ? "ci" : "install"], workspace);
  }
}

/**
 * @param {string} workspace
 * @returns {Map<string, Buffer>}
 */
function snapshot(workspace) {
  /** @type {Map<string, Buffer>} */
  const found = new Map();
  for (const { dir, files } of walk(workspace)) {
    for (const name of MANIFESTS) {
      if (files.includes(name)) found.set(path.join(dir, name), readFileSync(path.join(dir, name)));
    }
  }
  return found;
}

/**
 * @param {Map<string, Buffer>} a
 * @param {Map<string, Buffer>} b
 */
function snapshotsEqual(a, b) {
  if (a.size !== b.size) return false;
  for (const [file, data] of a) {
    const other = b.get(file);
    if (!other || !other.equals(data)) return false;
  }
  return true;
}

/**
 * @param {string} workspace
 * @param {Map<string, Buffer>} saved
 */
function restore(workspace, saved) {
  for (const file of snapshot(workspace).keys()) {
    if (!saved.has(file)) unlinkSync(file);
  }
  for (const [file, data] of saved) {
    if (!existsSync(file) || !readFileSync(file).equals(data)) writeFileSync(file, data);
  }
  install(workspace);
}

/** @param {Advisory} advisory */
const advisoryKey = (advisory) => `${advisory.id}:${advisory.package}`;

/** @param {Advisory} advisory */
const hasPatch = (advisory) => advisory.patched !== "" && advisory.patched !== "<0.0.0";

/** @param {Advisory} advisory @returns {Status} */
const severeStatus = (advisory) => (SEVERE_LEVELS.includes(advisory.severity) ? "persisting" : "deferred");

/** @param {string[]} values */
const uniqueSorted = (values) => [...new Set(values)].sort();

/* ---------- CVE lookup ---------- */

/** @type {Map<string, string[]>} */
const cveCache = new Map();
/** @type {{ token?: string, disabled?: boolean }} */
const cveState = {};

function githubToken() {
  const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  if (token) return token;
  const result = spawnSync("gh", ["auth", "token", "--hostname", "github.com"], {
    encoding: "utf8",
    timeout: 10_000,
  });
  return !result.error && result.status === 0 ? result.stdout.trim() : "";
}

/**
 * Look up missing CVE IDs in batches and reuse results across audits.
 * @param {Set<string>} advisoryIds
 * @returns {Promise<Map<string, string[]>>}
 */
async function cveIds(advisoryIds) {
  const missing = [...advisoryIds].filter((id) => id.startsWith("GHSA-") && !cveCache.has(id)).sort();
  if (!missing.length || cveState.disabled) return cveCache;
  if (cveState.token === undefined) cveState.token = githubToken();
  if (!cveState.token) {
    info("CVE lookup skipped: authenticate with gh or set GH_TOKEN or GITHUB_TOKEN.");
    cveState.disabled = true;
    return cveCache;
  }
  for (let start = 0; start < missing.length; start += 50) {
    const batch = missing.slice(start, start + 50);
    const fields = batch.map(
      (identity, n) => `a${n}: securityAdvisory(ghsaId: ${JSON.stringify(identity)}) { cveId }`,
    );
    try {
      const response = await fetch(GITHUB_GRAPHQL, {
        method: "POST",
        headers: {
          Accept: "application/vnd.github+json",
          "Content-Type": "application/json",
          Authorization: "Bearer " + cveState.token,
        },
        body: JSON.stringify({ query: "query { " + fields.join(" ") + " }" }),
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) throw new HttpError(response.status, response.statusText);
      /** @type {{ data?: Record<string, { cveId?: string | null } | null>, errors?: Array<{ message?: string }> }} */
      const result = await response.json();
      const data = result.data ?? {};
      batch.forEach((identity, n) => {
        const alias = `a${n}`;
        if (alias in data) {
          const cve = data[alias]?.cveId;
          cveCache.set(identity, cve ? [cve] : []);
        }
      });
      if (result.errors?.length) {
        info(`CVE lookup failed: ${result.errors[0].message ?? "GraphQL error"}`);
        cveState.disabled = true;
        break;
      }
    } catch (error) {
      info(`CVE lookup failed: ${messageOf(error)}`);
      if (error instanceof HttpError && [401, 403, 429].includes(error.status)) cveState.disabled = true;
      break;
    }
  }
  return cveCache;
}

/**
 * @param {string} workspace
 * @param {string} registry
 * @returns {Promise<Map<string, Advisory>>}
 */
async function audit(workspace, registry) {
  const tool = manager(workspace);
  const data = runJson([tool, "audit", "--json", "--registry=" + registry], workspace, [0, 1]);
  if (typeof data !== "object" || data === null || !("advisories" in data || "vulnerabilities" in data)) {
    throw new Failure(`Audit returned no vulnerability data: ${JSON.stringify(data).slice(0, 300)}`);
  }
  const report = /** @type {AuditReport} */ (data);

  /** @type {RawAdvisory[]} */
  const advisories = Object.values(report.advisories ?? {});
  /** @type {Record<string, { version?: string }>} */
  let npmLock = {};
  if (tool === "npm") {
    const lockfile = ["npm-shrinkwrap.json", "package-lock.json"]
      .map((name) => path.join(workspace, name))
      .find((file) => existsSync(file));
    if (lockfile) npmLock = JSON.parse(readFileSync(lockfile, "utf8")).packages ?? {};
  }
  for (const [pkg, vulnerability] of Object.entries(report.vulnerabilities ?? {})) {
    for (const via of vulnerability.via ?? []) {
      // String entries describe dependents, not separate advisories.
      if (typeof via === "string") continue;
      advisories.push({
        id: via.source,
        module_name: via.name ?? pkg,
        severity: via.severity,
        title: via.title ?? "",
        url: via.url ?? "",
        vulnerable_versions: via.range ?? "",
        patched_versions: vulnerability.fixAvailable ? "Fix available (npm audit)" : "",
        findings: (vulnerability.nodes ?? []).map((node) => ({
          paths: [node],
          version: npmLock[node]?.version ?? "",
        })),
      });
    }
  }

  /** @type {Map<string, Advisory>} */
  const found = new Map();
  for (const advisory of advisories) {
    const url = advisory.url ?? "";
    const key =
      advisory.github_advisory_id ||
      (url.includes("github.com/advisories/GHSA-")
        ? url.replace(/\/+$/, "").split("/").pop() ?? ""
        : String(advisory.id));
    const findings = advisory.findings ?? [];
    /** @type {Advisory} */
    const record = {
      id: key,
      package: advisory.module_name || "",
      severity: advisory.severity || "unknown",
      title: advisory.title || "",
      url,
      cves: advisory.cves ?? [],
      vulnerable: advisory.vulnerable_versions || "",
      patched: advisory.patched_versions || "",
      versions: uniqueSorted(findings.map((f) => f.version || "").filter(Boolean)),
      paths: uniqueSorted(findings.flatMap((f) => f.paths ?? [])),
    };
    const identity = advisoryKey(record);
    const previous = found.get(identity);
    if (previous) {
      record.cves = record.cves.length ? record.cves : previous.cves;
      record.versions = uniqueSorted([...record.versions, ...previous.versions]);
      record.paths = uniqueSorted([...record.paths, ...previous.paths]);
    }
    found.set(identity, record);
  }

  const missing = new Set([...found.values()].filter((r) => r.cves.length === 0).map((r) => r.id));
  const cves = await cveIds(missing);
  for (const record of found.values()) {
    if (record.cves.length === 0) record.cves = cves.get(record.id) ?? [];
  }
  return found;
}

/* ---------- dependency graph ---------- */

/** @param {string} workspace @returns {VersionMap} */
function installedVersions(workspace) {
  const command =
    manager(workspace) === "pnpm"
      ? ["pnpm", "-r", "list", "--depth", "Infinity", "--json"]
      : ["npm", "ls", "--all", "--json"];
  const data = /** @type {DependencyNode[] | DependencyNode} */ (runJson(command, workspace));
  /** @type {VersionMap} */
  const result = new Map();
  /** @param {DependencyNode} node */
  const visit = (node) => {
    for (const dependencies of [node.dependencies, node.devDependencies, node.optionalDependencies]) {
      for (const [name, dependency] of Object.entries(dependencies ?? {})) {
        const match = /^(\d+)\.(\d+)\.(\d+)(?:$|[-+(])/.exec(dependency.version ?? "");
        if (match) {
          const versions = result.get(name) ?? new Set();
          versions.add(`${Number(match[1])}.${Number(match[2])}.${Number(match[3])}`);
          result.set(name, versions);
        }
        visit(dependency);
      }
    }
  };
  for (const project of Array.isArray(data) ? data : [data]) visit(project);
  return result;
}

/**
 * Largest semver jump of a newly installed version. In 0.x, a minor jump is breaking.
 * @param {VersionMap} before
 * @param {VersionMap} after
 * @returns {Risk}
 */
export function upgradeRisk(before, after) {
  let risk = 0;
  for (const [name, versions] of after) {
    const oldVersions = before.get(name) ?? new Set();
    for (const text of versions) {
      if (oldVersions.has(text)) continue;
      const version = parseVersion(text);
      /** @type {Version | null} */
      let nearest = null;
      for (const old of oldVersions) {
        const candidate = parseVersion(old);
        if (compareVersions(candidate, version) <= 0 && (!nearest || compareVersions(candidate, nearest) > 0)) {
          nearest = candidate;
        }
      }
      if (!nearest) continue;
      if (version[0] !== nearest[0] || (version[0] === 0 && version[1] !== nearest[1])) {
        risk = Math.max(risk, 2);
      } else if (version[1] !== nearest[1]) {
        risk = Math.max(risk, 1);
      }
    }
  }
  return RISKS[risk];
}

/**
 * @param {Risk} a
 * @param {Risk} b
 * @returns {Risk}
 */
const maxRisk = (a, b) => (RISKS.indexOf(a) >= RISKS.indexOf(b) ? a : b);

/**
 * @param {VersionMap} before
 * @param {VersionMap} after
 * @param {string} pkg
 */
function versionChange(before, after, pkg) {
  /** @param {Set<string> | undefined} versions */
  const text = (versions) =>
    [...(versions ?? [])]
      .map(parseVersion)
      .sort(compareVersions)
      .map((v) => v.join("."))
      .join(", ") || "none";
  return `${pkg} ${text(before.get(pkg))} -> ${text(after.get(pkg))}`;
}

/**
 * Return direct dependents of `spec` as [registry packages, workspace projects].
 * @param {string} workspace
 * @param {string} spec
 * @param {string} target
 * @returns {[Set<string>, Set<string>]}
 */
function dependents(workspace, spec, target) {
  const tool = manager(workspace);
  const command = tool === "pnpm" ? ["pnpm", "-r", "why", spec, "--json"] : ["npm", "explain", spec, "--json"];
  const data = /** @type {WhyEntry[]} */ (runJson(command, workspace));
  /** @type {Set<string>} */
  const packages = new Set();
  /** @type {Set<string>} */
  const projects = new Set();

  /**
   * @param {DependencyNode} node
   * @param {string | null} parent
   */
  const visitTree = (node, parent) => {
    for (const dependencies of [node.dependencies, node.devDependencies, node.optionalDependencies]) {
      for (const [name, child] of Object.entries(dependencies ?? {})) {
        if (name === target) {
          if (parent) packages.add(parent);
          else projects.add(node.name ?? "?");
        }
        visitTree(child, name);
      }
    }
  };

  for (const entry of data) {
    if ("dependents" in entry) {
      // pnpm 10.x+ prints an inverted tree.
      for (const dependent of entry.dependents ?? []) {
        if (tool === "npm") {
          const owner = dependent.from ?? {};
          if (owner.name) {
            (owner.isWorkspace || owner.location === "" ? projects : packages).add(owner.name);
          }
        } else {
          (("depField" in dependent) ? projects : packages).add(dependent.name);
        }
      }
    } else {
      visitTree(entry, null);
    }
  }
  return [packages, projects];
}

class Repair {
  /**
   * @param {string} workspace
   * @param {string} registry
   * @param {boolean} allowMajor
   */
  constructor(workspace, registry, allowMajor) {
    this.workspace = workspace;
    this.registry = registry;
    this.allowMajor = allowMajor;
    this.tool = manager(workspace);
    this.npmWorkspaces = hasWorkspaces(readManifest(path.join(workspace, "package.json")));
    /** @type {Set<string | undefined>} */
    this.projects = new Set();
    for (const [file, data] of snapshot(workspace)) {
      if (path.basename(file) === "package.json") this.projects.add(JSON.parse(data.toString("utf8")).name);
    }
  }

  /**
   * @param {Set<string>} ids
   * @returns {Promise<Map<string, Advisory>>}
   */
  async remaining(ids) {
    const current = await audit(this.workspace, this.registry);
    return new Map([...current].filter(([key]) => ids.has(key)));
  }

  /**
   * @param {string} target
   * @param {VersionMap} before
   * @param {string[]} steps
   * @returns {Risk}
   */
  upgrade(target, before, steps) {
    if (!PACKAGE_NAME.test(target)) throw new Failure(`Invalid package name '${target}'`);
    const command = this.tool === "pnpm" ? ["pnpm", "-r", "up", target] : ["npm", "update", target];
    if (this.tool === "npm" && this.npmWorkspaces) command.push("--workspaces", "--include-workspace-root");
    run(command, this.workspace);
    run([this.tool, "dedupe"], this.workspace);
    steps.push(`${command.join(" ")} && ${this.tool} dedupe`);
    const risk = upgradeRisk(before, installedVersions(this.workspace));
    if (risk === "major" && !this.allowMajor) {
      throw new Failure("The fix needs a major version jump. Review it, then run again with --allow-major.");
    }
    return risk;
  }

  /**
   * Follow the guide: upgrade the package, then its dependents breadth-first.
   * @param {string} pkg
   * @param {Advisory[]} advisories
   * @returns {Promise<string>}
   */
  async fix(pkg, advisories) {
    if (!advisories.some(hasPatch)) {
      throw new Failure("No patched version is available. Check the upstream issues for a fix in progress.");
    }
    const ids = new Set(advisories.map(advisoryKey));
    const before = installedVersions(this.workspace);
    /** @type {string[]} */
    const steps = [];
    let risk = this.upgrade(pkg, before, steps);
    let left = await this.remaining(ids);
    /** @type {string[]} */
    const queue = [pkg];
    const tried = new Set([pkg]);
    /** @type {Set<string>} */
    const blockers = new Set();
    while (left.size && queue.length) {
      const target = queue.shift();
      if (target === undefined) break;
      const specs =
        target === pkg
          ? uniqueSorted([...left.values()].flatMap((a) => a.versions.map((v) => `${target}@${v}`)))
          : [target];
      if (target === pkg && !specs.length) specs.push(target);

      /** @type {Set<string>} */
      const packages = new Set();
      /** @type {Set<string>} */
      const projects = new Set();
      for (const spec of specs) {
        const [found, owners] = dependents(this.workspace, spec, target);
        for (const p of found) if (!this.projects.has(p)) packages.add(p);
        for (const p of owners) projects.add(p);
        for (const p of found) if (this.projects.has(p)) projects.add(p);
      }
      for (const p of projects) blockers.add(`${p} -> ${target}`);
      for (const parent of [...packages].filter((p) => !tried.has(p)).sort()) {
        tried.add(parent);
        risk = maxRisk(risk, this.upgrade(parent, before, steps));
        left = await this.remaining(ids);
        if (!left.size) break;
        queue.push(parent);
      }
    }

    let problem = "";
    if (left.size) {
      problem = blockers.size
        ? `Workspace packages pin a vulnerable range (${[...blockers].sort().join(", ")}). Consult an expert.`
        : "Version ranges of upstream dependents still require a vulnerable version.";
      if (left.size === ids.size) throw new Failure(problem);
    }
    const after = installedVersions(this.workspace);
    let how = `${versionChange(before, after, pkg)}. ${steps.join("; ")}`;
    if (risk === "minor") how += ". Minor upgrade: review the changelog.";
    if (problem) how += ". Partial fix: " + problem;
    return how;
  }
}

/* ---------- repair orchestration ---------- */

/**
 * @param {Advisory} advisory
 * @param {Status} status
 * @param {string} detail
 * @returns {Result}
 */
const withStatus = (advisory, status, detail) => ({ ...advisory, status, detail });

/**
 * @param {string} workspace
 * @param {FixArgs} args
 * @param {Record<string, string[]>} checks
 * @param {Map<string, Advisory>} initial
 * @returns {Promise<Result[]>}
 */
async function repairWorkspace(workspace, args, checks, initial) {
  const { registry } = args;
  const all = [...initial.values()];
  if (args.auditOnly) {
    return all.map((a) =>
      SEVERE_LEVELS.includes(a.severity)
        ? withStatus(a, "persisting", "Audit only. No changes attempted.")
        : withStatus(a, "deferred", "Deferred until a normal dependency upgrade."),
    );
  }
  if (!all.some((a) => SEVERE_LEVELS.includes(a.severity))) {
    return all.map((a) => withStatus(a, "deferred", "Deferred until a normal dependency upgrade."));
  }

  install(workspace);
  const original = snapshot(workspace);
  /** @type {Map<string, string>} */
  const how = new Map();
  /** @type {Map<string, string>} */
  const why = new Map();
  const severeCount = all.filter((a) => severeStatus(a) === "persisting").length;
  info(`${workspace}: ${initial.size} advisories (${severeCount} high/critical)`);

  const repair = new Repair(workspace, registry, args.allowMajor);
  /** @type {Map<string, Advisory[]>} */
  const byPackage = new Map();
  for (const advisory of all) {
    if (severeStatus(advisory) !== "persisting") continue;
    byPackage.set(advisory.package, [...(byPackage.get(advisory.package) ?? []), advisory]);
  }
  for (const pkg of [...byPackage.keys()].sort()) {
    const advisories = byPackage.get(pkg) ?? [];
    if (!(await repair.remaining(new Set(advisories.map(advisoryKey)))).size) {
      how.set(pkg, "Fixed by an earlier upgrade in this run.");
      continue;
    }
    const saved = snapshot(workspace);
    try {
      const detail = await repair.fix(pkg, advisories);
      how.set(pkg, detail);
      info(`UPGRADE ${pkg}: ${detail}`);
    } catch (error) {
      if (!(error instanceof Failure)) throw error;
      why.set(pkg, error.message);
      info(`NOT FIXED ${pkg}: ${error.message}`);
      if (!snapshotsEqual(snapshot(workspace), saved)) restore(workspace, saved);
    }
  }

  const severeIds = new Set([...initial].filter(([, a]) => severeStatus(a) === "persisting").map(([key]) => key));
  /** @type {string | null} */
  let overrideFailure = null;
  if (
    args.allowOverride &&
    manager(workspace) === "pnpm" &&
    [...(await repair.remaining(severeIds)).values()].some(hasPatch)
  ) {
    info("Last resort: pnpm audit --fix");
    const saved = snapshot(workspace);
    try {
      const current = await audit(workspace, registry);
      const eligible = new Set(
        [...current.values()].filter((a) => severeStatus(a) === "persisting" && hasPatch(a)).map((a) => a.id),
      );
      const ignored = uniqueSorted([...current.values()].map((a) => a.id).filter((id) => !eligible.has(id)));
      // --audit-level limits printed findings, not the overrides.
      const command = ["pnpm", "audit", "--registry=" + registry, "--audit-level", "high", "--fix"];
      command.push(...ignored.map((identity) => "--ignore=" + identity));
      run(command, workspace, [0, 1]);
      install(workspace, false);
      const left = await repair.remaining(severeIds);
      for (const pkg of [...why.keys()]) {
        if (![...left.values()].some((a) => a.package === pkg)) {
          how.set(pkg, OVERRIDE_NOTE);
          why.delete(pkg);
        }
      }
    } catch (error) {
      if (!(error instanceof Failure)) throw error;
      info(`Override failed: ${error.message}`);
      overrideFailure = `Last-resort override failed: ${error.message}.`;
      restore(workspace, saved);
    }
  }

  /** @type {string | null} */
  let checkFailure = null;
  if (!snapshotsEqual(snapshot(workspace), original)) {
    for (const [name, argv] of Object.entries(checks)) {
      try {
        run(argv, workspace);
      } catch (error) {
        if (!(error instanceof Failure)) throw error;
        checkFailure =
          `Check '${name}' failed after the upgrades, so all upgrades in this ` +
          `workspace were reverted (${error.message}).`;
        info(checkFailure);
        restore(workspace, original);
        break;
      }
    }
  }

  const final = await audit(workspace, registry);
  /** @type {Result[]} */
  const results = [];
  const sortedInitial = [...initial].sort(([keyA, a], [keyB, b]) =>
    compareStrings(a.package, b.package) || compareStrings(keyA, keyB),
  );
  for (const [key, advisory] of sortedInitial) {
    const pkg = advisory.package;
    if (!final.has(key)) {
      results.push(withStatus(advisory, "solved", how.get(pkg) ?? "Fixed by other upgrades in this run."));
      continue;
    }
    let detail;
    if (checkFailure && how.has(pkg)) {
      detail = checkFailure;
    } else if (severeStatus(advisory) !== "persisting") {
      detail = "Deferred until a normal dependency upgrade.";
    } else {
      detail = why.get(pkg) ?? how.get(pkg) ?? "Still reported after the upgrades of this run.";
      if (!args.allowOverride && hasPatch(advisory) && why.has(pkg)) {
        detail += " Last resort not tried: run again with --allow-override.";
      }
      if (args.allowOverride && manager(workspace) === "npm") {
        detail += " npm force-fix is not automatic. Review a manual fix with an expert.";
      }
      if (overrideFailure) detail += " " + overrideFailure;
    }
    results.push(withStatus(advisory, severeStatus(advisory), detail));
  }
  for (const [key, advisory] of [...final].sort(([a], [b]) => compareStrings(a, b))) {
    if (!initial.has(key)) {
      results.push(withStatus(advisory, severeStatus(advisory), "Appeared after the upgrades of this run."));
    }
  }
  if (checkFailure) {
    for (const result of results) result.error = checkFailure;
  }
  return results;
}

/**
 * @param {string} a
 * @param {string} b
 */
const compareStrings = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * @param {string} workspace
 * @param {FixArgs} args
 * @param {Record<string, string[]>} checks
 * @returns {Promise<Result[]>}
 */
async function fixWorkspace(workspace, args, checks) {
  const initial = await audit(workspace, args.registry);
  const saved = args.auditOnly ? null : snapshot(workspace);
  try {
    return await repairWorkspace(workspace, args, checks, initial);
  } catch (error) {
    if (!isExpected(error)) throw error;
    let detail = `Workspace repair failed: ${messageOf(error)}.`;
    if (saved && !snapshotsEqual(snapshot(workspace), saved)) {
      try {
        restore(workspace, saved);
        detail += " Dependency files were restored.";
      } catch (rollbackError) {
        if (!isExpected(rollbackError)) throw rollbackError;
        detail += ` Restore failed: ${messageOf(rollbackError)}. Review dependency files before continuing.`;
      }
    }
    info(`ERROR ${workspace}: ${detail}`);
    return [...initial.values()].map((a) => ({
      ...a,
      status: severeStatus(a),
      detail,
      error: detail,
    }));
  }
}

/**
 * @param {string | undefined} file
 * @param {string} repo
 * @returns {Map<string, Record<string, string[]>>}
 */
function loadChecks(file, repo) {
  /** @type {Map<string, Record<string, string[]>>} */
  const checks = new Map();
  if (!file) return checks;
  const data = JSON.parse(readFileSync(file, "utf8"));
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new Failure("Checks must map workspace paths to command objects");
  }
  for (const [directory, commands] of Object.entries(/** @type {Record<string, unknown>} */ (data))) {
    if (!isCommandSet(commands)) throw new Failure("Each check must be a non-empty argument array of strings");
    checks.set(path.resolve(repo, directory), commands);
  }
  return checks;
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, string[]>}
 */
function isCommandSet(value) {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.values(value).every((argv) => Array.isArray(argv) && argv.length > 0 && argv.every((arg) => typeof arg === "string"))
  );
}

/**
 * @param {string} workspace
 * @returns {Record<string, string[]>}
 */
function defaultChecks(workspace) {
  const manifest = readManifest(path.join(workspace, "package.json"));
  const tool = manager(workspace);
  const names = ["build", "lint", "test"];
  /** @type {Record<string, string[]>} */
  const commands = {};
  if (tool === "pnpm" && existsSync(path.join(workspace, "pnpm-workspace.yaml"))) {
    for (const name of names) commands[name] = ["pnpm", "-r", "--if-present", "run", name];
  } else if (tool === "npm" && hasWorkspaces(manifest)) {
    for (const name of names) {
      commands[name] = ["npm", "run", name, "--if-present", "--workspaces", "--include-workspace-root"];
    }
  } else {
    for (const name of names) {
      if ((manifest.scripts ?? {})[name] !== undefined) commands[name] = [tool, "run", name];
    }
  }
  return commands;
}

/* ---------- reporting ---------- */

/**
 * Same behavior as Python textwrap.fill for the simple case used here.
 * @param {string} text
 * @param {number} width
 * @param {string} first
 * @param {string} rest
 */
function wrap(text, width, first, rest) {
  /** @type {string[]} */
  const lines = [];
  let line = "";
  for (const word of text.split(/\s+/).filter(Boolean)) {
    const indent = lines.length ? rest : first;
    const candidate = line ? line + " " + word : word;
    if (line && indent.length + candidate.length > width) {
      lines.push(indent + line);
      line = word;
    } else {
      line = candidate;
    }
  }
  if (line) lines.push((lines.length ? rest : first) + line);
  return lines.join("\n");
}

/**
 * @param {Result[]} results
 * @param {string[]} errors
 */
function summary(results, errors) {
  /** @type {string[]} */
  const lines = [];
  for (const status of /** @type {Status[]} */ (["solved", "persisting", "deferred"])) {
    const items = results.filter((r) => r.status === status);
    lines.push(`${status.toUpperCase()} (${items.length}):`);
    for (const r of items) {
      lines.push(
        `  [${r.severity}] ${r.workspace} ${r.package} ${r.id} (${r.cves.join(", ") || "no CVE id"}): ${r.detail}`,
      );
      lines.push(
        `    Vulnerable: ${r.vulnerable}. Patched: ${r.patched || "none reported"}. Versions: ${r.versions.join(", ") || "not reported"}`,
      );
      lines.push(wrap(`Paths: ${r.paths.join(", ") || "not reported"}`, 120, "    ", "      "));
    }
  }
  for (const error of errors) lines.push("ERROR: " + error);
  return lines.join("\n");
}

/** @param {string} text */
function escapeHtml(text) {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#x27;");
}

/**
 * @param {Array<[string, string]>} meta
 * @param {Result[]} results
 * @param {string[]} errors
 */
function renderHtml(meta, results, errors) {
  /** @param {Result} r */
  const row = (r) => {
    const advisory = r.url
      ? `<a href="${escapeHtml(r.url)}">${escapeHtml(r.id)}</a>`
      : escapeHtml(r.id);
    const details =
      `<details><summary>Dependency details (${r.paths.length} paths)</summary>` +
      `<dl><dt>Workspace</dt><dd>${escapeHtml(r.workspace ?? "")}</dd>` +
      `<dt>Installed versions</dt><dd><code>${escapeHtml(r.versions.join(", ") || "not reported")}</code></dd>` +
      `<dt>Vulnerable</dt><dd><code>${escapeHtml(r.vulnerable || "not reported")}</code></dd>` +
      `<dt>Patched</dt><dd><code>${escapeHtml(r.patched || "none reported")}</code></dd></dl>` +
      `<ul class="paths">${r.paths.map((p) => `<li><code>${escapeHtml(p)}</code></li>`).join("")}</ul></details>`;
    const cells = [
      escapeHtml(r.severity),
      `<code>${escapeHtml(r.package)}</code>`,
      `${advisory}<br><small>${escapeHtml([...r.cves, r.title].join(" "))}</small>`,
      escapeHtml(r.detail) + details,
    ];
    return `<tr class='${escapeHtml(r.severity)}'>${cells.map((cell) => `<td>${cell}</td>`).join("")}</tr>`;
  };

  /**
   * @param {Status} status
   * @param {string} heading
   * @param {string} column
   */
  const table = (status, heading, column) => {
    const items = results.filter((r) => r.status === status);
    if (!items.length) return `<h2>${heading} (0)</h2>`;
    return (
      `<h2>${heading} (${items.length})</h2><div class='table-scroll'><table><thead><tr><th>Severity</th><th>Package</th>` +
      `<th>Advisory</th><th>${column}</th></tr></thead><tbody>${items.map(row).join("")}</tbody></table></div>`
    );
  };

  const facts = meta.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${value}</dd>`).join("");
  const errorHtml = errors.length
    ? `<h2 class='err'>Errors</h2><ul class='err'>${errors.map((e) => `<li>${escapeHtml(e)}</li>`).join("")}</ul>`
    : "";
  return `<!doctype html><html><head><meta charset="utf-8"><title>CVE fix report</title><style>
body{font:14px system-ui,sans-serif;margin:2em;color:#222} table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:6px;text-align:left;vertical-align:top;overflow-wrap:anywhere} th{background:#f3f3f3}
.table-scroll{overflow-x:auto} td:first-child{width:6em} td:nth-child(2){width:17%}
td:nth-child(3){width:30%} tbody tr:nth-child(even){background:#fafafa}
details{margin-top:10px} summary{cursor:pointer;color:#245a91;font-weight:600}
.paths{max-height:22em;overflow:auto;padding-left:20px} .paths li{margin:6px 0}
tr.critical td:first-child{background:#b00020;color:#fff} tr.high td:first-child{background:#e65100;color:#fff}
dl{display:grid;grid-template-columns:max-content auto;gap:4px 16px} dt{font-weight:bold} .err{color:#b00020}
</style></head><body><h1>CVE fix report</h1><dl>${facts}</dl>${table("solved", "Solved", "How")}${table("persisting", "Still open", "Why not fixed")}${table("deferred", "Deferred (moderate/low)", "Reason")}${errorHtml}</body></html>
`;
}

/**
 * @param {string} repo
 * @param {string} base
 * @param {string} branch
 * @param {Result[]} results
 * @param {boolean} push
 * @returns {[string | null, string | null]}
 */
function publish(repo, base, branch, results, push) {
  const changed = run(["git", "status", "--porcelain"], repo)
    .split("\n")
    .filter(Boolean)
    .map((line) => line.slice(3).replace(/^"+|"+$/g, ""))
    .filter((file) => MANIFESTS.includes(path.basename(file)));
  if (!changed.length) {
    info("No dependency files changed, so no branch was created.");
    return [null, null];
  }
  const solved = results.filter((r) => r.status === "solved");
  run(["git", "checkout", "-b", branch], repo);
  run(["git", "add", "--", ...changed], repo);
  let message =
    "fix: upgrade dependencies for high/critical advisories\n\n" +
    solved.map((r) => `- ${r.package} ${r.id} (${r.cves.join(", ") || r.severity})`).join("\n");
  message += "\n\nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>";
  run(["git", "commit", "-m", message], repo);
  if (!push) return [branch, null];

  run(["git", "push", "-u", "origin", branch], repo);
  /** @type {string[]} */
  let templates = [
    path.join(repo, ".github", "pull_request_template.md"),
    path.join(repo, ".github", "PULL_REQUEST_TEMPLATE.md"),
  ];
  const templateDir = path.join(repo, ".github", "PULL_REQUEST_TEMPLATE");
  if (existsSync(templateDir)) {
    templates = templates.concat(
      readdirSync(templateDir)
        .filter((name) => name.endsWith(".md"))
        .sort()
        .map((name) => path.join(templateDir, name)),
    );
  }
  const template = templates.find(isFile);
  let body = template ? readFileSync(template, "utf8") : "autoclose none\n";
  body = body.replaceAll("autoclose LOOP-xxxx", "autoclose none");
  if (!/^autoclose (?:none|LOOP-\d+)/m.test(body)) body = "autoclose none\n\n" + body;
  body += "\n\nAutomated by fix_cves.mjs.\n\n```\n" + summary(results, []) + "\n```\n";
  const pr = run(
    ["gh", "pr", "create", "--base", base, "--head", branch, "--title", `fix: high/critical CVEs (${branch})`, "--body", body],
    repo,
  ).trim();
  return [branch, pr];
}

/**
 * @param {string} repo
 * @param {string | undefined} expectedBranch
 */
function pullLatest(repo, expectedBranch) {
  if (run(["git", "status", "--porcelain", "--untracked-files=no"], repo).trim()) {
    throw new Failure("The repository has uncommitted changes. Commit or stash them before pulling.");
  }
  const current = run(["git", "branch", "--show-current"], repo).trim();
  if (!current) throw new Failure("Detached HEAD: check out a branch before pulling.");
  if (expectedBranch && expectedBranch !== current) {
    throw new Failure(`Check out ${expectedBranch} before running repairs.`);
  }
  run(["git", "pull", "--ff-only"], repo);
  return current;
}

/* ---------- CLI ---------- */

/** @param {string[]} argv */
function parseCli(argv) {
  try {
    const { values } = parseArgs({
      args: argv,
      strict: true,
      options: {
        help: { type: "boolean", short: "h" },
        repo: { type: "string" },
        base: { type: "string" },
        workspace: { type: "string", multiple: true },
        dryrun: { type: "boolean" },
        "audit-only": { type: "boolean" },
        commit: { type: "boolean" },
        checks: { type: "string" },
        out: { type: "string" },
        registry: { type: "string" },
        "allow-major": { type: "boolean" },
        "allow-override": { type: "boolean" },
        push: { type: "boolean" },
      },
    });
    if (values.help) {
      process.stdout.write(USAGE);
      process.exit(0);
    }
    const auditOnly = Boolean(values.dryrun || values["audit-only"]);
    if (auditOnly && (values.commit || values.push)) {
      throw new Error("--dryrun cannot be combined with --commit or --push");
    }
    return { values, auditOnly };
  } catch (error) {
    process.stderr.write(`fix_cves.mjs: error: ${messageOf(error)}\n\n${USAGE}`);
    process.exit(2);
  }
}

/** @param {Date} date */
function isoLocal(date) {
  return (
    `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}` +
    `T${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`
  );
}

async function main() {
  const { values, auditOnly } = parseCli(process.argv.slice(2));
  const out = path.resolve(values.out ?? "cache/fix-cves-report");
  if (!auditOnly) mkdirSync(out, { recursive: true });
  const color = Boolean(process.stdout.isTTY) && !("NO_COLOR" in process.env);
  sinks.push(consoleSink(color));
  if (!auditOnly) {
    const reportLog = path.join(out, "report.log");
    writeFileSync(reportLog, "");
    sinks.push(fileSink(reportLog));
  }

  /** @type {FixArgs} */
  const fixArgs = {
    auditOnly,
    commit: Boolean(values.commit),
    push: Boolean(values.push),
    registry: values.registry || REGISTRY,
    allowMajor: Boolean(values["allow-major"]),
    allowOverride: Boolean(values["allow-override"]),
  };

  let repo = resolvePath(values.repo || ".");
  let base = values.base || "?";
  /** @type {Result[]} */
  const results = [];
  /** @type {string[]} */
  const errors = [];
  let fixBranch = /** @type {string | null} */ (null);
  let pr = /** @type {string | null} */ (null);
  let engineMismatch = false;
  /** @type {{ cleanup: () => void } | null} */
  let engineTools = null;
  const engineEnv = Object.fromEntries(
    ["PATH", "COREPACK_HOME", "COREPACK_ENABLE_STRICT"].map((key) => [key, process.env[key]]),
  );

  try {
    repo = resolvePath(run(["git", "rev-parse", "--show-toplevel"], repo).trim());
    engineTools = requireEngines(repo);
    if (!auditOnly) {
      const untracked = run(["git", "ls-files", "--others", "--exclude-standard", "-z"], repo).split("\0");
      if (untracked.some((file) => file && MANIFESTS.includes(path.basename(file)))) {
        throw new Failure("The repository has untracked dependency files. Track them before running repairs.");
      }
    }
    const current = auditOnly
      ? run(["git", "branch", "--show-current"], repo).trim()
      : pullLatest(repo, values.base);
    base = values.base || current;
    const branch = branchName(base, new Date());
    if ((fixArgs.commit || fixArgs.push) && run(["git", "branch", "--list", branch], repo).trim()) {
      throw new Failure(`Branch ${branch} already exists`);
    }
    const checks = loadChecks(values.checks, repo);
    const workspaces = candidateWorkspaces(repo, values.workspace ?? []);
    if (!workspaces.length) throw new Failure("No npm/pnpm workspace found");

    for (const workspace of workspaces) {
      if (!isInside(workspace, repo)) throw new Failure(`Workspace must be inside the repository: ${workspace}`);
      const name = path.relative(repo, workspace) || ".";
      const saved = auditOnly ? null : snapshot(workspace);
      try {
        const commands = checks.get(workspace) ?? defaultChecks(workspace);
        const workspaceResults = await fixWorkspace(workspace, fixArgs, commands);
        results.push(...workspaceResults.map((r) => ({ ...r, workspace: name })));
        const messages = new Set(workspaceResults.map((r) => r.error).filter((e) => e !== undefined));
        for (const message of [...messages].sort()) errors.push(`${name}: ${message}`);
      } catch (error) {
        if (!isExpected(error)) throw error;
        errors.push(`${name}: ${messageOf(error)}`);
        info(`ERROR ${name}: ${messageOf(error)}`);
        if (saved && !snapshotsEqual(snapshot(workspace), saved)) {
          try {
            restore(workspace, saved);
          } catch (rollbackError) {
            if (!(rollbackError instanceof Failure)) throw rollbackError;
            errors.push(`${name}: Restore failed: ${rollbackError.message}`);
          }
        }
      }
    }
    if (!auditOnly && !errors.length && (fixArgs.commit || fixArgs.push)) {
      [fixBranch, pr] = publish(repo, base, branch, results, fixArgs.push);
    }
  } catch (error) {
    if (!isExpected(error)) throw error;
    errors.push(messageOf(error));
    engineMismatch = error instanceof EngineMismatch;
    info(`ERROR ${messageOf(error)}`);
  }

  /** @type {Array<[string, string]>} */
  const meta = [
    ["Repository", escapeHtml(repo)],
    ["Base branch", escapeHtml(base)],
    ["Fix branch", escapeHtml(fixBranch ?? "none")],
    ["Pull request", pr ? `<a href="${escapeHtml(pr)}">${escapeHtml(pr)}</a>` : "none"],
    ["Date", escapeHtml(isoLocal(new Date()))],
    ["Options", escapeHtml(process.argv.slice(2).join(" ") || "defaults")],
  ];
  info(`SUMMARY\n${summary(results, errors)}`);
  if (!auditOnly) {
    const htmlFile = path.join(out, "report.html");
    writeFileSync(htmlFile, renderHtml(meta, results, errors));
    info(`Reports: ${path.join(out, "report.log")}, ${htmlFile}`);
  }
  sinks.length = 0;
  engineTools?.cleanup();
  for (const [key, value] of Object.entries(engineEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  if (errors.length) {
    process.exitCode = engineMismatch ? EXIT_ENGINE_MISMATCH : 2;
  } else {
    process.exitCode = results.some((r) => r.status === "persisting") ? 1 : 0;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) await main();
