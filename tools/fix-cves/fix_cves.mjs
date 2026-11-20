#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import {
  closeSync, existsSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync,
  realpathSync, unlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";

const USAGE = `Usage: node fix_cves.mjs [PACKAGE_DIR] [options]

  --audit-only      Report findings without installing or changing dependencies
  --allow-major     Approve major upgrades, including 0.x minor upgrades
  --allow-override  Approve pnpm overrides as a last resort
  --registry URL    Audit registry (default: https://registry.npmjs.org/)
  --fallback-registry URL
                    Retry failed audits with this registry
  --out DIR         Report directory (default: under node_modules/.cache)
  -h, --help        Show this help
`;
const REGISTRY = "https://registry.npmjs.org/";
const PACKAGE = /^(?:@[a-z\d][\w.-]*\/)?[a-z\d][\w.-]*$/i;
const GHSA = /^GHSA-[\da-z]{4}-[\da-z]{4}-[\da-z]{4}$/i;
const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"];
const severe = (a) => a.severity === "high" || a.severity === "critical";
const unique = (values) => [...new Set(values)].sort();
const clean = (s) => String(s).replace(/[\x00-\x1f\x7f-\x9f]/g, " ");
const html = (s) => String(s).replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
})[c]);
const httpUrl = (s) => {
  try {
    const url = new URL(s);
    if (["http:", "https:"].includes(url.protocol) && !url.username && !url.password) return url;
  } catch { /* Not a URL. */ }
};

function packageRoot(dir) {
  const target = realpathSync(dir);
  if (!lstatSync(target).isDirectory()) throw new Error("Specify a package directory.");
  for (let root = target; ; root = path.dirname(root)) {
    const lockfiles = ["pnpm-lock.yaml", "npm-shrinkwrap.json", "package-lock.json"]
      .filter((name) => existsSync(path.join(root, name)));
    if (lockfiles.length) {
      const file = path.join(root, "package.json");
      const manifest = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : {};
      const declared = manifest.packageManager?.split("@")[0];
      const tools = unique(lockfiles.map((name) => name === "pnpm-lock.yaml" ? "pnpm" : "npm"));
      const tool = declared || (tools.length === 1 ? tools[0] : "");
      if (!tools.includes(tool)) throw new Error("The lockfiles do not identify a single npm or pnpm project.");
      return { root, target, tool, manifest };
    }
    if (root === path.dirname(root)) throw new Error("No npm or pnpm lockfile found.");
  }
}

function runner({ tool, root }, log) {
  const env = { ...process.env, CI: "true", COREPACK_ENABLE_AUTO_PIN: "0" };
  delete env.GH_TOKEN;
  delete env.GITHUB_TOKEN;
  return (args, { json = false, codes = [0] } = {}) => {
    log(`> ${[tool, ...args].join(" ")}`);
    const result = spawnSync(tool, args, {
      cwd: root, env, encoding: "utf8", maxBuffer: 256 * 1024 * 1024, timeout: 300_000,
    });
    const command = args[0] === "-r" ? args[1] : args[0];
    if (result.error || !codes.includes(result.status)) {
      throw new Error(`${tool} ${command}: ${result.error?.code ?? `exit ${result.status ?? result.signal}`}`);
    }
    if (!json) return result.stdout;
    try {
      return JSON.parse(result.stdout);
    } catch {
      throw new Error(`${tool} ${command} did not return valid JSON.`);
    }
  };
}

function projectFiles(project, run) {
  const { root, target, tool, manifest } = project;
  const pnpmWorkspace = tool === "pnpm" && existsSync(path.join(root, "pnpm-workspace.yaml"));
  const npmWorkspace = tool === "npm" && Boolean(manifest.workspaces);
  const members = pnpmWorkspace
    ? run(["-r", "list", "--depth", "-1", "--json"], { json: true })
    : npmWorkspace ? run(["query", ".workspace", "--package-lock-only", "--json"], { json: true }) : [];
  if (!Array.isArray(members)) throw new Error("Invalid workspace listing.");
  const directories = new Set([root]);
  const names = new Set([manifest.name]);
  for (const member of members) {
    if (!path.isAbsolute(member.path ?? "")) throw new Error("Invalid workspace member path.");
    const dir = realpathSync(member.path);
    const relative = path.relative(root, dir);
    if (relative.split(path.sep)[0] === ".." || path.isAbsolute(relative)) {
      throw new Error("A workspace member is outside the lockfile directory.");
    }
    names.add(member.name);
    directories.add(dir);
  }
  if (!directories.has(target)) throw new Error("The target is not a member of the lockfile workspace.");
  const files = [...directories].map((dir) => path.join(dir, "package.json"));
  const lockNames = tool === "pnpm" ? ["pnpm-lock.yaml", "pnpm-workspace.yaml"] : [
    "package-lock.json", "npm-shrinkwrap.json",
  ];
  return {
    files: [...files, ...lockNames.map((file) => path.join(root, file))],
    names,
    workspaceFlags: npmWorkspace ? ["--workspaces", "--include-workspace-root"] : [],
  };
}

function snapshot(files) {
  return files.map((file) => {
    if (!existsSync(file)) return null;
    if (!lstatSync(file).isFile()) throw new Error(`Not a regular dependency file: ${file}`);
    return readFileSync(file);
  });
}

function restore(files, saved) {
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    if (!saved[i]) {
      if (existsSync(file)) unlinkSync(file);
    } else if (!existsSync(file) || !readFileSync(file).equals(saved[i])) {
      writeFileSync(file, saved[i]);
    }
  }
}

function audit(run, registry, fallbackRegistry, log) {
  let data = run(["audit", "--json", `--registry=${registry}`], { json: true, codes: [0, 1] });
  if (data?.error && fallbackRegistry && fallbackRegistry !== registry) {
    log(`Audit failed at ${registry}; retrying with ${fallbackRegistry}.`);
    data = run(["audit", "--json", `--registry=${fallbackRegistry}`], { json: true, codes: [0, 1] });
  }
  const records = new Map();
  function add(raw, pkg, nodes, patched) {
    if (!PACKAGE.test(pkg ?? "") || !(raw.id ?? raw.source) || !raw.severity) {
      throw new Error("Audit returned an invalid advisory.");
    }
    const url = httpUrl(raw.url);
    const slug = url?.hostname === "github.com" ? url.pathname.split("/").filter(Boolean).at(-1) : "";
    const id = raw.github_advisory_id || (GHSA.test(slug) ? slug : String(raw.id ?? raw.source));
    const key = `${pkg}:${id}`;
    const old = records.get(key);
    records.set(key, {
      id, pkg, severity: raw.severity, title: raw.title ?? "", url: url?.href,
      cves: unique([...(old?.cves ?? []), ...(raw.cves ?? [])]),
      range: raw.vulnerable_versions ?? raw.range ?? "", patched,
      paths: unique([...(old?.paths ?? []), ...nodes]),
    });
  }
  const object = (value) => value && typeof value === "object" && !Array.isArray(value);
  if (!data?.error && object(data?.advisories)) {
    for (const entry of Object.values(data.advisories)) {
      const patch = entry.patched_versions?.trim();
      add(entry, entry.module_name, (entry.findings ?? []).flatMap((f) =>
        (f.paths?.length ? f.paths : [""]).map((p) => `${p} @ ${f.version ?? "unknown"}`)),
      patch && patch !== "<0.0.0" ? patch : null);
    }
  } else if (!data?.error && object(data?.vulnerabilities)) {
    for (const [pkg, finding] of Object.entries(data.vulnerabilities)) {
      if (!Array.isArray(finding.via)) throw new Error("Audit returned an invalid npm finding.");
      for (const entry of finding.via) {
        if (typeof entry !== "string") add(entry, entry.name ?? pkg, finding.nodes ?? [], undefined);
      }
    }
  } else {
    throw new Error("Audit failed or returned an unsupported report.");
  }
  return records;
}

function versions(run, tool) {
  if (tool === "pnpm") {
    const directories = run(["-r", "list", "--depth", "Infinity", "--parseable"])
      .trim().split(/\r?\n/);
    const graph = new Map();
    for (const dir of new Set(directories)) {
      const file = path.join(dir, "package.json");
      let pkg;
      if (existsSync(file)) {
        pkg = JSON.parse(readFileSync(file, "utf8"));
      } else {
        const segments = dir.split(path.sep);
        const storeKey = segments[segments.lastIndexOf(".pnpm") + 1] ?? "";
        const match = storeKey.match(/^(@[^+]+\+[^@]+|[^@]+)@(.+)$/);
        if (!match) throw new Error(`Missing package manifest: ${file}`);
        pkg = { name: match[1].replace("+", "/"), version: match[2].split("_", 1)[0] };
      }
      const { name, version } = pkg;
      if (name && /^\d+\.\d+\.\d+(?:$|[-+])/.test(version ?? "")) {
        graph.set(dir, { name, version });
      }
    }
    return graph;
  }
  const projects = [run(["ls", "--all", "--json"], { json: true })];
  if (!Array.isArray(projects) || !projects.length || !projects.every((node) => node && typeof node === "object")) {
    throw new Error("Invalid dependency tree.");
  }
  const graph = new Map();
  function walk(node, route) {
    for (const field of DEP_FIELDS) {
      for (const [name, child] of Object.entries(node[field] ?? {})) {
        const key = `${route}>${name}`;
        if (/^\d+\.\d+\.\d+(?:$|[-+])/.test(child.version ?? "")) {
          graph.set(key, { name: child.name ?? child.from ?? name, version: child.version });
        }
        walk(child, key);
      }
    }
  }
  for (const node of projects) walk(node, node.path ?? node.name ?? ".");
  return graph;
}

function upgradeRisk(before, after) {
  const byName = new Map();
  for (const { name, version } of before.values()) {
    if (!byName.has(name)) byName.set(name, new Set());
    byName.get(name).add(version);
  }
  const parts = (v) => v.split(/[.+-]/).slice(0, 2).map(Number);
  const major = ([a, b], [c, d]) => a !== c || (a === 0 && b !== d);
  let minor = false;
  for (const [key, { name, version }] of after) {
    const old = before.get(key);
    const candidates = old?.name === name ? [old.version] : [...(byName.get(name) ?? [])];
    if (!candidates.length || candidates.includes(version)) continue;
    const compatible = candidates.map(parts).filter((candidate) => !major(candidate, parts(version)));
    if (!compatible.length) return { risk: "major", change: `${name}: ${unique(candidates).join(", ")} -> ${version}` };
    if (!compatible.some(([, minorVersion]) => minorVersion === parts(version)[1])) minor = true;
  }
  return { risk: minor ? "minor" : "patch" };
}

function dependents(run, tool, name, range, projects) {
  const spec = range ? `${name}@${range}` : name;
  const data = run(tool === "pnpm"
    ? ["-r", "why", spec, "--depth", "Infinity", "--json"]
    : ["explain", spec, "--json"], { json: true, codes: tool === "npm" ? [0, 1] : [0] });
  if (tool === "npm" && data?.error?.summary?.startsWith("No dependencies found matching ")) return [];
  if (!Array.isArray(data)) throw new Error(`Invalid dependency explanation for ${name}.`);
  const parents = [];
  function add(owner, workspace) {
    if (owner) parents.push({ name: owner, workspace: workspace || projects.has(owner) });
  }
  function walk(node, parent, root) {
    for (const field of DEP_FIELDS) {
      for (const [alias, child] of Object.entries(node[field] ?? {})) {
        if ([alias, child.name, child.from].includes(name)) add(parent, root);
        walk(child, child.name ?? child.from ?? alias, false);
      }
    }
  }
  for (const entry of data) {
    if (Array.isArray(entry.dependents)) {
      for (const dependent of entry.dependents) {
        if (tool === "npm") {
          const owner = dependent.from;
          add(owner?.name, owner?.isWorkspace || owner?.location === "");
        } else {
          add(dependent.name, "depField" in dependent);
        }
      }
    } else {
      walk(entry, entry.name ?? "(workspace root)", true);
    }
  }
  return parents;
}

function versionText(graph, pkg) {
  return unique([...graph.values()].filter((item) => item.name === pkg).map((item) => item.version))
    .join(", ") || "not installed";
}

function repair(project, options, report, log) {
  const run = runner(project, log);
  const { tool } = project;
  const { files, names, workspaceFlags } = projectFiles(project, run);
  const readAudit = () => audit(run, options.registry, options.fallbackRegistry, log);
  const install = (frozen) => run(tool === "pnpm"
    ? ["install", frozen ? "--frozen-lockfile" : "--no-frozen-lockfile", "--ignore-scripts"]
    : ["ci", "--ignore-scripts", "--no-audit"]);
  const original = readAudit();
  report.initial = new Map([...original].filter(([, advisory]) => severe(advisory)));
  report.current = report.initial;
  const noPatch = "No patched version is available. Check upstream issues and schedule a recheck.";
  if (!options.auditOnly) {
    for (const [key, a] of report.initial) if (a.patched === null) report.details.set(key, noPatch);
  }
  if (options.auditOnly || ![...report.initial.values()].some((a) => a.patched !== null)) return;
  const saved = snapshot(files);
  let current = original;
  let attempted = false;
  try {
    install(true);
    let graph = versions(run, tool);
    function attempt(action, label, keys, target, vulnerablePackage = target) {
      const prior = snapshot(files);
      let nextGraph;
      try {
        attempted = true;
        action();
        nextGraph = versions(run, tool);
      } catch (error) {
        restore(files, prior);
        install(true);
        return { reason: `${label} failed: ${error.message}` };
      }
      const { risk, change } = upgradeRisk(graph, nextGraph);
      const next = readAudit();
      const fixed = [...current].filter(([key, a]) => severe(a) && !next.has(key));
      const helps = keys.some((key) => {
        const old = current.get(key);
        const newer = next.get(key);
        return old && (!newer || (newer.paths.length > 0 && newer.paths.length < old.paths.length
          && newer.paths.every((p) => old.paths.includes(p))));
      });
      let reason;
      if (risk === "major" && !options.allowMajor) {
        reason = `${label} needs major upgrade approval (--allow-major): ${change}.`;
      } else if ([...next].some(([key, a]) => severe(a) && !severe(current.get(key) ?? {}))) {
        reason = `${label} introduces a new high or critical advisory.`;
      } else if (!helps) {
        reason = `${label} did not remove an advisory or affected path.`;
      }
      if (reason) {
        restore(files, prior);
        // A solver can change node_modules without changing the saved files.
        install(true);
        return { reason };
      }
      for (const [key, advisory] of fixed) {
        const packages = unique([advisory.pkg, target].filter(Boolean));
        const versionsChanged = packages.map((pkg) =>
          `${pkg}: ${versionText(graph, pkg)} -> ${versionText(nextGraph, pkg)}`).join(". ");
        report.details.set(key, `${label}. ${versionsChanged}. The audit no longer reports this advisory.`
          + (risk === "minor" ? " Review the changelog for the minor upgrade." : "")
          + (risk === "major" ? " Major upgrade approved. Review breaking changes." : ""));
      }
      const versionsChanged = unique([target, vulnerablePackage].filter(Boolean)).map((pkg) =>
        `${pkg}: ${versionText(graph, pkg)} -> ${versionText(nextGraph, pkg)}`).join(". ");
      log(`Kept: ${label}.${versionsChanged ? ` ${versionsChanged}` : ""}`);
      graph = nextGraph;
      current = next;
      return { improvement: `${label} removed affected paths.${versionsChanged ? ` ${versionsChanged}.` : ""}` };
    }

    function upgrade(target, keys, pkg) {
      return attempt(() => {
        if (!PACKAGE.test(target)) throw new Error("Invalid dependency name.");
        const command = tool === "pnpm" ? ["-r", "up", target] : ["update", target, ...workspaceFlags, "--no-audit"];
        run([...command, "--ignore-scripts"]);
        run(["dedupe", "--ignore-scripts", ...(tool === "npm" ? ["--no-audit"] : [])]);
      }, `Updated ${target} within dependency ranges and ran ${tool} dedupe`, keys, target, pkg);
    }

    const reasons = new Map();
    for (const pkg of unique([...report.initial.values()].map((a) => a.pkg))) {
      const active = () => [...current].filter(([, a]) => severe(a) && a.pkg === pkg && a.patched !== null);
      const keys = active().map(([key]) => key);
      if (!keys.length) continue;
      const tried = new Set([pkg]);
      const notes = [];
      const blockers = new Set();
      const record = (result) => {
        const detail = result.reason ?? result.improvement;
        notes.push(detail);
        if (result.reason) log(result.reason);
      };
      record(upgrade(pkg, keys, pkg));
      const queue = [{ name: pkg, ranges: unique(active().map(([, a]) => a.range)) }];
      while (active().length && queue.length) {
        const { name, ranges } = queue.shift();
        const parents = ranges.flatMap((range) => dependents(run, tool, name, range, names));
        for (const parent of parents.filter((p) => p.workspace)) blockers.add(`${parent.name} -> ${name}`);
        for (const parent of unique(parents.filter((p) => !p.workspace).map((p) => p.name))) {
          if (!active().length) break;
          if (tried.has(parent)) continue;
          tried.add(parent);
          record(upgrade(parent, active().map(([key]) => key), pkg));
          queue.push({ name: parent, ranges: [""] });
        }
      }
      if (blockers.size) notes.push(`Workspace dependencies to review with an expert: ${unique(blockers).join(", ")}.`);
      reasons.set(pkg, notes);
    }

    const eligible = [...current].filter(([, a]) => severe(a) && a.patched);
    let overrideReason;
    if (options.allowOverride && tool === "pnpm" && eligible.length) {
      const eligibleKeys = new Set(eligible.map(([key]) => key));
      const ignored = [...current].filter(([key]) => !eligibleKeys.has(key)).map(([, a]) => a.id);
      if (ignored.some((id) => !GHSA.test(id) || eligible.some(([, a]) => a.id === id))) {
        overrideReason = "Skipped overrides because pnpm cannot exclude noneligible advisories by GitHub advisory ID.";
      } else {
        const result = attempt(() => {
          run(["audit", "--fix", "--audit-level", "high", `--registry=${options.registry}`,
            ...unique(ignored).map((id) => `--ignore=${id}`)], { codes: [0, 1] });
          install(false);
        }, "Applied an approved pnpm override. Notify upstream and create a CMS ticket to remove it",
        [...eligibleKeys]);
        overrideReason = result.reason ?? result.improvement;
      }
    }
    // Each accepted state has a successful audit. Recheck the state left on disk.
    const final = readAudit();
    const currentSevere = [...current].filter(([, a]) => severe(a)).map(([key]) => key);
    const finalSevere = [...final].filter(([, a]) => severe(a)).map(([key]) => key);
    if (JSON.stringify(unique(currentSevere)) !== JSON.stringify(unique(finalSevere))) {
      throw new Error("The final audit does not match the last verified state.");
    }
    report.current = new Map([...final].filter(([, a]) => severe(a)));
    for (const [key, advisory] of report.current) {
      let notes = reasons.get(advisory.pkg) ?? [];
      if (advisory.patched === null) {
        notes = [noPatch];
      } else if (advisory.patched === undefined) {
        notes = ["npm does not list a patched version per advisory. Check the upstream advisory.", ...notes];
      } else if (overrideReason) {
        notes = [...notes, overrideReason];
      } else if (tool === "pnpm" && !options.allowOverride) {
        notes = [...notes, "An override requires explicit approval (--allow-override)."];
      }
      report.details.set(key, notes.join(" ") || "The advisory remains after the repair attempts.");
    }
  } catch (error) {
    report.details.clear();
    try {
      restore(files, saved);
      if (attempted) install(true);
    } catch (rollback) {
      throw new Error(`${error.message} Restore failed: ${rollback.message}. Review the dependency files.`);
    }
    throw error;
  }
}

async function findCves(advisories, log) {
  const missing = new Map();
  for (const advisory of advisories) {
    if (!advisory.cves.length && GHSA.test(advisory.id)) {
      if (!missing.has(advisory.id)) missing.set(advisory.id, []);
      missing.get(advisory.id).push(advisory);
    }
  }
  const deadline = AbortSignal.timeout(5_000);
  for (const [id, entries] of missing) {
    try {
      const response = await fetch(`https://api.github.com/advisories/${id}`, {
        headers: { Accept: "application/vnd.github+json" }, signal: deadline,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const advisory = await response.json();
      if (advisory.cve_id) for (const entry of entries) entry.cves = [advisory.cve_id];
    } catch {
      log("Some CVE IDs are unavailable. The report lists the advisory IDs.");
      break;
    }
  }
}

function reportRows(report, auditOnly) {
  const rows = new Map([...report.initial, ...report.current]);
  return [...rows].sort(([a], [b]) => a.localeCompare(b)).map(([key, advisory]) => ({
    ...advisory,
    status: !report.current.has(key) ? "Fixed" : report.error ? "Open (unverified)" : "Open",
    detail: report.details.get(key) ?? (report.error ? "Last known finding. The run did not complete."
      : auditOnly ? "Audit only. No repair attempted." : "Resolved by another dependency update."),
  }));
}

function render(rows, root, error) {
  const items = (status) => rows.filter((row) => row.status.startsWith(status)).map((row) => {
    const id = row.url ? `<a href="${html(row.url)}">${html(row.id)}</a>` : html(row.id);
    return `<tr><th scope="row">${html(row.pkg)}</th><td>${html(row.severity)}</td>
<td>${id}${row.cves.length ? ` / ${html(row.cves.join(", "))}` : ""}<br>${html(row.title)}</td>
<td>${html(row.range || "Not reported")}</td><td>${html(row.patched ?? (row.patched === null ? "None" : "Not reported"))}</td>
<td>${html(row.status)}</td><td>${html(row.detail)}</td></tr>`;
  }).join("\n");
  const table = (status) => {
    const body = items(status);
    return `<h2>${status} advisories</h2>${body ? `<table><thead><tr>
<th scope="col">Package</th><th scope="col">Severity</th><th scope="col">Advisory / CVE</th>
<th scope="col">Affected range</th><th scope="col">Patched range</th><th scope="col">Status</th>
<th scope="col">Result</th></tr></thead><tbody>${body}</tbody></table>` : "<p>None.</p>"}`;
  };
  return `<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Dependency vulnerability report</title>
<style>body{font:1rem system-ui;max-width:90rem;margin:2rem auto;padding:0 1rem}
table{width:100%;border-collapse:collapse}th,td{text-align:left;vertical-align:top;border:1px solid #888;padding:.5rem}</style>
<h1>Dependency vulnerability report</h1><p>${html(root)}</p>
${error ? `<p><strong>Run incomplete:</strong> ${html(error)}</p>` : ""}
${table("Fixed")}${table("Open")}</html>\n`;
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      help: { type: "boolean", short: "h" },
      "audit-only": { type: "boolean" },
      "allow-major": { type: "boolean" },
      "allow-override": { type: "boolean" },
      registry: { type: "string" },
      "fallback-registry": { type: "string" },
      out: { type: "string" },
    },
  });
  if (values.help) return console.log(USAGE.trimEnd());
  if (positionals.length > 1) throw new Error("Specify one package directory.");
  const registry = httpUrl(values.registry ?? REGISTRY);
  if (!registry || registry.search || registry.hash) throw new Error("Specify an HTTP(S) registry URL without credentials.");
  const fallbackRegistry = values["fallback-registry"] === undefined
    ? undefined : httpUrl(values["fallback-registry"]);
  if (values["fallback-registry"] !== undefined
    && (!fallbackRegistry || fallbackRegistry.search || fallbackRegistry.hash)) {
    throw new Error("Specify an HTTP(S) fallback registry URL without credentials.");
  }
  const options = {
    registry: registry.href, fallbackRegistry: fallbackRegistry?.href, auditOnly: values["audit-only"],
    allowMajor: values["allow-major"], allowOverride: values["allow-override"],
  };
  const target = path.resolve(positionals[0] ?? ".");
  let project;
  let packageError;
  try {
    project = packageRoot(target);
  } catch (error) {
    packageError = error;
  }
  const defaultParent = project ? path.join(project.root, "node_modules", ".cache") : tmpdir();
  mkdirSync(defaultParent, { recursive: true });
  const out = values.out === undefined
    ? mkdtempSync(path.join(defaultParent, "fix-cves-"))
    : path.resolve(values.out);
  mkdirSync(out, { recursive: true });
  const file = path.join(out, "report.html");
  const fd = openSync(file, "wx", 0o600);
  const report = { initial: new Map(), current: new Map(), details: new Map() };
  const log = (line) => console.log(clean(line));
  let root = project?.root ?? target;
  try {
    if (packageError) throw packageError;
    log(`Auditing ${root} with ${project.tool}.`);
    repair(project, options, report, log);
  } catch (error) {
    report.error = error.message;
    log(`Error: ${report.error}`);
  }
  try {
    const rows = reportRows(report, options.auditOnly);
    // Send only public advisory IDs, never repository data or registry credentials.
    if ([registry.href, fallbackRegistry?.href].includes(REGISTRY)) await findCves(rows, log);
    for (const row of rows) {
      log(`${row.status}: ${row.pkg} [${row.severity}] ${[row.id, ...row.cves].join(" / ")}. ${row.detail}`);
    }
    const fixed = rows.filter((row) => row.status === "Fixed").length;
    log(`${fixed} fixed, ${rows.length - fixed} open.${report.error ? " Run incomplete." : ""}`);
    writeFileSync(fd, render(rows, root, report.error));
    log(`HTML report: ${file}`);
    process.exitCode = report.error ? 2 : report.current.size ? 1 : 0;
  } finally {
    closeSync(fd);
  }
}

try {
  await main();
} catch (error) {
  console.error(`fix-cves: ${clean(error.message)}`);
  process.exitCode = 2;
}
