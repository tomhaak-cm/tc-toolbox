import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("../tools/fix-cves/fix_cves.mjs", import.meta.url));

function packageManager() {
  const { mkdirSync, readFileSync, writeFileSync } = require("node:fs");
  const path = require("node:path");
  const args = process.argv.slice(2);
  const command = args[0] === "-r" ? args[1] : args[0];
  const npm = process.argv[1].endsWith("/npm");
  const mode = process.env.FIX_TEST_MODE;
  const lock = npm ? "package-lock.json" : "pnpm-lock.yaml";
  const member = () => ({ name: "app", path: `${process.cwd()}/app` });
  const state = readFileSync(lock, "utf8");
  const vulnerable = state === "original";
  const major = ["major", "override-major"].includes(mode);
  const version = vulnerable ? "0.1.1" : major ? "0.2.0" : "0.1.2";
  const emit = (value) => console.log(JSON.stringify(value));
  const update = () => writeFileSync(lock, "updated");
  const main = {
    id: 1, github_advisory_id: "GHSA-1111-2222-3333", module_name: "problem",
    severity: "critical", title: "<script>alert(1)</script>", url: "javascript:alert(1)",
    vulnerable_versions: "<0.1.2", patched_versions: mode === "no-patch" ? "<0.0.0" : ">=0.1.2",
    cves: ["CVE-2026-1234"], findings: [{ paths: ["app>bridge>adapter>problem"], version }],
  };
  const unrelated = {
    ...main, id: 2, github_advisory_id: "GHSA-2222-2222-3333",
    module_name: "unrelated", severity: "moderate",
  };
  const newCritical = {
    ...main, id: 3, github_advisory_id: "GHSA-3333-2222-3333", module_name: "regression",
  };
  if (process.env.GH_TOKEN || process.env.GITHUB_TOKEN) process.exit(44);
  if (command === "audit") {
    if (args.includes("--fix")) {
      if (!args.includes("--ignore=GHSA-2222-2222-3333")) process.exit(47);
      writeFileSync("pnpm-workspace.yaml", "override");
      update();
    } else if (mode === "fallback-audit" && !args.includes("--registry=https://registry.npmjs.org/")) {
      emit({ error: { code: "ERR_PNPM_AUDIT_BAD_RESPONSE", message: "registry unauthorized" } });
      process.exitCode = 1;
    } else if (mode === "broken-audit" && !vulnerable) {
      emit({ error: "registry down" });
      process.exitCode = 1;
    } else if (npm) {
      emit({ vulnerabilities: vulnerable ? {
        problem: {
          via: [{ source: main.id, name: "problem", severity: main.severity, title: main.title, range: main.vulnerable_versions }],
          nodes: ["node_modules/problem"],
          fixAvailable: false,
        },
        bridge: { via: ["problem"], severity: "critical" },
      } : {} });
      process.exitCode = vulnerable ? 1 : 0;
    } else {
      emit({ advisories: {
        ...(vulnerable ? { 1: main } : {}),
        ...(mode.startsWith("override") ? { 2: unrelated } : {}),
        ...(!vulnerable && mode === "regression" ? { 3: newCritical } : {}),
      } });
      process.exitCode = vulnerable ? 1 : 0;
    }
  } else if (command === "query" || args.includes("-1")) {
    emit([member()]);
  } else if (command === "list" || command === "ls") {
    const graph = { ...member(), dependencies: { bridge: { version: "1.0.0", dependencies: {
      adapter: { version: "1.0.0", dependencies: { problem: { version } } },
    } } } };
    if (args.includes("--parseable")) {
      for (const pkg of [
        { name: "bridge", version: "1.0.0" },
        { name: "adapter", version: "1.0.0" },
        { name: "problem", version },
      ]) {
        const dir = path.join(process.cwd(), "node_modules", ".pnpm", `${pkg.name}@test`,
          "node_modules", pkg.name);
        mkdirSync(dir, { recursive: true });
        writeFileSync(path.join(dir, "package.json"), JSON.stringify(pkg));
        console.log(dir);
      }
      console.log(path.join(process.cwd(), "node_modules", ".pnpm", "encoding@0.1.14",
        "node_modules", "encoding"));
    } else {
      emit(npm ? graph : [graph]);
    }
  } else if (command === "up" || command === "update") {
    const name = args[command === "up" ? 2 : 1];
    if (!args.includes("--ignore-scripts")) process.exit(45);
    if (mode === "bfs" && name === "bridge" || mode === "failed-update" || [
      "major", "broken-audit", "fallback-audit", "regression", "npm-patch",
    ].includes(mode)) update();
    if (mode === "failed-update") {
      writeFileSync("app/package.json", "{}");
      process.exit(42);
    }
  } else if (command === "why" || command === "explain") {
    const spec = args[command === "why" ? 2 : 1];
    const parent = spec.startsWith("problem@") ? "adapter" : spec === "adapter" ? "bridge" : "app";
    emit([{ dependents: [npm ? { from: { name: parent } } : { name: parent }] }]);
  } else if (!["ci", "install", "dedupe"].includes(command)) {
    process.exit(46);
  }
}

function fixture(t, mode, tool = "pnpm", customOutput = true) {
  const root = mkdtempSync(path.join(tmpdir(), "fix-cves-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const app = path.join(root, "app");
  const bin = path.join(root, "bin");
  mkdirSync(app);
  mkdirSync(bin);
  const executable = path.join(bin, tool);
  writeFileSync(executable, `#!${process.execPath}\n(${packageManager})();`, { mode: 0o700 });
  const memberManifest = JSON.stringify({ name: "app" });
  writeFileSync(path.join(app, "package.json"), memberManifest);
  writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "root", workspaces: ["app"] }));
  const config = path.join(root, "pnpm-workspace.yaml");
  if (tool === "pnpm") writeFileSync(config, "packages:\n  - app\n");
  const lock = path.join(root, tool === "pnpm" ? "pnpm-lock.yaml" : "package-lock.json");
  writeFileSync(lock, "original");
  let runs = 0;
  return {
    run(...args) {
      const out = path.join(root, `out-${runs++}`);
      const outputArgs = customOutput ? ["--out", out] : [];
      const result = spawnSync(process.execPath, [
        cli, app, "--registry", "http://localhost:12345/", ...outputArgs, ...args,
      ], {
        cwd: tmpdir(), encoding: "utf8", env: {
          ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
          FIX_TEST_MODE: mode, GH_TOKEN: "test-token", GITHUB_TOKEN: "test-token",
        },
      });
      assert.equal(result.error, undefined);
      const reportPath = customOutput
        ? path.join(out, "report.html")
        : result.stdout.match(/^HTML report: (.+)$/m)?.[1];
      assert.ok(reportPath, result.stdout);
      return {
        ...result, reportPath, report: readFileSync(reportPath, "utf8"),
        lock: readFileSync(lock, "utf8"), member: readFileSync(path.join(app, "package.json"), "utf8"),
        config: tool === "pnpm" ? readFileSync(config, "utf8") : null,
      };
    },
    memberManifest, root,
  };
}

test("the default report directory is inside the project node_modules cache", (t) => {
  const { root, run } = fixture(t, "no-patch", "pnpm", false);
  const result = run("--audit-only");
  assert.equal(result.status, 1, result.stdout);
  assert.equal(path.dirname(path.dirname(result.reportPath)),
    path.join(realpathSync(root), "node_modules", ".cache"));
  assert.match(path.basename(path.dirname(result.reportPath)), /^fix-cves-/);
  assert.ok(existsSync(result.reportPath));
  assert.equal(result.lock, "original");
});

test("pnpm walks dependents breadth-first and reports the verified fix from a workspace member", (t) => {
  const { run } = fixture(t, "bfs");
  const result = run();
  assert.equal(result.status, 0, result.stdout);
  assert.match(result.stdout, /> pnpm -r list --depth Infinity --parseable/);
  assert.match(result.stdout, /up problem.*up adapter.*up bridge/s);
  assert.match(result.stdout, /Fixed: problem \[critical\].*CVE-2026-1234.*Updated bridge.*problem: 0.1.1 -> 0.1.2/);
  assert.match(result.report, /<h2>Fixed advisories<\/h2>.*CVE-2026-1234.*&lt;script&gt;/s);
  assert.doesNotMatch(result.report, /javascript:|<script>/);
  assert.equal(result.lock, "updated");
});

test("an explicitly configured fallback registry retries failed audits", (t) => {
  const { run } = fixture(t, "fallback-audit");
  const result = run("--fallback-registry", "https://registry.npmjs.org/");
  assert.equal(result.status, 0, result.stdout);
  assert.match(result.stdout, /retrying with https:\/\/registry\.npmjs\.org\//);
  assert.match(result.stdout, /> pnpm audit --json --registry=https:\/\/registry\.npmjs\.org\//);
  assert.match(result.stdout, /1 fixed, 0 open/);
  assert.equal(result.lock, "updated");
});

test("a configured fallback registry stays unused when the primary audit succeeds", (t) => {
  const { run } = fixture(t, "bfs");
  const result = run("--fallback-registry", "https://registry.npmjs.org/");
  assert.equal(result.status, 0, result.stdout);
  assert.doesNotMatch(result.stdout, /retrying with/);
  assert.doesNotMatch(result.stdout, /--registry=https:\/\/registry\.npmjs\.org\//);
});

test("npm reports individual advisories, not meta-vulnerabilities", (t) => {
  const { run } = fixture(t, "npm-patch", "npm");
  const result = run();
  assert.equal(result.status, 0, result.stdout);
  assert.match(result.stdout, /npm update problem --workspaces --include-workspace-root/);
  assert.match(result.stdout, /1 fixed, 0 open/);
  assert.match(result.report, /Not reported/);
  assert.equal(result.lock, "updated");
});

test("audit-only and findings without a patch leave dependencies alone", (t) => {
  const { run } = fixture(t, "no-patch");
  for (const flags of [["--audit-only"], ["--allow-override"]]) {
    const result = run(...flags);
    assert.equal(result.status, 1, result.stdout);
    assert.doesNotMatch(result.stdout, /> pnpm (install|-r up|audit --fix)/);
    assert.match(result.report, flags.includes("--audit-only") ? /Audit only/ : /No patched version/);
    assert.equal(result.lock, "original");
  }
});

test("unapproved breaking upgrades, regressions, and failed updates restore dependency files", (t) => {
  for (const [mode, reason] of [
    ["major", /major upgrade approval.*problem: 0.1.1 -&gt; 0.2.0/],
    ["regression", /introduces a new high or critical advisory/],
    ["failed-update", /exit 42/],
  ]) {
    const { run, memberManifest } = fixture(t, mode);
    const result = run();
    assert.equal(result.status, 1, result.stdout);
    assert.match(result.report, reason);
    assert.equal(result.lock, "original");
    assert.equal(result.member, memberManifest);
  }
});

test("a failed verification audit restores the lockfile and marks the report incomplete", (t) => {
  const { run } = fixture(t, "broken-audit");
  const result = run();
  assert.equal(result.status, 2, result.stdout);
  assert.equal(result.lock, "original");
  assert.match(result.stdout, /> pnpm install --frozen-lockfile.*> pnpm install --frozen-lockfile.*Audit failed/s);
  assert.match(result.report, /Open \(unverified\)/);
});

test("pnpm last resort needs explicit override and breaking-upgrade approval", (t) => {
  const { run } = fixture(t, "override-major");
  assert.doesNotMatch(run().stdout, /> pnpm audit --fix/);
  const denied = run("--allow-override");
  assert.equal(denied.status, 1);
  assert.equal(denied.lock, "original");
  assert.equal(denied.config, "packages:\n  - app\n");
  const accepted = run("--allow-override", "--allow-major");
  assert.equal(accepted.status, 0, accepted.stdout);
  assert.match(accepted.stdout, /audit --fix.*--ignore=GHSA-2222-2222-3333/);
  assert.match(accepted.report, /approved pnpm override.*CMS ticket/);
  assert.doesNotMatch(accepted.report, /unrelated/);
  assert.equal(accepted.config, "override");
});
