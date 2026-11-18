import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { branchName, cleanIncompatiblePnpmModules, pullLatest, satisfies, upgradeRisk } from "../tools/fix-cves/fix_cves.mjs";

function git(repo, ...args) {
  return execFileSync("git", args, { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function repositories(t) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "fix-cves-pull-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const remote = path.join(dir, "remote");
  const local = path.join(dir, "local");
  git(dir, "init", "-q", "--initial-branch=main", remote);
  git(remote, "config", "user.name", "Test");
  git(remote, "config", "user.email", "test@example.com");
  writeFileSync(path.join(remote, "tracked"), "original\n");
  git(remote, "add", "tracked");
  git(remote, "commit", "-qm", "initial");
  git(dir, "clone", "-q", remote, local);
  git(local, "config", "user.name", "Test");
  git(local, "config", "user.email", "test@example.com");
  return { remote, local };
}

test("pull choices skip, exit, and reject non-interactive input", async (t) => {
  const { local } = repositories(t);
  writeFileSync(path.join(local, "tracked"), "local\n");
  assert.equal(await pullLatest(local, "main", undefined, async () => "skip"), "main");
  await assert.rejects(pullLatest(local, "main", undefined, async () => "exit"), /Pull canceled/);
  await assert.rejects(pullLatest(local, "main"), /Run interactively/);
  assert.equal(readFileSync(path.join(local, "tracked"), "utf8"), "local\n");
});

test("stash restores staged and unstaged changes after pull and after pull failure", async (t) => {
  const { local, remote } = repositories(t);
  writeFileSync(path.join(remote, "upstream"), "new\n");
  git(remote, "add", "upstream");
  git(remote, "commit", "-qm", "upstream");
  writeFileSync(path.join(local, "tracked"), "staged\n");
  git(local, "add", "tracked");
  writeFileSync(path.join(local, "tracked"), "unstaged\n");
  await pullLatest(local, "main", undefined, async () => "stash");
  assert.equal(readFileSync(path.join(local, "upstream"), "utf8"), "new\n");
  assert.equal(readFileSync(path.join(local, "tracked"), "utf8"), "unstaged\n");
  assert.equal(git(local, "show", ":tracked"), "staged");
  assert.equal(git(local, "stash", "list"), "");

  git(local, "remote", "remove", "origin");
  await assert.rejects(pullLatest(local, "main", undefined, async () => "stash"), /git pull/);
  assert.equal(readFileSync(path.join(local, "tracked"), "utf8"), "unstaged\n");
  assert.equal(git(local, "show", ":tracked"), "staged");
  assert.equal(git(local, "stash", "list"), "");
});

test("discard removes tracked changes and only untracked files that block the pull", async (t) => {
  const { local, remote } = repositories(t);
  writeFileSync(path.join(remote, "incoming"), "upstream\n");
  git(remote, "add", "incoming");
  git(remote, "commit", "-qm", "upstream");
  writeFileSync(path.join(local, "tracked"), "local\n");
  writeFileSync(path.join(local, "incoming"), "blocking\n");
  writeFileSync(path.join(local, "keep"), "keep\n");
  await pullLatest(local, "main", undefined, async () => "discard");
  assert.equal(readFileSync(path.join(local, "tracked"), "utf8"), "original\n");
  assert.equal(readFileSync(path.join(local, "incoming"), "utf8"), "upstream\n");
  assert.equal(readFileSync(path.join(local, "keep"), "utf8"), "keep\n");
});

test("stash remains available when restoring changes conflicts with the pull", async (t) => {
  const { local, remote } = repositories(t);
  writeFileSync(path.join(remote, "tracked"), "upstream\n");
  git(remote, "add", "tracked");
  git(remote, "commit", "-qm", "upstream");
  writeFileSync(path.join(local, "tracked"), "local\n");
  await assert.rejects(pullLatest(local, "main", undefined, async () => "stash"), /stash.*remains in Git/);
  assert.match(git(local, "stash", "list"), /stash@\{0\}/);
  assert.equal(git(local, "show", "stash@{0}:tracked"), "local");
});

test("branch name encodes slashes in the base", () => {
  assert.equal(branchName("release/2406", new Date(2026, 9, 30)), "venus/fix-cves-261030-release-2406");
});

test("pnpm cleanup requires a lockfile mismatch and stays within workspace members", (t) => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "fix-cves-pnpm-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const workspace = path.join(dir, "workspace");
  const member = path.join(workspace, "member");
  const ignored = path.join(workspace, "ignored");
  const outside = path.join(dir, "outside");
  for (const project of [workspace, member, ignored, outside]) {
    mkdirSync(path.join(project, "node_modules"), { recursive: true });
  }
  const store = path.join(workspace, "node_modules", ".pnpm");
  mkdirSync(store);
  writeFileSync(path.join(workspace, "pnpm-lock.yaml"), "lockfileVersion: '6.0'\n");
  const installed = path.join(store, "lock.yaml");
  const listMember = () => [{ path: member }];

  cleanIncompatiblePnpmModules(workspace, listMember);
  writeFileSync(installed, "lockfileVersion: 6.0\n");
  cleanIncompatiblePnpmModules(workspace, listMember);
  assert.ok(existsSync(installed));

  writeFileSync(installed, "lockfileVersion: '9.0'\n");
  assert.throws(
    () => cleanIncompatiblePnpmModules(workspace, () => [...listMember(), { path: outside }]),
    /Refusing to clean node_modules outside the workspace/,
  );
  assert.ok(existsSync(installed));
  assert.ok(existsSync(path.join(member, "node_modules")));

  cleanIncompatiblePnpmModules(workspace, listMember);
  for (const project of [workspace, member]) assert.ok(!existsSync(path.join(project, "node_modules")));
  for (const project of [ignored, outside]) assert.ok(existsSync(path.join(project, "node_modules")));
});

test("upgrade risk treats a 0.x minor jump as major", () => {
  const before = new Map([["b", new Set(["0.8.4"])]]);
  const after = new Map([["b", new Set(["0.9.0"])]]);
  assert.equal(upgradeRisk(before, after), "major");
});

test("upgrade risk classifies minor and patch jumps", () => {
  const minor = upgradeRisk(new Map([["a", new Set(["1.2.3"])]]), new Map([["a", new Set(["1.3.0"])]]));
  const patch = upgradeRisk(new Map([["a", new Set(["1.2.3"])]]), new Map([["a", new Set(["1.2.4"])]]));
  assert.equal(minor, "minor");
  assert.equal(patch, "patch");
});

test("engine ranges match installed versions", () => {
  assert.equal(satisfies("20.1.0", "^18.0.0 || >=20"), true);
  assert.equal(satisfies("22.0.0", "^18.0.0"), false);
  assert.equal(satisfies("20.9.0", "18 - 20"), true);
  assert.equal(satisfies("21.0.0", "18 - 20"), false);
  assert.equal(satisfies("9.0.0", "*"), true);
});
