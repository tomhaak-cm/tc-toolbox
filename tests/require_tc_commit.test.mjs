import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { decide } from "../hooks/require-tc-commit.mjs";

const run = (command, cwd) => decide({ toolName: "bash", toolArgs: JSON.stringify({ command }), cwd });

test("denies a commit without a Models trailer", () => {
  assert.equal(run('git commit -m "fix: x"').permissionDecision, "deny");
  assert.equal(run('cd a && git -C b commit -am "fix: x"').permissionDecision, "deny");
});

test("allows a commit with a Models trailer", () => {
  assert.equal(run('git commit -m "fix: x" -m "Models: gpt-6-luna"'), null);
});

test("reads the message file", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "tc-commit-"));
  writeFileSync(path.join(dir, "msg"), "fix: x\n\nModels: gpt-6-luna\n");
  writeFileSync(path.join(dir, "bad"), "fix: x\n");
  assert.equal(run("git commit -F msg", dir), null);
  assert.equal(run("git commit -F bad", dir).permissionDecision, "deny");
});

test("ignores other commands and --no-edit", () => {
  assert.equal(run("git status"), null);
  assert.equal(run("git log --grep commit"), null);
  assert.equal(run("git commit --amend --no-edit"), null);
});
