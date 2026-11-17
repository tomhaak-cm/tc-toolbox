import assert from "node:assert/strict";
import { test } from "node:test";
import { branchName, satisfies, upgradeRisk } from "../tools/fix-cves/fix_cves.mjs";

test("branch name encodes slashes in the base", () => {
  assert.equal(branchName("release/2406", new Date(2026, 9, 30)), "venus/fix-cves-261030-release-2406");
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
