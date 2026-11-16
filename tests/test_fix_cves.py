import datetime as dt
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "tools/fix-cves/fix_cves.py"
SPEC = importlib.util.spec_from_file_location("fix_cves", SCRIPT)
fix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fix)


def workspace(directory):
    path = Path(directory)
    (path / "package.json").write_text("{}")
    (path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
    return path


class FixCvesTests(unittest.TestCase):
    def test_branch_name_encodes_slashes(self):
        self.assertEqual(
            "venus/fix-cves-261030-release-2406",
            fix.branch_name("release/2406", dt.date(2026, 10, 30)))

    def test_upgrade_risk_treats_0x_minor_as_major(self):
        before = {"a": {(1, 2, 3)}, "b": {(0, 8, 4)}}
        self.assertEqual("patch", fix.upgrade_risk(before, {"a": {(1, 2, 4)}}))
        self.assertEqual("minor", fix.upgrade_risk(before, {"a": {(1, 3, 0)}}))
        self.assertEqual("major", fix.upgrade_risk(before, {"a": {(2, 0, 0)}}))
        self.assertEqual("major", fix.upgrade_risk(before, {"b": {(0, 9, 0)}}))

    def test_audit_keeps_high_and_critical_and_looks_up_cves(self):
        advisories = {"advisories": {
            "1": {"module_name": "a", "severity": "high", "github_advisory_id": "GHSA-1",
                  "patched_versions": ">=1.0.1", "findings": [{"version": "1.0.0"}]},
            "2": {"module_name": "b", "severity": "moderate", "github_advisory_id": "GHSA-2"},
            "3": {"module_name": "c", "severity": "critical", "github_advisory_id": "GHSA-3",
                  "cves": ["CVE-2026-3"], "patched_versions": "<0.0.0"},
        }}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(fix, "run", return_value=advisories), \
                patch.object(fix, "cve_ids", return_value={"GHSA-1": ["CVE-2026-1"]}) as lookup:
            found = fix.audit(workspace(directory), fix.REGISTRY)
        self.assertEqual(["GHSA-1:a", "GHSA-2:b", "GHSA-3:c"], sorted(found))
        self.assertEqual("moderate", found["GHSA-2:b"]["severity"])
        self.assertEqual(["CVE-2026-1"], found["GHSA-1:a"]["cves"])
        self.assertEqual(["CVE-2026-3"], found["GHSA-3:c"]["cves"])
        lookup.assert_called_once_with({"GHSA-1", "GHSA-2"})
        self.assertFalse(fix.has_patch(found["GHSA-3:c"]))

    def test_dependents_reads_inverted_and_legacy_why_output(self):
        inverted = [{"name": "glob", "dependents": [
            {"name": "shelljs", "dependents": [{"name": "app", "depField": "dependencies"}]},
            {"name": "app", "depField": "devDependencies"},
        ]}]
        legacy = [{"name": "app", "dependencies": {
            "glob": {"version": "7.0.0"},
            "shelljs": {"dependencies": {"glob": {"version": "7.0.0"}}},
        }}]
        with tempfile.TemporaryDirectory() as directory:
            for output in (inverted, legacy):
                with patch.object(fix, "run", return_value=output):
                    self.assertEqual(({"shelljs"}, {"app"}),
                                     fix.dependents(workspace(directory), "glob", "glob"))

    def test_package_without_patch_is_not_upgraded(self):
        repair = object.__new__(fix.Repair)
        with patch.object(fix, "run") as run:
            with self.assertRaisesRegex(fix.Failure, "No patched version"):
                repair.fix("a", [{"id": "GHSA-1", "patched": "<0.0.0"}])
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
