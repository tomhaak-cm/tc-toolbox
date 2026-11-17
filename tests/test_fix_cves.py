import datetime as dt
import importlib.util
import os
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

    def test_engine_ranges_match_installed_versions(self):
        self.assertTrue(fix.satisfies("v18.20.1", "18"))
        self.assertFalse(fix.satisfies("v24.18.0", "18"))
        self.assertTrue(fix.satisfies("v20.1.0", "^14 || ^16 || >=18.0"))
        self.assertFalse(fix.satisfies("9.0.0", "^8.6"))
        self.assertTrue(fix.satisfies("8.15.0", "^8.6"))
        self.assertTrue(fix.satisfies("v18.0.0", "18.0.0 - 20.0.0"))
        self.assertFalse(fix.satisfies("v21.0.0", "18 - 20"))


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "nvm.sh").touch()
        env = patch.dict(os.environ, {"NVM_DIR": str(self.root), "COREPACK_HOME": str(self.root / "cache")})
        env.start()
        self.addCleanup(env.stop)

    def test_installs_missing_versions_and_switches_subprocess_path(self):
        calls = []

        def run(args, cwd, **kwargs):
            calls.append(args)
            if args[0] == "bash":
                if "ls-remote" in args:
                    return "v20.19.0\nv22.1.0\n"
                if "ls" in args:
                    return "v18.20.8\n"
                if "install" in args:
                    return ""
                return "/selected/node/bin:" + os.environ["PATH"]
            if args[0] == "pnpm":
                return "8.9.0" if any(call[:2] == ["corepack", "prepare"] for call in calls) else "10.0.0"
            if args[0] == "node":
                return "v20.19.0"
            return ""

        projects = [
            (Path("a/package.json"), {"node": "20", "pnpm": "^8.6"}),
            (Path("b/package.json"), {"node": ">=20 <21", "pnpm": ">=8.8 <9"}),
        ]
        with patch.object(fix, "find_projects", return_value=projects), \
                patch.object(fix, "run", side_effect=run), \
                patch.object(fix.shutil, "which", return_value="/bin/tool"):
            tools = fix.require_engines(self.root)
            self.addCleanup(tools.cleanup)
            self.assertTrue(any("install" in call and "20.19.0" in call for call in calls))
            self.assertTrue(any(call[:2] == ["corepack", "prepare"] and
                                "^8.6" in call[2] and ">=8.8 <9" in call[2] for call in calls))
            self.assertIn("/selected/node/bin", os.environ["PATH"])
            self.assertTrue(os.environ["PATH"].startswith(tools.name))
            self.assertTrue(any(call[:2] == ["corepack", "enable"] and call[-1] == "pnpm" for call in calls))

    def test_reports_failed_corepack_install(self):
        def run(args, cwd, **kwargs):
            if args[:2] == ["corepack", "prepare"]:
                raise fix.Failure("network error")
            return "10.0.0" if args[0] == "pnpm" else ""

        with patch.object(fix, "find_projects", return_value=[
            (Path("package.json"), {"pnpm": "^8.6"})
        ]), patch.object(fix, "run", side_effect=run), \
                patch.object(fix.shutil, "which", return_value="/bin/tool"):
            with self.assertRaisesRegex(fix.EngineMismatch, "Corepack.*network error"):
                fix.require_engines(self.root)

    def test_reports_incompatible_node_requirements(self):
        with patch.object(fix, "find_projects", return_value=[
            (Path("a/package.json"), {"node": "18"}),
            (Path("b/package.json"), {"node": "20"}),
        ]), patch.object(fix, "run", return_value="v18.20.8\nv20.19.0\n"):
            with self.assertRaisesRegex(fix.EngineMismatch, "No Node.js version"):
                fix.require_engines(self.root)

    def test_reports_failed_nvm_install(self):
        def run(args, cwd, **kwargs):
            if "install" in args:
                raise fix.Failure("download failed")
            return "v20.19.0\n" if "ls-remote" in args else "N/A"

        with patch.object(fix, "find_projects", return_value=[
            (Path("package.json"), {"node": "20"})
        ]), patch.object(fix, "run", side_effect=run):
            with self.assertRaisesRegex(fix.EngineMismatch, "NVM install.*download failed"):
                fix.require_engines(self.root)

    def test_switches_when_project_version_does_not_match(self):
        calls = []

        def run(args, cwd, **kwargs):
            calls.append(args)
            if args[0] == "pnpm":
                if cwd == self.root / "a" and not any(call[:2] == ["corepack", "prepare"] for call in calls):
                    return "7.0.0"
                return "8.9.0"
            return ""

        with patch.object(fix, "find_projects", return_value=[
            (Path("a/package.json"), {"pnpm": "^8.6"})
        ]), patch.object(fix, "run", side_effect=run), \
                patch.object(fix.shutil, "which", return_value="/bin/tool"):
            tools = fix.require_engines(self.root)
            self.addCleanup(tools.cleanup)
            self.assertTrue(any(call[:2] == ["corepack", "prepare"] for call in calls))

    def test_reports_invalid_project_corepack_version(self):
        def run(args, cwd, **kwargs):
            return "7.0.0" if args[0] == "pnpm" and cwd == self.root / "a" else "8.9.0"

        with patch.object(fix, "find_projects", return_value=[
            (Path("a/package.json"), {"pnpm": "^8.6"})
        ]), patch.object(fix, "run", side_effect=run), \
                patch.object(fix.shutil, "which", return_value="/bin/tool"):
            with self.assertRaisesRegex(fix.EngineMismatch, "7.0.0.*a/package.json"):
                fix.require_engines(self.root)


if __name__ == "__main__":
    unittest.main()
