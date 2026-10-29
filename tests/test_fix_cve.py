import argparse
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.request import Request


SCRIPT = Path(__file__).resolve().parents[1] / "skills/fix-cve/scripts/fix_cve.py"
SPEC = importlib.util.spec_from_file_location("fix_cve", SCRIPT)
cve = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cve)


def alert(package="example", identifier="CVE-2026-1234"):
    return {
        "number": 1,
        "security_advisory": {"cve_id": identifier},
        "dependency": {
            "package": {"name": package, "ecosystem": "npm"},
            "manifest_path": "package.json",
        },
        "security_vulnerability": {
            "severity": "high", "vulnerable_version_range": "<1.0.1",
            "first_patched_version": {"identifier": "1.0.1"},
        },
    }


def issue(summary="example CVE-2026-1234", key="CMS-1"):
    return {
        "key": key,
        "fields": {
            "summary": summary, "description": None, "versions": [],
            "status": {"name": "Open"},
            "customfield_12042": {"value": "High"},
            "customfield_12043": "Upgrade the dependency",
        },
    }


class CollectionTests(unittest.TestCase):
    def test_paginated_board_reads_every_page(self):
        jira = object.__new__(cve.Atlassian)
        with patch.object(jira, "request", side_effect=[
            {"issues": [issue(key="CMS-1")], "total": 2},
            {"issues": [issue(key="CMS-2")], "total": 2},
        ]) as request:
            result = list(jira.board_issues(109, "project = CMS"))
        self.assertEqual(["CMS-1", "CMS-2"], [item["key"] for item in result])
        self.assertEqual(1, request.call_args_list[1].kwargs["params"]["startAt"])

    def test_incomplete_pagination_fails_instead_of_truncating(self):
        jira = object.__new__(cve.Atlassian)
        with patch.object(jira, "request", return_value={"issues": [], "total": 1}):
            with self.assertRaises(cve.WorkflowError):
                list(jira.board_issues(109, "project = CMS"))

    def test_same_cve_needs_unambiguous_package_match(self):
        alerts = [alert("example"), alert("other")]
        self.assertEqual([alerts[0]], cve.match_alerts(issue(), alerts)[1])
        _, matches, reason = cve.match_alerts(issue("CVE-2026-1234"), alerts)
        self.assertEqual([], matches)
        self.assertIn("Ambiguous", reason)

    def test_unmatched_alert_is_not_declared_withdrawn(self):
        _, matches, reason = cve.match_alerts(issue(), [alert(identifier=None)])
        self.assertEqual([], matches)
        self.assertIn("withdrawal not confirmed", reason)

    def test_multiple_cves_cannot_silently_drop_one(self):
        _, matches, reason = cve.match_alerts(
            issue("example CVE-2026-1234 CVE-2026-4321"), [alert()])
        self.assertEqual([], matches)
        self.assertIn("Some CVE IDs", reason)

    def test_only_supported_rows_in_release_overview_count(self):
        storage = """
        <h1>Other table</h1><table><tr><td>v12.9999.1</td><td>ACTIVE</td></tr></table>
        <h1>Release Branches Overview</h1>
        <table>
        <tr><td>v12.2406.4 (LTS)</td><td>EXTENDED</td></tr>
        <tr><td>v13.2512.1</td><td>UPCOMING</td></tr>
        <tr><td>v11.2301.1</td><td>ARCHIVED</td></tr>
        </table>
        <table><tr><td>v12.8888.1</td><td>ACTIVE</td></tr></table>
        """
        self.assertEqual({"2406.4", "2512.1"}, cve.release_branches(storage))

    def test_missing_rating_statement_is_unrated(self):
        ticket = issue()
        ticket["fields"]["customfield_12043"] = None
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(
                state=Path(directory) / "state/run.json", repo=Path(directory) / "repo",
                prefix="OTHER", status_category=None, board=109,
            )
            with patch.object(cve, "repository", return_value=(args.repo, "owner/repo", "main")), \
                    patch.object(cve, "command", return_value=[[alert()]]), \
                    patch.object(cve, "Atlassian") as jira, \
                    patch.object(cve, "report"):
                jira.return_value.board_issues.side_effect = [[ticket], [ticket]]
                cve.collect(args)
            saved = cve.load(args.state)
            self.assertEqual("unrated", saved["tickets"]["CMS-1"]["status"])


class UpgradeTests(unittest.TestCase):
    def test_patch_minor_and_major_classification(self):
        before = {"a": {(1, 0, 0)}}
        self.assertEqual("patch", cve.upgrade_risk(before, {"a": {(1, 0, 1)}}))
        self.assertEqual("minor", cve.upgrade_risk(before, {"a": {(1, 1, 0)}}))
        self.assertEqual("major", cve.upgrade_risk(before, {"a": {(2, 0, 0)}}))

    def test_existing_major_does_not_hide_new_minor(self):
        self.assertEqual("minor", cve.upgrade_risk(
            {"a": {(1, 0, 0), (2, 0, 0)}},
            {"a": {(1, 1, 0), (2, 0, 0)}},
        ))

    def test_dependency_parents_include_intermediate_and_direct_owners(self):
        tree = [{
            "name": "workspace",
            "dependencies": {
                "parent": {"dependencies": {"bad": {"version": "1.0.0"}}},
                "bad": {"version": "1.0.0"},
            },
        }]
        with patch.object(cve, "command", return_value=tree):
            self.assertEqual((["parent"], ["workspace"]), cve.dependency_parents(Path("."), "bad"))

    def test_rejected_upgrade_restores_only_manifest_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "package.json"
            package.write_text('{"name":"a","version":"1.0.0"}')
            snapshot = cve.manifests(root)
            package.write_text('{"name":"a","version":"2.0.0"}')
            (root / "pnpm-lock.yaml").write_text("new lock")
            source = root / "keep.js"
            source.write_text("unchanged")
            with patch.object(cve, "command"):
                cve.restore_manifests(root, snapshot)
            self.assertEqual(snapshot[package], package.read_bytes())
            self.assertFalse((root / "pnpm-lock.yaml").exists())
            self.assertEqual("unchanged", source.read_text())


class SafetyTests(unittest.TestCase):
    def test_state_is_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            cve.save(path, {"schema": 1})
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_cross_origin_redirect_never_forwards_credentials(self):
        handler = cve.SameOriginRedirect()
        with self.assertRaises(cve.WorkflowError):
            handler.redirect_request(
                Request("https://jira.example/api"), None, 302, "", {},
                "https://different.example/api",
            )

    def test_build_commands_do_not_inherit_api_credentials(self):
        with patch.dict(os.environ, {
            "JIRA_TOKEN": "private", "CONFLUENCE_TOKEN": "private",
            "GH_TOKEN": "private", "GITHUB_TOKEN": "private", "NPM_TOKEN": "registry",
        }, clear=True):
            self.assertEqual({"NPM_TOKEN": "registry"}, cve.build_environment())

    def test_checks_must_cover_every_changed_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = {"app": {
                "build": ["build"], "lint": ["lint"], "test": ["test"],
            }}
            with patch.object(cve, "changed_files", return_value=["other/package.json"]):
                with self.assertRaises(cve.WorkflowError):
                    cve.checks_for(root, config)
            with patch.object(cve, "changed_files", return_value=["app/package.json"]):
                self.assertEqual(3, len(cve.checks_for(root, config)))

    def test_checks_cannot_escape_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cve, "changed_files", return_value=["package.json"]):
                with self.assertRaises(cve.WorkflowError):
                    cve.checks_for(Path(directory), {"..": {}})

    def test_invalid_checks_fail_before_any_dependency_command(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checks.json"
            path.write_text(json.dumps({".": {"build": ["build"], "lint": ["lint"]}}))
            with patch.object(cve, "ensure_group") as prepare, patch.object(cve, "command") as command:
                with self.assertRaises(cve.WorkflowError):
                    cve.apply(argparse.Namespace(checks=path), {})
                prepare.assert_not_called()
                command.assert_not_called()

    def test_publish_requires_explicit_approval_before_api_access(self):
        with patch.object(cve, "Atlassian") as jira:
            with self.assertRaises(cve.WorkflowError):
                cve.publish(argparse.Namespace(yes=False), {})
            jira.assert_not_called()

    def test_unrated_ticket_cannot_be_modified(self):
        state = {"tickets": {"CMS-1": {"status": "unrated"}}}
        with patch.object(cve, "Atlassian") as jira:
            with self.assertRaises(cve.WorkflowError):
                cve.decide(argparse.Namespace(ticket="CMS-1"), state)
            jira.assert_not_called()

    def test_wont_fix_preserves_existing_versions(self):
        state = {
            "tickets": {"CMS-1": {
                "status": "decision", "base": "2406.1", "affects_versions": ["2406.1"],
            }},
            "groups": {},
        }
        with patch.object(cve, "Atlassian") as jira, patch.object(cve, "save"):
            jira.return_value.issue.return_value = {
                "fields": {"customfield_11680": [{"name": "2301.1"}]},
            }
            cve.decide(argparse.Namespace(
                ticket="CMS-1", wont_fix="2406.1", state=Path("unused")), state)
            jira.return_value.edit.assert_called_once_with("CMS-1", {
                "customfield_11680": [{"name": "2301.1"}, {"name": "2406.1"}],
            })
        self.assertEqual("skipped", state["tickets"]["CMS-1"]["status"])

    def test_verify_rejects_source_mutations_without_marking_fixed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = {"tickets": {"CMS-1": {"base": "main", "status": "changed"}}}
            group = {"base": "main", "path": str(root)}
            with patch.object(cve, "checks_for", return_value=[(root, "build", ["build"])]), \
                    patch.object(cve, "save"), \
                    patch.object(cve, "fingerprint", side_effect=["before", "after"]), \
                    patch.object(cve.subprocess, "run") as run:
                run.return_value.returncode = 0
                with self.assertRaises(cve.WorkflowError):
                    cve.verify_group(state, group, root / "run.json", {})
            self.assertEqual("failed", state["tickets"]["CMS-1"]["status"])
            self.assertTrue(state["tickets"]["CMS-1"]["verification_pending"])
            self.assertNotIn("verification", group)

    def test_final_audit_blocks_a_reintroduced_vulnerability(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ticket = {
                "key": "CMS-1", "base": "main", "status": "changed",
                "repair_mode": "automatic",
                "alerts": [{"manifest": "package.json", "package": "example", "cve": "CVE-2026-1234"}],
            }
            state = {"tickets": {"CMS-1": ticket}}
            group = {"base": "main", "path": str(root)}
            with patch.object(cve, "save"), \
                    patch.object(cve, "workspace_for", return_value=root), \
                    patch.object(cve, "audit", return_value={
                        "1": {"module_name": "example", "cves": ["CVE-2026-1234"]},
                    }), \
                    patch.object(cve.subprocess, "run") as run:
                with self.assertRaises(cve.WorkflowError):
                    cve.verify_group(state, group, root / "state.json", {})
                run.assert_not_called()
            self.assertEqual("hard", ticket["status"])
            self.assertNotIn("verification", group)

    def test_publication_rejects_changes_after_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "run.json"
            group = {
                "path": directory, "base": "main", "base_commit": "original",
                "verification": {"fingerprint": "verified"},
            }
            state = {
                "groups": {"main": group},
                "tickets": {"CMS-1": {"base": "main", "status": "fixed"}},
            }
            with patch.object(cve, "Atlassian"), \
                    patch.object(cve, "ensure_group", return_value=group), \
                    patch.object(cve, "start_progress"), \
                    patch.object(cve, "command", return_value="original") as command, \
                    patch.object(cve, "fingerprint", return_value="modified"):
                with self.assertRaises(cve.WorkflowError):
                    cve.publish(argparse.Namespace(yes=True, state=state_path), state)
                self.assertEqual([["git", "rev-parse", "HEAD"]],
                                 [call.args[0] for call in command.call_args_list])

    def test_clean_worktree_without_new_commits_can_be_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            group = {"path": directory, "base_commit": "original"}
            state = {"groups": {"main": group}, "repo_path": "/source"}
            with patch.object(cve, "command", side_effect=["", "original", ""]) as command, \
                    patch.object(cve, "save"):
                cve.cleanup(argparse.Namespace(state=Path(directory) / "run.json"), state)
            self.assertTrue(group["cleaned"])
            self.assertEqual(["git", "worktree", "remove", Path(directory)], command.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
