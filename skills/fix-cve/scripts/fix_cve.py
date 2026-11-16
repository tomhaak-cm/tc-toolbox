#!/usr/bin/env python3
"""Resumable CVE maintenance. Python standard library, git, gh, and pnpm."""

import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from html import escape
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


FIELDS = [
    "summary", "description", "versions", "status", "assignee",
    "customfield_12042", "customfield_12043", "customfield_11680",
]
TRAILER = "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
SKIPPABLE = ("ready", "decision", "difficult")
FIXABLE = {
    "ready": "Yes, automatic repair pending apply",
    "changed": "Yes, manual repair recorded",
    "fixed": "Fixed and verified",
    "resolved": "Fixed, Jira resolved",
    "resolve_failed": "Fixed, Jira resolve failed",
    "difficult": "No, difficult",
    "decision": "Decision needed",
    "failed": "Verification failed",
    "applying": "Interrupted during upgrade",
    "skipped": "Skipped",
    "unrated": "Not touched",
}


class WorkflowError(Exception):
    pass


class ApprovalNeeded(WorkflowError):
    def __init__(self, message, level):
        super().__init__(message)
        self.level = level


class SameOriginRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        old, new = urlsplit(request.full_url), urlsplit(new_url)
        if (old.scheme, old.netloc) != (new.scheme, new.netloc):
            raise WorkflowError("Refusing to send Atlassian credentials to a different origin")
        return super().redirect_request(request, response, code, message, headers, new_url)


def build_environment():
    return {
        key: value for key, value in os.environ.items()
        if not key.startswith(("JIRA_", "CONFLUENCE_")) and key not in ("GH_TOKEN", "GITHUB_TOKEN")
    }


def command(args, cwd=None, json_output=False, allowed=(0,)):
    result = subprocess.run(
        [str(arg) for arg in args], cwd=cwd, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=build_environment() if args[0] == "pnpm" else None,
    )
    if result.returncode not in allowed:
        # Do not echo arguments: a caller can pass credentials to a build command.
        raise WorkflowError(
            "{} failed (exit {}): {}".format(args[0], result.returncode, result.stderr[-4000:])
        )
    if json_output:
        try:
            return json.loads(result.stdout)
        except ValueError as exc:
            raise WorkflowError("{} did not return JSON".format(args[0])) from exc
    return result.stdout.strip()


def save(path, state):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".run-")
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(state, stream, indent=2)
            stream.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load(path):
    with Path(path).open() as stream:
        state = json.load(stream)
    if state.get("schema") != 1:
        raise WorkflowError("Unsupported state schema")
    return state


class Atlassian:
    def __init__(self, service="JIRA"):
        self.base = os.environ.get(service + "_BASE_URL", "").rstrip("/")
        token = os.environ.get(service + "_TOKEN", "")
        email = os.environ.get(service + "_EMAIL", "")
        if service == "CONFLUENCE":
            token = token or os.environ.get("JIRA_TOKEN", "")
            email = email or os.environ.get("JIRA_EMAIL", "")
        if not self.base or not token:
            raise WorkflowError("Set {}_BASE_URL and {}_TOKEN".format(service, service))
        if urlsplit(self.base).scheme != "https":
            raise WorkflowError("Atlassian URLs must use HTTPS")
        self.authorization = "Bearer " + token
        if email:
            encoded = base64.b64encode((email + ":" + token).encode()).decode()
            self.authorization = "Basic " + encoded

    def request(self, method, path, body=None, params=None):
        url = self.base + path
        if params:
            url += "?" + urlencode(params)
        request = Request(
            url, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={
                "Authorization": self.authorization,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with build_opener(SameOriginRedirect()).open(request, timeout=60) as response:
                data = response.read()
                return json.loads(data) if data else None
        except HTTPError as exc:
            # Response bodies can contain private ticket data.
            raise WorkflowError("Atlassian {} {}: HTTP {}".format(method, path, exc.code)) from exc
        except URLError as exc:
            raise WorkflowError("Atlassian request failed: {}".format(exc.reason)) from exc

    def board_issues(self, board, jql):
        start = 0
        while True:
            page = self.request("GET", "/rest/agile/1.0/board/{}/issue".format(board), params={
                "jql": jql, "fields": ",".join(FIELDS), "startAt": start, "maxResults": 100,
            })
            issues = page.get("issues", [])
            yield from issues
            start += len(issues)
            if page.get("isLast") or start >= page.get("total", sys.maxsize):
                return
            if not issues:
                raise WorkflowError("Jira pagination stopped before the last page")

    def issue(self, key):
        return self.request("GET", "/rest/api/2/issue/" + key, params={"fields": ",".join(FIELDS)})

    def edit(self, key, fields):
        self.request("PUT", "/rest/api/2/issue/" + key, {"fields": fields})

    def transition(self, key, identifier, fields=None):
        body = {"transition": {"id": identifier}}
        if fields:
            body["fields"] = fields
        self.request("POST", "/rest/api/2/issue/{}/transitions".format(key), body)


class ReleaseTable(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows = []
        self.row = None
        self.cell = None

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.row = []
        elif tag in ("td", "th") and self.row is not None:
            self.cell = []

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.cell is not None:
            self.row.append(" ".join(self.cell))
            self.cell = None
        elif tag == "tr" and self.row is not None:
            self.rows.append(self.row)
            self.row = None


def release_branches(storage):
    heading = re.search(r"Release Branches Overview", storage, re.I)
    if not heading:
        raise WorkflowError("Release Branches Overview is absent from the Confluence page")
    table = re.search(r"<table\b.*?</table>", storage[heading.end():], re.S | re.I)
    if not table:
        raise WorkflowError("Release Branches Overview has no table")
    parser = ReleaseTable()
    parser.feed(table.group())
    branches = set()
    for row in parser.rows:
        text = " ".join(row)
        if re.search(r"\b(?:EXTENDED|ACTIVE|UPCOMING)\b", text):
            branches.update(re.findall(r"\bv\d+\.(\d{4}\.\d+)\b", text))
    if not branches:
        raise WorkflowError("No supported release branches found in the Confluence page")
    return branches


def text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(text(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(text(item) for item in value)
    return ""


def quoted(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def repository(path):
    root = Path(command(["git", "rev-parse", "--show-toplevel"], cwd=path)).resolve()
    remote = command(["git", "remote", "get-url", "origin"], cwd=root)
    match = re.fullmatch(r"(?:git@github\.com:|https://github\.com/)([\w.-]+/[\w.-]+?)(?:\.git)?/?", remote)
    if not match:
        raise WorkflowError("origin must be an SSH or HTTPS github.com repository URL")
    name = match.group(1)
    default = command(["gh", "api", "repos/" + name, "--jq", ".default_branch"])
    return root, name, default


def match_alerts(issue, alerts):
    fields = issue["fields"]
    content = text([fields.get("summary"), fields.get("description")])
    cves = sorted(set(re.findall(r"\bCVE-\d{4}-\d+\b", content, re.I)))
    matches = [
        alert for alert in alerts
        if (alert["security_advisory"].get("cve_id") or "").upper() in {cve.upper() for cve in cves}
    ]
    packages = {alert["dependency"]["package"]["name"] for alert in matches}
    if len(packages) > 1:
        named = {
            package for package in packages
            if re.search(r"(?<![\w@/.-])" + re.escape(package) + r"(?![\w/.-])", content)
        }
        if len(named) == 1:
            matches = [alert for alert in matches if alert["dependency"]["package"]["name"] in named]
        else:
            return cves, [], "Ambiguous package match; inspect ticket and alerts"
    if not cves:
        return [], [], "No CVE ID in ticket summary or description"
    if not matches:
        return cves, [], "No matching open alert; withdrawal not confirmed"
    matched_cves = {(alert["security_advisory"].get("cve_id") or "").upper() for alert in matches}
    if {cve.upper() for cve in cves} - matched_cves:
        return cves, [], "Some CVE IDs have no matching alert; inspect ticket scope"
    return cves, matches, ""


def collect(args):
    if args.state.exists():
        raise WorkflowError("State already exists; choose a new --state path")
    if getattr(args, "checks", None):
        read_checks(args.checks)
    root, repo, default = repository(args.repo)
    if root == args.state.resolve().parent or root in args.state.resolve().parents:
        raise WorkflowError("Keep the state file outside the source repository; it contains private ticket data")
    jira = Atlassian()
    categories = args.status_category or ["To Do"]
    jql = (
        "project = {} AND labels = cve AND labels = {} AND statusCategory in ({})"
    ).format(quoted(args.prefix), quoted("repo-" + repo.split("/")[-1]),
             ", ".join(quoted(category) for category in categories))
    rated = list(jira.board_issues(
        args.board, jql + ' AND "Internal Rating" is not EMPTY ORDER BY key'))
    all_issues = list(jira.board_issues(args.board, jql + " ORDER BY key"))
    pages = command([
        "gh", "api", "--paginate", "--slurp",
        "repos/{}/dependabot/alerts?state=open&per_page=100".format(repo),
    ], json_output=True)
    alerts = [alert for page in pages for alert in page]
    accepted = {default}
    if args.prefix.upper() == "CMS":
        page = Atlassian("CONFLUENCE").request(
            "GET", "/rest/api/content/" + args.release_page, params={"expand": "body.storage"})
        accepted.update(release_branches(page["body"]["storage"]["value"]))
    rated_keys = {issue["key"] for issue in rated}
    state = {
        "schema": 1, "repo_path": str(root), "repository": repo,
        "default_branch": default, "accepted_branches": sorted(accepted),
        "date": dt.date.today().strftime("%y%m%d"),
        "board": args.board, "prefix": args.prefix, "categories": categories,
        "jira_base": jira.base, "groups": {}, "tickets": {},
        "checks": str(args.checks.resolve()) if getattr(args, "checks", None) else "",
    }
    issues_by_key = {issue["key"]: issue for issue in rated}
    issues_by_key.update({issue["key"]: issue for issue in all_issues})
    for issue in issues_by_key.values():
        fields = issue["fields"]
        cves, matches, reason = match_alerts(issue, alerts)
        versions = [version["name"] for version in fields.get("versions", [])]
        status = "ready"
        if (issue["key"] not in rated_keys or not fields.get("customfield_12042")
                or not fields.get("customfield_12043")):
            status, reason = "unrated", "Internal Rating or Rating Statement missing; not touched"
        elif reason:
            status = "skipped" if reason.startswith("No matching") else "decision"
        elif any(not alert["security_vulnerability"].get("first_patched_version") for alert in matches):
            status, reason = "difficult", "No patched version; wait for upstream or replace the package"
        base = versions[0] if len(versions) == 1 else default if not versions else None
        if status in ("ready", "difficult") and (base is None or base not in accepted):
            status, reason = "decision", "Select an affects version and approve unsupported branches"
        state["tickets"][issue["key"]] = {
            "key": issue["key"], "summary": fields["summary"], "cves": cves,
            "affects_versions": versions, "jira_status": fields.get("status"),
            "assignee": fields.get("assignee"),
            "rating_statement": fields.get("customfield_12043"),
            "alerts": [{
                "number": alert["number"],
                "package": alert["dependency"]["package"]["name"],
                "ecosystem": alert["dependency"]["package"]["ecosystem"],
                "manifest": alert["dependency"].get("manifest_path", ""),
                "cve": alert["security_advisory"].get("cve_id"),
                "severity": alert["security_vulnerability"]["severity"],
                "vulnerable_range": alert["security_vulnerability"]["vulnerable_version_range"],
                "patched_version": (alert["security_vulnerability"].get("first_patched_version") or {}).get("identifier"),
            } for alert in matches],
            "status": status, "reason": reason, "base": base,
        }
    save(args.state, state)
    report(state, args.state)


def ticket_for(state, key):
    try:
        return state["tickets"][key]
    except KeyError as exc:
        raise WorkflowError("Unknown ticket: " + key) from exc


def decide(args, state):
    ticket = ticket_for(state, args.ticket)
    if ticket["status"] in ("unrated", "skipped", "resolved", "fixed", "applying"):
        raise WorkflowError("This ticket is read-only; collect a new run to reconsider it")
    if ticket["base"] in state["groups"] and state["groups"][ticket["base"]].get("commit"):
        raise WorkflowError("Group already committed; collect a new run for further changes")
    if args.wont_fix:
        if args.wont_fix not in ticket["affects_versions"]:
            raise WorkflowError("--wont-fix must name an affects version")
        jira = Atlassian()
        existing = jira.issue(args.ticket)["fields"].get("customfield_11680") or []
        names = {version["name"] for version in existing} | {args.wont_fix}
        jira.edit(args.ticket, {"customfield_11680": [{"name": name} for name in sorted(names)]})
        ticket.update(status="skipped", reason="Won't Fix Versions: " + args.wont_fix)
    else:
        base = args.base or ticket.get("base")
        if not base:
            raise WorkflowError("Select --base")
        if base not in (ticket["affects_versions"] or [state["default_branch"]]):
            raise WorkflowError("--base must name an affects version")
        if base not in state["accepted_branches"] and not args.still_do:
            raise WorkflowError("Unsupported branch requires --still-do")
        if ticket.get("work_started") and base != ticket["base"]:
            raise WorkflowError("A ticket cannot change groups after work starts")
        if not ticket["alerts"]:
            raise WorkflowError("Resolve the alert match in Jira and collect a new run")
        ticket.update(
            base=base, allow_minor=args.allow_minor,
            allow_major=args.allow_major, verification_pending=False,
        )
        if all(alert["patched_version"] for alert in ticket["alerts"]):
            ticket.update(status="ready", reason="")
        else:
            ticket.update(status="difficult", reason="No patched version; wait for upstream or replace the package")
    save(args.state, state)
    report(state, args.state)


def skip(args, state):
    ticket = ticket_for(state, args.ticket)
    if ticket["status"] not in SKIPPABLE:
        raise WorkflowError("Only ready, decision, or difficult tickets can be skipped")
    if ticket["base"] in state["groups"] and state["groups"][ticket["base"]].get("commit"):
        raise WorkflowError("Group already committed; collect a new run for further changes")
    ticket.update(status="skipped", reason="Skipped in the report; Jira unchanged")
    save(args.state, state)


def branch_name(state, base):
    # Encode slashes instead of collapsing them into an existing name.
    suffix = quote(base, safe=".-_")
    return "venus/{}-fix-cve-{}".format(state["date"], suffix)


def ensure_group(state, base, state_path):
    command(["git", "check-ref-format", "--branch", base])
    groups = state["groups"]
    if base not in groups:
        root = Path(state["repo_path"])
        branch = branch_name(state, base)
        existing = subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", "refs/heads/" + branch], cwd=root,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if existing.returncode == 0:
            raise WorkflowError("Branch already exists without saved ownership; choose a fresh run")
        if existing.returncode != 1:
            raise WorkflowError("Cannot inspect the local branch")
        digest = hashlib.sha256(base.encode()).hexdigest()[:10]
        path = state_path.resolve().parent / "worktrees" / digest
        groups[base] = {"branch": branch, "path": str(path), "base": base}
        save(state_path, state)
    group = groups[base]
    path = Path(group["path"])
    root = Path(state["repo_path"])
    if group.get("cleaned"):
        raise WorkflowError("This group's worktree was already removed")
    if path.exists():
        actual = command(["git", "rev-parse", "--show-toplevel"], cwd=path)
        branch = command(["git", "branch", "--show-current"], cwd=path)
        if Path(actual).resolve() != path or branch != group["branch"]:
            raise WorkflowError("Worktree path or branch does not match the saved state")
    else:
        command(["git", "worktree", "prune"], cwd=root)
        command(["git", "fetch", "origin", base], cwd=root)
        if not group.get("base_commit"):
            group["base_commit"] = command(["git", "rev-parse", "FETCH_HEAD"], cwd=root)
            save(state_path, state)
        path.parent.mkdir(parents=True, exist_ok=True)
        ref = subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", "refs/heads/" + group["branch"]],
            cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if ref.returncode == 0:
            command(["git", "worktree", "add", path, group["branch"]], cwd=root)
        elif ref.returncode != 1:
            raise WorkflowError("Cannot inspect the local branch")
        else:
            command(["git", "worktree", "add", "-b", group["branch"], path, "FETCH_HEAD"], cwd=root)
        save(state_path, state)
    return group


def workspace_for(path, manifest):
    candidate = (path / manifest).resolve()
    if path not in candidate.parents or not candidate.is_file():
        raise WorkflowError("Alert manifest is absent from this branch: " + manifest)
    candidate = candidate.parent
    while candidate == path or path in candidate.parents:
        if (candidate / "pnpm-workspace.yaml").is_file():
            return candidate
        if candidate == path:
            break
        candidate = candidate.parent
    raise WorkflowError("No pnpm workspace for " + manifest + "; agent repair required")


def manifests(workspace):
    found = {}
    for directory, dirs, files in os.walk(workspace):
        dirs[:] = [name for name in dirs if name not in ("node_modules", ".git", "dist", "build", ".turbo")]
        for name in ("package.json", "pnpm-lock.yaml"):
            if name in files:
                path = Path(directory) / name
                found[path] = path.read_bytes()
    return found


def restore_manifests(workspace, snapshot):
    current = manifests(workspace)
    for path in current.keys() - snapshot.keys():
        path.unlink()
    for path, data in snapshot.items():
        if not path.exists() or path.read_bytes() != data:
            path.write_bytes(data)
    command(["pnpm", "install", "--frozen-lockfile"], cwd=workspace)


def dependency_versions(workspace):
    data = command(["pnpm", "-r", "list", "--depth", "Infinity", "--json"], cwd=workspace, json_output=True)
    result = {}

    def visit(node):
        if not isinstance(node, dict):
            return
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, dependency in node.get(section, {}).items():
                version = dependency.get("version", "")
                match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:$|[-+(])", version)
                if match:
                    result.setdefault(name, set()).add(tuple(map(int, match.groups())))
                visit(dependency)

    for project in data:
        visit(project)
    return result


def upgrade_risk(before, after):
    risk = "patch"
    for name in before.keys() & after.keys():
        for version in after[name] - before[name]:
            same_major = [old for old in before[name] if old[0] == version[0]]
            if not same_major and version[0] > max(before[name])[0]:
                return "major"
            if same_major and version[:2] > min(same_major)[:2]:
                risk = "minor"
    return risk


def audit(workspace):
    data = command([
        "pnpm", "audit", "--json", "--registry=https://registry.npmjs.org/", "--audit-level", "high",
    ], cwd=workspace, json_output=True, allowed=(0, 1))
    if "error" in data or "advisories" not in data:
        raise WorkflowError("pnpm audit failed or returned an unsupported JSON format")
    return data["advisories"]


def findings(advisories, alert):
    return [
        advisory for advisory in advisories.values()
        if advisory.get("module_name") == alert["package"]
        and alert["cve"] in advisory.get("cves", [])
    ]


def dependency_parents(workspace, target):
    data = command(["pnpm", "-r", "why", target, "--json"], cwd=workspace, json_output=True)
    parents = set()
    direct = set()

    def visit(node, parent=None):
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, child in node.get(section, {}).items():
                if name == target:
                    if parent is None:
                        direct.add(node.get("name", "unnamed workspace package"))
                    else:
                        parents.add(parent)
                visit(child, name)

    for project in data:
        visit(project)
    return sorted(parents), sorted(direct)


def repair_alert(workspace, alert, ticket):
    advisories = audit(workspace)
    if not findings(advisories, alert):
        return "Already absent from this branch's audit"
    before = dependency_versions(workspace)
    workspace_names = {
        json.loads(data).get("name") for path, data in manifests(workspace).items()
        if path.name == "package.json"
    }
    queue, visited = [alert["package"]], set()
    while queue:
        target = queue.pop(0)
        if target in visited:
            continue
        visited.add(target)
        if target in workspace_names:
            raise WorkflowError("Workspace package {} needs an agent repair".format(target))
        if not re.fullmatch(r"(?:@[a-z0-9._~-]+/)?[a-z0-9][a-z0-9._~-]*", target):
            raise WorkflowError("Invalid npm package name")
        command(["pnpm", "-r", "up", target], cwd=workspace)
        command(["pnpm", "dedupe"], cwd=workspace)
        risk = upgrade_risk(before, dependency_versions(workspace))
        if risk == "major" and not ticket.get("allow_major"):
            raise ApprovalNeeded("Major upgrade requires --allow-major approval", "major")
        if risk == "minor" and not ticket.get("allow_minor"):
            raise ApprovalNeeded("Minor upgrade requires a changelog review and --allow-minor approval", "minor")
        advisories = audit(workspace)
        if not findings(advisories, alert):
            return "Updated {} and its dependents".format(alert["package"])
        parents, direct = dependency_parents(workspace, target)
        if not parents:
            raise WorkflowError(
                "Pinned/workspace dependency {} still blocks {}; agent repair required".format(
                    ", ".join(direct) or target, alert["package"]))
        queue.extend(parent for parent in parents if parent not in visited)
    raise WorkflowError("Upstream dependency ranges still block the patched version")


def changed_files(path):
    tracked = command(["git", "diff", "--name-only", "HEAD", "-z"], cwd=path)
    untracked = command(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=path)
    return sorted(set(name for name in (tracked + "\0" + untracked).split("\0") if name))


def fingerprint(path):
    digest = hashlib.sha256()
    digest.update(command(["git", "rev-parse", "HEAD"], cwd=path).encode())
    digest.update(command(["git", "diff", "HEAD", "--binary"], cwd=path).encode())
    for name in changed_files(path):
        file = path / name
        digest.update(name.encode())
        if file.is_file():
            digest.update(file.read_bytes())
        elif file.is_symlink():
            digest.update(os.readlink(file).encode())
    return digest.hexdigest()


def checks_for(path, config):
    path = path.resolve()
    selected, covered = [], set()
    changes = changed_files(path)
    for directory, checks in config.items():
        cwd = (path / directory).resolve()
        if cwd != path and path not in cwd.parents:
            raise WorkflowError("Verification directory escapes the worktree")
        matching = [name for name in changes if cwd == path or cwd in (path / name).parents]
        if not matching:
            continue
        for phase in ("build", "lint", "test"):
            args = checks.get(phase)
            if not isinstance(args, list) or not args or not all(isinstance(arg, str) for arg in args):
                raise WorkflowError("Each verification directory needs build, lint, and test argv arrays")
            selected.append((cwd, phase, args))
        covered.update(matching)
    if set(changes) - covered:
        raise WorkflowError("No verification commands cover: " + ", ".join(sorted(set(changes) - covered)))
    if not selected:
        raise WorkflowError("No source changes to verify")
    return selected


def load_checks(args, state):
    if getattr(args, "checks", None):
        config = read_checks(args.checks)
        state["checks"] = str(args.checks.resolve())
        save(args.state, state)
        return config
    if not state.get("checks"):
        raise WorkflowError("No checks file saved; pass --checks or collect with --checks")
    return read_checks(Path(state["checks"]))


def read_checks(file):
    with file.open() as stream:
        config = json.load(stream)
    if not isinstance(config, dict) or not config:
        raise WorkflowError("Verification configuration must be a nonempty directory-to-command map")
    for directory, checks in config.items():
        if not isinstance(directory, str) or not isinstance(checks, dict):
            raise WorkflowError("Invalid verification directory")
        for phase in ("build", "lint", "test"):
            args = checks.get(phase)
            if not isinstance(args, list) or not args or not all(isinstance(arg, str) for arg in args):
                raise WorkflowError("Each verification directory needs build, lint, and test argv arrays")
    return config


def verify_group(state, group, state_path, config):
    path = Path(group["path"])
    if group.get("commit"):
        raise WorkflowError("Group already committed; collect a new run for further changes")
    if any(ticket["base"] == group["base"] and ticket["status"] == "applying"
           for ticket in state["tickets"].values()):
        raise WorkflowError("Interrupted upgrade: inspect the worktree and record its outcome first")
    group.pop("verification", None)
    save(state_path, state)
    candidates = [
        ticket for ticket in state["tickets"].values()
        if ticket["base"] == group["base"] and (
            ticket["status"] in ("changed", "fixed") or ticket.get("verification_pending"))
    ]
    audits = {}
    for ticket in candidates:
        if ticket.get("repair_mode") != "automatic":
            continue
        for alert in ticket["alerts"]:
            workspace = workspace_for(path, alert["manifest"])
            if workspace not in audits:
                audits[workspace] = audit(workspace)
            if findings(audits[workspace], alert):
                ticket.update(status="difficult", reason="Final audit still reports this CVE", verification_pending=False)
                save(state_path, state)
                raise WorkflowError(ticket["key"] + " is still vulnerable; inspect the group")
    checks = checks_for(path, config)
    evidence = []
    for cwd, phase, args in checks:
        print("{}: {} ({})".format(group["base"], phase, cwd.relative_to(path)), flush=True)
        before = fingerprint(path)
        result = subprocess.run(args, cwd=cwd, env=build_environment())
        if result.returncode:
            for ticket in candidates:
                ticket.update(status="failed", verification_pending=True, reason=phase + " failed")
            save(state_path, state)
            raise WorkflowError("{} failed (exit {})".format(phase, result.returncode))
        if fingerprint(path) != before:
            for ticket in candidates:
                ticket.update(status="failed", verification_pending=True, reason=phase + " changed source files")
            save(state_path, state)
            raise WorkflowError(phase + " changed source files; inspect the changes and verify again")
        evidence.append({"cwd": str(cwd.relative_to(path)), "phase": phase, "argv": args})
    group["verification"] = {"fingerprint": fingerprint(path), "commands": evidence}
    for ticket in candidates:
        ticket.update(status="fixed", reason="Build, lint, and tests passed", verification_pending=False)
    save(state_path, state)
    start_progress(state, group, state_path)


def apply(args, state):
    config = load_checks(args, state)
    bases = sorted({ticket["base"] for ticket in state["tickets"].values() if ticket["status"] == "ready"})
    for base in bases:
        group = ensure_group(state, base, args.state)
        if group.get("commit"):
            raise WorkflowError("Group already committed; collect a new run for further changes")
        path = Path(group["path"])
        if any(Path(name).name not in ("package.json", "pnpm-lock.yaml") for name in changed_files(path)):
            raise WorkflowError("Worktree contains code changes; use record and verify for manual repairs")
        if any(ticket["base"] == base and ticket["status"] == "applying"
               for ticket in state["tickets"].values()):
            raise WorkflowError("Interrupted upgrade: inspect the worktree and record its outcome first")
        for directory in config:
            cwd = (path / directory).resolve()
            if cwd != path and path not in cwd.parents:
                raise WorkflowError("Verification directory escapes the worktree")
        for ticket in state["tickets"].values():
            if ticket["base"] != base or ticket["status"] != "ready":
                continue
            ticket["work_started"] = True
            snapshots = {}
            ticket.update(status="applying", repair_mode="automatic", approval=None)
            save(args.state, state)
            try:
                if "upstream" in text(ticket["rating_statement"]).lower():
                    raise WorkflowError("Rating Statement mentions upstream; agent review required")
                if any(alert["ecosystem"] != "npm" for alert in ticket["alerts"]):
                    raise WorkflowError("Automatic repair supports pnpm only; agent repair required")
                for alert in ticket["alerts"]:
                    workspace = workspace_for(path, alert["manifest"])
                    if workspace not in snapshots:
                        command(["pnpm", "install", "--frozen-lockfile"], cwd=workspace)
                        snapshots[workspace] = manifests(workspace)
                summaries = [repair_alert(workspace_for(path, alert["manifest"]), alert, ticket)
                             for alert in ticket["alerts"]]
                if any(Path(name).name not in ("package.json", "pnpm-lock.yaml") for name in changed_files(path)):
                    raise OSError("Dependency commands changed source files; inspect the worktree and record its outcome")
                if all(manifests(workspace) == snapshot for workspace, snapshot in snapshots.items()):
                    ticket.update(status="difficult", reason="No dependency change; inspect branch applicability")
                else:
                    ticket.update(status="changed", reason="; ".join(summaries))
            except WorkflowError as exc:
                try:
                    for workspace, snapshot in snapshots.items():
                        restore_manifests(workspace, snapshot)
                except (WorkflowError, OSError):
                    save(args.state, state)
                    raise
                ticket.update(status="difficult", reason=str(exc), approval=getattr(exc, "level", None))
            save(args.state, state)
        if any(ticket["base"] == base and ticket["status"] == "changed"
               for ticket in state["tickets"].values()):
            verify_group(state, group, args.state, config)
    report(state, args.state)


def record(args, state):
    ticket = ticket_for(state, args.ticket)
    if ticket["status"] in ("unrated", "skipped", "resolved", "decision"):
        raise WorkflowError("Resolve collection decisions before recording work")
    if ticket["base"] in state["groups"] and state["groups"][ticket["base"]].get("commit"):
        raise WorkflowError("Group already committed; collect a new run for further changes")
    if args.status == "changed" and ticket["base"] not in state["groups"]:
        ensure_group(state, ticket["base"], args.state)
    ticket.update(
        status=args.status, reason=args.summary, work_started=True,
        repair_mode="manual", verification_pending=False,
    )
    if ticket["base"] in state["groups"]:
        state["groups"][ticket["base"]].pop("verification", None)
    save(args.state, state)


def prepare(args, state):
    bases = {ticket["base"] for ticket in state["tickets"].values()
             if ticket["base"] and ticket["status"] in ("ready", "difficult", "failed", "changed")}
    if args.base:
        if args.base not in bases:
            raise WorkflowError("No actionable tickets for this base")
        bases = {args.base}
    for base in sorted(bases):
        ensure_group(state, base, args.state)
    report(state, args.state)


def start_progress(state, group, state_path):
    jira = Atlassian()
    myself = jira.request("GET", "/rest/api/2/myself")
    identity = {"accountId": myself["accountId"]} if "accountId" in myself else {"name": myself["name"]}
    for ticket in state["tickets"].values():
        if ticket["base"] != group["base"] or ticket["status"] != "fixed" or ticket.get("in_progress"):
            continue
        live = jira.issue(ticket["key"])["fields"]
        if not live.get("customfield_12042") or not live.get("customfield_12043"):
            raise WorkflowError(ticket["key"] + " lost its required rating fields")
        jira.request("PUT", "/rest/api/2/issue/{}/assignee".format(ticket["key"]), identity)
        category = live["status"].get("statusCategory", {}).get("key")
        if category != "indeterminate":
            jira.transition(ticket["key"], "4")
        ticket["in_progress"] = True
        save(state_path, state)


def verify(args, state):
    config = load_checks(args, state)
    if args.base not in state["groups"]:
        raise WorkflowError("No worktree for this base; run apply or record first")
    group = ensure_group(state, args.base, args.state)
    verify_group(state, group, args.state, config)


def publish(args, state):
    if not args.yes:
        raise WorkflowError("Publication changes GitHub and Jira. Review report, then pass --yes")
    jira = Atlassian()
    for base, group in state["groups"].items():
        fixed = [ticket for ticket in state["tickets"].values()
                 if ticket["base"] == base and ticket["status"] in ("fixed", "resolved", "resolve_failed")]
        if not fixed:
            continue
        if group.get("cleaned"):
            continue
        path = Path(ensure_group(state, base, args.state)["path"])
        if any(ticket["base"] == base and (
            ticket["status"] in ("changed", "applying") or ticket.get("verification_pending"))
               for ticket in state["tickets"].values()):
            raise WorkflowError("Group contains unverified changes")
        start_progress(state, group, args.state)
        verification = group.get("verification")
        if not verification:
            raise WorkflowError("Group has no successful verification")
        if not group.get("commit"):
            # Recover a commit created immediately before an interrupted state write.
            head = command(["git", "rev-parse", "HEAD"], cwd=path)
            if head != group["base_commit"]:
                parent = command(["git", "rev-parse", "HEAD^"], cwd=path)
                tree = command(["git", "rev-parse", "HEAD^{tree}"], cwd=path)
                if parent != group["base_commit"] or tree != group.get("verified_tree"):
                    raise WorkflowError("Unexpected commit in worktree; inspect before publication")
                group["commit"] = head
            else:
                if fingerprint(path) != verification["fingerprint"]:
                    raise WorkflowError("Worktree changed after verification; run verify again")
                if command(["git", "diff", "--name-only", "--diff-filter=U"], cwd=path):
                    raise WorkflowError("Worktree contains merge conflicts")
                files = changed_files(path)
                command(["git", "add", "--"] + files, cwd=path)
                group["verified_tree"] = command(["git", "write-tree"], cwd=path)
                save(args.state, state)
                title = "fix: address CVEs ({})".format(", ".join(ticket["key"] for ticket in fixed))
                message = title + "\n\n" + "\n".join(
                    "{}: {}".format(ticket["key"], ", ".join(ticket["cves"])) for ticket in fixed)
                command(["git", "commit", "-m", message + "\n\n" + TRAILER], cwd=path)
                if command(["git", "rev-parse", "HEAD^{tree}"], cwd=path) != group["verified_tree"]:
                    raise WorkflowError("Commit hook changed the verified tree; inspect before publication")
                group["commit"] = command(["git", "rev-parse", "HEAD"], cwd=path)
            save(args.state, state)
        if command(["git", "status", "--porcelain"], cwd=path):
            raise WorkflowError("Worktree has uncommitted changes")
        if command(["git", "rev-parse", "HEAD"], cwd=path) != group["commit"]:
            raise WorkflowError("HEAD differs from the verified commit")
        command(["git", "push", "--set-upstream", "origin", group["branch"]], cwd=path)
        if not group.get("pr"):
            existing = command([
                "gh", "pr", "list", "--repo", state["repository"], "--head", group["branch"],
                "--base", base, "--state", "all", "--json", "url",
            ], json_output=True)
            if existing:
                group["pr"] = existing[0]["url"]
            else:
                body = "\n".join("- {}: {}".format(ticket["key"], ", ".join(ticket["cves"])) for ticket in fixed)
                group["pr"] = command([
                    "gh", "pr", "create", "--repo", state["repository"], "--base", base,
                    "--head", group["branch"], "--title", "Fix CVEs: " + ", ".join(
                        ticket["key"] for ticket in fixed), "--body", body,
                ], cwd=path)
            save(args.state, state)
        for ticket in fixed:
            if ticket["status"] in ("resolved", "resolve_failed"):
                continue
            key = ticket["key"]
            try:
                live = jira.issue(key)["fields"]
                if live["status"].get("statusCategory", {}).get("key") != "done":
                    jira.transition(key, "5", {"customfield_11580": {"id": "10781"}})
                live = jira.request("GET", "/rest/api/2/issue/" + key, params={
                    "fields": "status,customfield_11580"})["fields"]
                impact = live.get("customfield_11580") or {}
                if live["status"].get("statusCategory", {}).get("key") != "done" or impact.get("id") != "10781":
                    raise WorkflowError("Resolved state or Customer Impact not confirmed")
                ticket["status"] = "resolved"
            except WorkflowError as exc:
                try:
                    jira.transition(key, "301")
                    live = jira.issue(key)["fields"]
                    opened = live["status"].get("statusCategory", {}).get("key") == "new"
                    suffix = "; back in Open" if opened else "; Stop Progress did not return the ticket to Open"
                    ticket.update(status="resolve_failed", reason=str(exc) + suffix)
                except WorkflowError as fallback:
                    ticket.update(status="resolve_failed", reason=str(exc) + "; " + str(fallback))
            save(args.state, state)
    report(state, args.state)


def cleanup(args, state):
    for group in state["groups"].values():
        if group.get("cleaned"):
            continue
        path = Path(group["path"])
        if path.exists():
            if command(["git", "status", "--porcelain"], cwd=path):
                raise WorkflowError("Preserving dirty worktree: " + str(path))
            if group.get("commit"):
                if not group.get("pr"):
                    raise WorkflowError("Preserving unpublished worktree: " + str(path))
                remote = command(["git", "ls-remote", "origin", "refs/heads/" + group["branch"]], cwd=path)
                if remote.split()[0:1] != [group["commit"]]:
                    raise WorkflowError("Remote branch does not contain the saved commit")
            elif command(["git", "rev-parse", "HEAD"], cwd=path) != group.get("base_commit"):
                raise WorkflowError("Preserving worktree with unpublished commits: " + str(path))
            command(["git", "worktree", "remove", path], cwd=state["repo_path"])
        group["cleaned"] = True
        save(args.state, state)


def link(url, label):
    if urlsplit(url).scheme != "https":
        return escape(label)
    return '<a href="{}" target="_blank" rel="noopener">{}</a>'.format(
        escape(url, quote=True), escape(label))


def report_row(state, ticket):
    key, status = ticket["key"], ticket["status"]
    base = ticket.get("base") or ""
    group = state["groups"].get(base, {})
    jira = state.get("jira_base", "")
    key_cell = link(jira + "/browse/" + quote(key), key) if jira else escape(key)
    buttons = []
    if status == "decision":
        options = ticket["affects_versions"] or [state["default_branch"]]
        items = "".join(
            '<option value="{0}"{1}>{0}</option>'.format(
                escape(option, quote=True), " selected" if option == base else "")
            for option in options)
        buttons.append('<select data-role="base">{}</select>'.format(items))
        buttons.append('<button data-action="approve">Approve</button>')
    elif status == "difficult" and base and ticket.get("approval"):
        buttons.append('<button data-action="approve">Approve {} upgrade</button>'.format(
            escape(ticket["approval"])))
    elif status == "difficult" and base:
        buttons.append('<button data-action="approve">Prepare repair</button>')
    if base and status in ("difficult", "failed", "changed") and not ticket.get("approval"):
        buttons.append(
            '<select data-role="record-status"><option selected>changed</option>'
            '<option>difficult</option><option>failed</option></select> '
            '<input data-role="summary" size="24" placeholder="What changed"> '
            '<button data-action="record">Record repair</button>')
    if status in SKIPPABLE:
        buttons.append('<button data-action="skip">Skip</button>')
    reason = ticket.get("reason") or ("Waiting for apply" if status == "ready" else "-")
    cells = [
        key_cell + "<br><small>" + escape(ticket["summary"]) + "</small>",
        escape(", ".join(ticket["cves"]) or "-"),
        escape(", ".join(sorted({alert["package"] for alert in ticket["alerts"]})) or "-"),
        escape(base or "-"),
        escape(FIXABLE.get(status, status)),
        '<span class="badge {0}">{0}</span>'.format(escape(status)),
        escape(reason),
        link(group["pr"], "Pull request") if group.get("pr") else "-",
        '<span class="actions">' + " ".join(buttons) + "</span>",
    ]
    return ('<tr data-key="{}" data-status="{}" data-base="{}" data-approval="{}"><td>{}</td></tr>').format(
        escape(key, quote=True), escape(status, quote=True), escape(base, quote=True),
        escape(ticket.get("approval") or "", quote=True), "</td><td>".join(cells))


def render_report(state, state_path):
    counts = {}
    for ticket in state["tickets"].values():
        counts[ticket["status"]] = counts.get(ticket["status"], 0) + 1
    summary = " · ".join("{}: {}".format(escape(name), count) for name, count in sorted(counts.items()))
    rows = "\n".join(report_row(state, ticket) for ticket in state["tickets"].values())
    config = json.dumps({
        "state": str(state_path), "script": str(Path(__file__).resolve()),
        "accepted": state.get("accepted_branches", []), "checks": state.get("checks", ""),
    }).replace("<", "\\u003c")
    return (REPORT_TEMPLATE.replace("__CONFIG__", config)
            .replace("__SUMMARY__", summary).replace("__ROWS__", rows))


def write_report(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(content)


def report(state, state_path):
    print("Ticket\tBase\tStatus\tDetails")
    for ticket in state["tickets"].values():
        detail = ticket.get("reason", "").replace("\n", " ").replace("\t", " ")
        print("{}\t{}\t{}\t{}".format(ticket["key"], ticket.get("base") or "-", ticket["status"], detail))
    for base, group in state["groups"].items():
        print("{}: {}{}".format(base, group["path"], " " + group["pr"] if group.get("pr") else ""))
    path = state_path.with_suffix(".html")
    write_report(path, render_report(state, state_path))
    print("HTML report: " + str(path))


REPORT_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CVE repair report</title>
<style>
body { font-family: system-ui, sans-serif; margin: 24px; color: #1f2328; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { border-bottom: 1px solid #d0d7de; padding: 8px; text-align: left; vertical-align: top; }
th { background: #f6f8fa; }
.badge { border-radius: 12px; padding: 2px 8px; background: #eaeef2; white-space: nowrap; }
.badge.ready, .badge.fixed, .badge.resolved, .badge.changed { background: #dafbe1; }
.badge.difficult, .badge.failed, .badge.resolve_failed { background: #ffebe9; }
.badge.decision { background: #fff8c5; }
tr.approved { background: #f0fff4; }
tr.skipped { color: #656d76; background: #f6f8fa; }
.actions button, .actions select { margin: 2px; }
pre { background: #f6f8fa; padding: 12px; overflow-x: auto; }
</style>
</head>
<body>
<h1>CVE repair report</h1>
<p>__SUMMARY__</p>
<table>
<thead><tr><th>Ticket</th><th>CVE</th><th>Package</th><th>Base</th><th>Can it be fixed?</th>
<th>Status</th><th>How it got fixed or why not</th><th>PR</th><th>Decision</th></tr></thead>
<tbody>
__ROWS__
</tbody>
</table>
<h2>Next commands</h2>
<p id="open"></p>
<p>Run the blocks in order. Blocks 2 and 3 appear when they apply. Each change regenerates this page's commands.</p>
Checks file: <input id="checks" size="60" placeholder="/absolute/path/to/checks.json">
<button id="copy">Copy commands</button> <button id="clear">Clear selections</button>
<pre id="commands"></pre>
<script>
const CONFIG = __CONFIG__;
const storeKey = "fix-cve:" + CONFIG.state;
let choices = JSON.parse(localStorage.getItem(storeKey) || "{}");
const quote = value => /^[\\w.\\/@:=-]+$/.test(value) ? value : "'" + value.replace(/'/g, "'\\\\''") + "'";
const run = args => args.map(quote).join(" ");
const rows = () => [...document.querySelectorAll("tr[data-key]")];
const python = ["python3", CONFIG.script];
const checksInput = document.getElementById("checks");
checksInput.value = CONFIG.checks;

const checksArgs = () => {
  const value = checksInput.value.trim();
  return value && value !== CONFIG.checks ? ["--checks", value] : [];
};

function pruneStale() {
  for (const row of rows()) {
    const choice = choices[row.dataset.key];
    if (choice && choice.seen !== row.dataset.status) delete choices[row.dataset.key];
  }
}

function commandBlocks() {
  const skips = [], decides = [], prepares = [], records = [], verifies = new Set();
  let open = 0, fixed = 0;
  for (const row of rows()) {
    const key = row.dataset.key, status = row.dataset.status, choice = choices[key];
    if (["fixed", "resolved"].includes(status)) fixed++;
    if (choice && choice.action === "skip") {
      skips.push(run([...python, "skip", CONFIG.state, key]));
      continue;
    }
    if (["decision", "ready", "applying", "changed", "failed"].includes(status)) open++;
    if (!choice) continue;
    const flags = CONFIG.accepted.includes(choice.base) ? [] : ["--still-do"];
    if (choice.action === "approve" && status === "decision") {
      decides.push(run([...python, "decide", CONFIG.state, key, "--base", choice.base, ...flags]));
    } else if (choice.action === "approve" && row.dataset.approval) {
      decides.push(run([...python, "decide", CONFIG.state, key, "--base", choice.base, ...flags,
        "--allow-" + row.dataset.approval]));
    } else if (choice.action === "approve") {
      prepares.push(run([...python, "prepare", CONFIG.state, "--base", choice.base]));
    } else if (choice.action === "record") {
      records.push(run([...python, "record", CONFIG.state, key, "--status", choice.recordStatus,
        "--summary", choice.summary]));
      if (choice.recordStatus === "changed") verifies.add(choice.base);
    }
  }
  const lines = ["# 1. Run now", ...skips, ...decides,
    run([...python, "apply", CONFIG.state, ...checksArgs()]), ...prepares];
  if (records.length || verifies.size) {
    lines.push("", "# 2. After editing the worktrees: record and verify", ...records);
    for (const base of verifies) {
      lines.push(run([...python, "verify", CONFIG.state, "--base", base, ...checksArgs()]));
    }
  }
  if (open === 0 && fixed > 0) {
    lines.push("", "# 3. Publish", run([...python, "publish", CONFIG.state, "--yes"]),
      run([...python, "cleanup", CONFIG.state]), run([...python, "report", CONFIG.state]));
  }
  return { lines, open };
}

function paint() {
  pruneStale();
  localStorage.setItem(storeKey, JSON.stringify(choices));
  for (const row of rows()) {
    const choice = choices[row.dataset.key];
    row.classList.toggle("approved", !!choice && choice.action !== "skip");
    row.classList.toggle("skipped", !!choice && choice.action === "skip");
  }
  const { lines, open } = commandBlocks();
  document.getElementById("open").textContent = open
    ? "Open items: " + open + ". Publish appears when nothing is open."
    : "Nothing open.";
  document.getElementById("commands").textContent = lines.join("\\n");
}

document.querySelector("tbody").addEventListener("click", event => {
  const button = event.target.closest("button");
  if (!button) return;
  const row = button.closest("tr"), key = row.dataset.key, action = button.dataset.action;
  if (choices[key] && choices[key].action === action) {
    delete choices[key];
  } else if (action === "record") {
    const summary = row.querySelector("input[data-role=summary]").value.trim();
    if (!summary) {
      alert("Enter a short summary of the repair.");
      return;
    }
    choices[key] = {
      action, seen: row.dataset.status, base: row.dataset.base, summary,
      recordStatus: row.querySelector("select[data-role=record-status]").value,
    };
  } else {
    const select = row.querySelector("select[data-role=base]");
    choices[key] = { action, seen: row.dataset.status, base: select ? select.value : row.dataset.base };
  }
  paint();
});

checksInput.addEventListener("input", paint);
document.getElementById("clear").addEventListener("click", () => {
  choices = {};
  paint();
});
document.getElementById("copy").addEventListener("click", () =>
  navigator.clipboard.writeText(document.getElementById("commands").textContent));
paint();
</script>
</body>
</html>
"""


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="action", required=True)
    collect_parser = sub.add_parser("collect", help="Read Jira, Confluence, and Dependabot into a new state file")
    collect_parser.add_argument("--repo", type=Path, default=Path.cwd())
    collect_parser.add_argument("--board", type=int, required=True)
    collect_parser.add_argument("--prefix", required=True)
    collect_parser.add_argument("--status-category", action="append")
    collect_parser.add_argument("--release-page", default="40869657")
    collect_parser.add_argument("--state", type=Path, required=True)
    collect_parser.add_argument("--checks", type=Path, help="Verification config; saved in the state file")
    for name in ("decide", "skip", "prepare", "apply", "record", "verify", "publish", "cleanup", "report"):
        child = sub.add_parser(name)
        child.add_argument("state", type=Path)
        if name == "decide":
            child.add_argument("ticket")
            child.add_argument("--base")
            child.add_argument("--wont-fix")
            child.add_argument("--still-do", action="store_true")
            child.add_argument("--allow-minor", action="store_true")
            child.add_argument("--allow-major", action="store_true")
        elif name == "skip":
            child.add_argument("ticket")
        elif name in ("apply", "verify"):
            child.add_argument("--checks", type=Path, help="Verification config; saved once in the state file")
            if name == "verify":
                child.add_argument("--base", required=True)
        elif name == "record":
            child.add_argument("ticket")
            child.add_argument("--status", choices=("changed", "difficult", "failed"), required=True)
            child.add_argument("--summary", required=True)
        elif name == "publish":
            child.add_argument("--yes", action="store_true")
        elif name == "prepare":
            child.add_argument("--base")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        args.state = args.state.resolve()
        args.state.parent.mkdir(parents=True, exist_ok=True)
        with (args.state.parent / (args.state.name + ".lock")).open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise WorkflowError("Another process holds this run's lock") from exc
            if args.action == "collect":
                collect(args)
            else:
                state = load(args.state)
                if args.action == "report":
                    report(state, args.state)
                else:
                    globals()[args.action](args, state)
        return 0
    except (WorkflowError, OSError, ValueError, KeyError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
