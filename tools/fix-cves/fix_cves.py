#!/usr/bin/env python3
"""Report npm/pnpm vulnerabilities and try to fix high and critical findings.

Python standard library, git, the tools named in package.json engines, and (for --push) gh.
CVE lookups require GH_TOKEN, GITHUB_TOKEN, or an authenticated gh.
Use --dryrun for a terminal report without repository or Git changes.
"""

import argparse
import datetime as dt
import itertools
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from html import escape
from urllib.error import HTTPError
from urllib.request import Request, urlopen


REGISTRY = "https://registry.npmjs.org/"
GITHUB_GRAPHQL = "https://api.github.com/graphql"
SEVERE = ("high", "critical")
RISKS = ("patch", "minor", "major")
SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".turbo", ".oci-build", "ai-foundation"}
LOCKFILES = ("pnpm-lock.yaml", "package-lock.json", "npm-shrinkwrap.json")
MANIFESTS = ("package.json", "pnpm-workspace.yaml") + LOCKFILES
PACKAGE_NAME = re.compile(r"(?:@[a-z0-9._~-]+/)?[a-z0-9][a-z0-9._~-]*")
OVERRIDE_NOTE = (
    "Override from `pnpm audit --fix`. It breaks semver. Tell the maintainers, "
    "create a follow-up CMS issue with advisory links to remove the override, and add a release note."
)
EXIT_ENGINE_MISMATCH = 3
log = logging.getLogger("fix-cves")


class Failure(Exception):
    pass


class EngineMismatch(Failure):
    pass


class LogFormatter(logging.Formatter):
    def __init__(self, color=False):
        super().__init__()
        self.color = color

    @staticmethod
    def label(line):
        if line.startswith("$ "):
            return "RUN", "36"
        if line.startswith("UPGRADE "):
            return "FIXED", "32"
        if line.startswith("NOT FIXED "):
            return "BLOCKED", "33"
        if line.startswith(("ERROR", "Workspace repair failed:")):
            return "ERROR", "31"
        if line.startswith("SUMMARY"):
            return "SUMMARY", "35"
        if line.startswith("SOLVED ("):
            return "SOLVED", "32"
        if line.startswith("PERSISTING ("):
            return "OPEN", "31"
        if line.startswith("DEFERRED ("):
            return "DEFERRED", "33"
        if line.startswith("Reports:"):
            return "REPORT", "36"
        if line.startswith(("Last resort", "CVE lookup failed:")):
            return "WARN", "33"
        return "INFO", "2"

    def format(self, record):
        lines = record.getMessage().splitlines() or [""]
        output = []
        for index, line in enumerate(lines):
            label, color = self.label(line)
            timestamp = self.formatTime(record, "%H:%M:%S") if index == 0 else " " * 8
            prefix = "{}  {:<7}  ".format(timestamp, label)
            if self.color:
                timestamp = "\033[2m{}\033[0m".format(timestamp)
                prefix = "{}  \033[{}m{:<7}\033[0m  ".format(timestamp, color, label)
            output.append(prefix + line)
        return "\n".join(output)


def run(args, cwd, allowed=(0,), json_output=False):
    log.info("$ %s    [%s]", " ".join(args), cwd)
    # Dependency scripts and checks do not need GitHub credentials.
    env = None if args[0] in ("git", "gh") else {
        key: value for key, value in os.environ.items() if key not in ("GH_TOKEN", "GITHUB_TOKEN")
    }
    if args[0] == "pnpm":
        env["pnpm_config_verify_deps_before_run"] = "false"
    try:
        result = subprocess.run(
            [str(arg) for arg in args], cwd=cwd, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise Failure("Cannot run {}: {}".format(args[0], exc)) from exc
    if result.returncode not in allowed:
        output = (result.stderr.strip() or result.stdout.strip())[-2000:]
        log.info("  exit %s: %s", result.returncode, output)
        raise Failure("`{}` failed (exit {}): {}".format(" ".join(args[:4]), result.returncode, output))
    if not json_output:
        if result.stdout.strip():
            log.info("%s", result.stdout.strip())
        if result.stderr.strip():
            log.info("%s", result.stderr.strip())
        return result.stdout
    if not result.stdout.strip():
        raise Failure("`{}` returned empty JSON output".format(" ".join(args[:3])))
    try:
        return json.loads(result.stdout)
    except ValueError as exc:
        raise Failure("`{}` did not return JSON".format(" ".join(args[:3]))) from exc


def branch_name(base, today):
    return "venus/fix-cves-{:%y%m%d}-{}".format(today, base.replace("/", "-"))


def pull_latest(repo, expected_branch=None):
    if run(["git", "status", "--porcelain", "--untracked-files=no"], repo).strip():
        raise Failure("The repository has uncommitted changes. Commit or stash them before pulling.")
    current = run(["git", "branch", "--show-current"], repo).strip()
    if not current:
        raise Failure("Detached HEAD: check out a branch before pulling.")
    if expected_branch and expected_branch != current:
        raise Failure("Check out {} before running repairs.".format(expected_branch))
    run(["git", "pull", "--ff-only"], repo)
    return current


def find_workspaces(repo):
    found, workspace_roots = [], []
    for directory, dirs, files in os.walk(repo):
        dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS)
        if "package.json" not in files:
            continue
        path = Path(directory)
        manifest = json.loads((path / "package.json").read_text())
        is_workspace = "pnpm-workspace.yaml" in files or bool(manifest.get("workspaces"))
        is_member = any(path.is_relative_to(root) for root in workspace_roots)
        if is_workspace or any(name in files for name in LOCKFILES) or not is_member:
            found.append(path)
        if is_workspace:
            workspace_roots.append(path)
    return found


def manager(workspace):
    manifest = json.loads((workspace / "package.json").read_text())
    declared = manifest.get("packageManager", "").split("@")[0]
    if declared in ("npm", "pnpm"):
        return declared
    return "pnpm" if (workspace / "pnpm-lock.yaml").exists() or (
        workspace / "pnpm-workspace.yaml").exists() else "npm"


def candidate_workspaces(repo, selected):
    return [(repo / w).resolve() for w in selected] or find_workspaces(repo)


WILDCARDS = ("", "x", "X", "*")
COMPARATOR = re.compile(r"(<=|>=|<|>|=|\^|~)?\s*([0-9A-Za-z.*+-]+)")


def find_projects(repo):
    found = []
    for directory, dirs, files in os.walk(repo):
        dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS)
        if "package.json" not in files:
            continue
        path = Path(directory)
        engines = json.loads((path / "package.json").read_text()).get("engines")
        if engines:
            found.append((path.relative_to(repo) / "package.json", engines))
    return found


def version_parts(text):
    core = re.split(r"[-+]", text.strip().lstrip("v"), maxsplit=1)[0]
    parts = []
    for part in core.split(".")[:3]:
        if part in WILDCARDS:
            break
        if not part.isdigit():
            raise Failure("Cannot read version or range bound: {}".format(text))
        parts.append(int(part))
    return parts


def padded(parts):
    return tuple((parts + [0, 0, 0])[:3])


def bump(parts, index):
    return padded(parts[:index] + [parts[index] + 1])


def comparator_matches(operator, text, installed):
    parts = version_parts(text)
    if not parts:
        return True
    low, partial = padded(parts), len(parts) < 3
    if operator in ("", "="):
        return low <= installed < bump(parts, len(parts) - 1) if partial else installed == low
    if operator == "^":
        index = next((i for i, part in enumerate(parts) if part), len(parts) - 1)
        return low <= installed < bump(parts, index)
    if operator == "~":
        return low <= installed < bump(parts, 0 if len(parts) == 1 else 1)
    if operator == ">=":
        return installed >= low
    if operator == ">":
        return installed >= bump(parts, len(parts) - 1) if partial else installed > low
    if operator == "<":
        return installed < low
    if operator == "<=":
        return installed < bump(parts, len(parts) - 1) if partial else installed <= low
    raise Failure("Unknown operator in engines range: {}".format(operator))


def satisfies(installed_text, requirement):
    if not isinstance(requirement, str):
        raise Failure("Engines range must be a string: {!r}".format(requirement))
    installed = padded(version_parts(installed_text))
    for alternative in requirement.split("||"):
        if re.search(r"\s-\s", alternative):
            low, high = re.split(r"\s+-\s+", alternative.strip(), maxsplit=1)
            pairs = [(">=", low), ("<=", high)]
        else:
            pairs = COMPARATOR.findall(alternative)
        if all(comparator_matches(operator, text, installed) for operator, text in pairs):
            return True
    return False


def require_engines(repo):
    temporary = tempfile.TemporaryDirectory(prefix="fix-cves-corepack-")
    try:
        used = configure_engines(repo, temporary.name)
    except BaseException:
        temporary.cleanup()
        raise
    if used:
        return temporary
    temporary.cleanup()
    return None


def configure_engines(repo, temporary_dir):
    declared = {}
    for project, engines in find_projects(repo):
        for tool, requirement in engines.items():
            declared.setdefault(tool, []).append((project, requirement))

    def matches(tool, version):
        return all(satisfies(version, requirement) for _, requirement in declared[tool])

    if "node" in declared:
        nvm_dir = Path(os.environ.get("NVM_DIR", str(Path.home() / ".nvm")))
        nvm_script = nvm_dir / "nvm.sh"
        if not nvm_script.is_file():
            raise EngineMismatch("NVM not found: {}. Set NVM_DIR to its installation directory.".format(nvm_script))

        def nvm(command, *args, allowed=(0,)):
            try:
                return run(["bash", "-c", '. "$1" --no-use && shift && nvm "$@"',
                            "nvm", str(nvm_script), command, *args], repo, allowed=allowed)
            except Failure as exc:
                raise EngineMismatch("NVM {} failed: {}".format(command, exc)) from exc

        def versions(output):
            return sorted({match.group(1) for line in output.splitlines()
                           if (match := re.match(r"\s*(?:->\s*)?v(\d+\.\d+\.\d+)(?=\s|$)", line))
                           and matches("node", match.group(1))}, key=version_parts, reverse=True)

        installed = versions(nvm("ls", "--no-colors", allowed=(0, 3)))
        if installed:
            version = installed[0]
        else:
            available = versions(nvm("ls-remote", "--no-colors"))
            if not available:
                raise EngineMismatch("No Node.js version satisfies all engine requirements: {}".format(
                    declared["node"]))
            version = available[0]
            nvm("install", version)
        try:
            path = run(["bash", "-c", '. "$1" --no-use && nvm use --silent "$2" && printf "%s" "$PATH"',
                        "nvm", str(nvm_script), version], repo).strip()
        except Failure as exc:
            raise EngineMismatch("NVM could not switch to Node.js {}: {}".format(version, exc)) from exc
        os.environ["PATH"] = path
        try:
            actual = run(["node", "--version"], repo).strip()
        except Failure as exc:
            raise EngineMismatch("Cannot run Node.js after NVM switch: {}".format(exc)) from exc
        if padded(version_parts(actual)) != padded(version_parts(version)):
            raise EngineMismatch("NVM selected Node.js {}, but PATH resolves to {}".format(version, actual))
        log.info("Using Node.js %s", version)

    corepack_enabled = False
    for tool in sorted(declared):
        if tool == "node":
            continue
        installed = None
        if shutil.which(tool):
            try:
                installed = run([tool, "--version"], repo).strip()
            except Failure:
                pass
        compatible = bool(installed and matches(tool, installed))
        if compatible and tool in ("npm", "pnpm", "yarn"):
            for project, requirement in declared[tool]:
                try:
                    project_version = run([tool, "--version"], repo / project.parent).strip()
                    if not satisfies(project_version, requirement):
                        compatible = False
                        break
                except Failure:
                    compatible = False
                    break
        if not compatible and tool in ("npm", "pnpm", "yarn"):
            if shutil.which("corepack") is None:
                raise EngineMismatch("Corepack is not on PATH. Install Corepack to switch {}.".format(tool))
            if not corepack_enabled:
                cache = Path(os.environ.get("COREPACK_HOME") or (
                    Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "node" / "corepack"))
                (cache / "v1").mkdir(parents=True, exist_ok=True)
                home = Path(temporary_dir) / "home"
                home.mkdir()
                (home / "v1").symlink_to(cache / "v1", target_is_directory=True)
                os.environ["COREPACK_HOME"] = str(home)
                os.environ["COREPACK_ENABLE_STRICT"] = "0"
                shim_dir = Path(temporary_dir) / "bin"
                shim_dir.mkdir()
                os.environ["PATH"] = str(shim_dir) + os.pathsep + os.environ["PATH"]
                corepack_enabled = True
            requirement = " || ".join(
                " ".join(parts) for parts in itertools.product(
                    *(value.split("||") for value in dict.fromkeys(
                        value for _, value in declared[tool]))))
            try:
                run(["corepack", "enable", "--install-directory", str(shim_dir), tool], repo)
                run(["corepack", "prepare", "{}@{}".format(tool, requirement), "--activate"], repo)
                installed = run([tool, "--version"], repo).strip()
            except Failure as exc:
                raise EngineMismatch("Corepack could not install or activate {} {}: {}".format(
                    tool, requirement, exc)) from exc
        if installed is None:
            raise EngineMismatch("{} is not on PATH, but {} requires it".format(tool, declared[tool][0][0]))
        for project, requirement in declared[tool]:
            if not satisfies(installed, requirement):
                raise EngineMismatch('Installed {} {} does not satisfy "{}" from {}'.format(
                    tool, installed, requirement, project))
        if not compatible and tool in ("npm", "pnpm", "yarn"):
            for project, requirement in declared[tool]:
                try:
                    project_version = run([tool, "--version"], repo / project.parent).strip()
                except Failure as exc:
                    raise EngineMismatch("Corepack could not activate {} for {}: {}".format(tool, project, exc)) from exc
                if not satisfies(project_version, requirement):
                    raise EngineMismatch('{} {} does not satisfy "{}" from {}'.format(
                        tool, project_version, requirement, project))
    return corepack_enabled


def install(workspace, frozen=True):
    if manager(workspace) == "pnpm":
        run(["pnpm", "install", "--frozen-lockfile" if frozen else "--no-frozen-lockfile"], workspace)
    else:
        run(["npm", "ci" if frozen else "install"], workspace)


def snapshot(workspace):
    found = {}
    for directory, dirs, files in os.walk(workspace):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        for name in MANIFESTS:
            if name in files:
                path = Path(directory) / name
                found[path] = path.read_bytes()
    return found


def restore(workspace, saved):
    for path in snapshot(workspace).keys() - saved.keys():
        path.unlink()
    for path, data in saved.items():
        if not path.exists() or path.read_bytes() != data:
            path.write_bytes(data)
    install(workspace)


def advisory_key(advisory):
    return "{}:{}".format(advisory["id"], advisory["package"])


def audit(workspace, registry):
    data = run(
        [manager(workspace), "audit", "--json", "--registry=" + registry],
        workspace, allowed=(0, 1), json_output=True,
    )
    if not isinstance(data, dict) or not any(key in data for key in ("advisories", "vulnerabilities")):
        raise Failure("Audit returned no vulnerability data: {}".format(str(data)[:300]))
    found = {}
    advisories = list((data.get("advisories") or {}).values())
    npm_lock = {}
    if manager(workspace) == "npm":
        lockfile = next((workspace / name for name in ("npm-shrinkwrap.json", "package-lock.json")
                         if (workspace / name).exists()), None)
        if lockfile:
            npm_lock = json.loads(lockfile.read_text()).get("packages", {})
    for package, vulnerability in (data.get("vulnerabilities") or {}).items():
        for via in vulnerability.get("via", []):
            if not isinstance(via, dict):
                continue  # String entries describe dependents, not separate advisories.
            advisories.append({
                "id": via["source"], "module_name": via.get("name", package),
                "severity": via["severity"], "title": via.get("title", ""),
                "url": via.get("url", ""), "vulnerable_versions": via.get("range", ""),
                "patched_versions": "Fix available (npm audit)" if vulnerability.get("fixAvailable") else "",
                "findings": [{"paths": [path], "version": npm_lock.get(path, {}).get("version", "")}
                             for path in vulnerability.get("nodes", [])],
            })
    for advisory in advisories:
        url = advisory.get("url") or ""
        key = advisory.get("github_advisory_id") or (
            url.rstrip("/").split("/")[-1] if "github.com/advisories/GHSA-" in url else str(advisory.get("id")))
        record = {
            "id": key,
            "package": advisory.get("module_name") or "",
            "severity": advisory.get("severity") or "unknown",
            "title": advisory.get("title") or "",
            "url": url,
            "cves": advisory.get("cves") or [],
            "vulnerable": advisory.get("vulnerable_versions") or "",
            "patched": advisory.get("patched_versions") or "",
            "versions": sorted({f.get("version") or "" for f in advisory.get("findings") or []} - {""}),
            "paths": sorted({p for f in advisory.get("findings") or [] for p in f.get("paths") or []}),
        }
        identity = advisory_key(record)
        if identity in found:
            record["cves"] = record["cves"] or found[identity]["cves"]
            record["versions"] = sorted(set(record["versions"] + found[identity]["versions"]))
            record["paths"] = sorted(set(record["paths"] + found[identity]["paths"]))
        found[identity] = record
    missing = {a["id"] for a in found.values() if not a["cves"]}
    cves = cve_ids(missing)
    for record in found.values():
        if not record["cves"]:
            record["cves"] = cves.get(record["id"], [])
    return found


def cve_ids(advisory_ids, cache={}, state={}):
    """Look up missing CVE IDs in batches and reuse results across audits."""
    missing = sorted(i for i in advisory_ids if i.startswith("GHSA-") and i not in cache)
    if not missing or state.get("disabled"):
        return cache
    if "token" not in state:
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            try:
                result = subprocess.run(
                    ["gh", "auth", "token", "--hostname", "github.com"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10,
                )
                token = result.stdout.strip() if result.returncode == 0 else ""
            except (OSError, subprocess.TimeoutExpired):
                token = ""
        state["token"] = token
    if not state["token"]:
        log.info("CVE lookup skipped: authenticate with gh or set GH_TOKEN or GITHUB_TOKEN.")
        state["disabled"] = True
        return cache
    for start in range(0, len(missing), 50):
        batch = missing[start:start + 50]
        fields = ["a{}: securityAdvisory(ghsaId: {}) {{ cveId }}".format(n, json.dumps(identity))
                  for n, identity in enumerate(batch)]
        payload = json.dumps({"query": "query { " + " ".join(fields) + " }"}).encode()
        request = Request(GITHUB_GRAPHQL, data=payload, headers={
            "Accept": "application/vnd.github+json", "Content-Type": "application/json",
            "Authorization": "Bearer " + state["token"],
        })
        try:
            with urlopen(request, timeout=10) as response:
                result = json.load(response)
            data = result.get("data") or {}
            for n, identity in enumerate(batch):
                alias = "a{}".format(n)
                if alias in data:
                    cve = (data[alias] or {}).get("cveId")
                    cache[identity] = [cve] if cve else []
            if result.get("errors"):
                log.info("CVE lookup failed: %s", result["errors"][0].get("message", "GraphQL error"))
                state["disabled"] = True
                break
        except (OSError, ValueError) as exc:
            log.info("CVE lookup failed: %s", exc)
            if isinstance(exc, HTTPError) and exc.code in (401, 403, 429):
                state["disabled"] = True
            break
    return cache


def has_patch(advisory):
    return advisory["patched"] not in ("", "<0.0.0")


def installed_versions(workspace):
    command = ["pnpm", "-r", "list", "--depth", "Infinity", "--json"] if manager(workspace) == "pnpm" else [
        "npm", "ls", "--all", "--json"]
    data = run(command, workspace, json_output=True)
    result = {}

    def visit(node):
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, dependency in (node.get(section) or {}).items():
                match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:$|[-+(])", dependency.get("version", ""))
                if match:
                    result.setdefault(name, set()).add(tuple(map(int, match.groups())))
                visit(dependency)

    for project in data if isinstance(data, list) else [data]:
        visit(project)
    return result


def upgrade_risk(before, after):
    """Largest semver jump of a newly installed version. In 0.x, a minor jump is breaking."""
    risk = 0
    for name, versions in after.items():
        old_versions = before.get(name, set())
        for version in versions - old_versions:
            nearest = max((old for old in old_versions if old <= version), default=None)
            if nearest is None:
                continue
            if version[0] != nearest[0] or (version[0] == 0 and version[1] != nearest[1]):
                risk = max(risk, 2)
            elif version[1] != nearest[1]:
                risk = max(risk, 1)
    return RISKS[risk]


def version_change(before, after, package):
    def text(versions):
        return ", ".join(".".join(map(str, v)) for v in sorted(versions)) or "none"
    return "{} {} -> {}".format(package, text(before.get(package, ())), text(after.get(package, ())))


def dependents(workspace, spec, target):
    """Return direct dependents of `spec` as (registry packages, workspace projects)."""
    tool = manager(workspace)
    command = ["pnpm", "-r", "why", spec, "--json"] if tool == "pnpm" else ["npm", "explain", spec, "--json"]
    data = run(command, workspace, json_output=True)
    packages, projects = set(), set()

    def visit_tree(node, parent):
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, child in (node.get(section) or {}).items():
                if name == target:
                    (packages if parent else projects).add(parent or node.get("name", "?"))
                visit_tree(child, name)

    for entry in data:
        if "dependents" in entry:  # pnpm 10.x+ prints an inverted tree.
            for dependent in entry["dependents"]:
                if tool == "npm":
                    owner = dependent.get("from", {})
                    if owner.get("name"):
                        (projects if owner.get("isWorkspace") or owner.get("location") == ""
                         else packages).add(owner["name"])
                else:
                    (projects if "depField" in dependent else packages).add(dependent["name"])
        else:
            visit_tree(entry, None)
    return packages, projects


class Repair:
    def __init__(self, workspace, registry, allow_major):
        self.workspace = workspace
        self.registry = registry
        self.allow_major = allow_major
        self.tool = manager(workspace)
        self.npm_workspaces = bool(json.loads((workspace / "package.json").read_text()).get("workspaces"))
        self.projects = {
            json.loads(data).get("name") for path, data in snapshot(workspace).items()
            if path.name == "package.json"
        }

    def remaining(self, ids):
        current = audit(self.workspace, self.registry)
        return {key: value for key, value in current.items() if key in ids}

    def upgrade(self, target, before, steps):
        if not PACKAGE_NAME.fullmatch(target):
            raise Failure("Invalid package name {!r}".format(target))
        command = ["pnpm", "-r", "up", target] if self.tool == "pnpm" else ["npm", "update", target]
        if self.tool == "npm" and self.npm_workspaces:
            command += ["--workspaces", "--include-workspace-root"]
        run(command, self.workspace)
        run([self.tool, "dedupe"], self.workspace)
        steps.append("{} && {} dedupe".format(" ".join(command), self.tool))
        risk = upgrade_risk(before, installed_versions(self.workspace))
        if risk == "major" and not self.allow_major:
            raise Failure("The fix needs a major version jump. Review it, then run again with --allow-major.")
        return risk

    def fix(self, package, advisories):
        """Follow the guide: upgrade the package, then its dependents breadth-first."""
        if not any(has_patch(a) for a in advisories):
            raise Failure("No patched version is available. Check the upstream issues for a fix in progress.")
        ids = {advisory_key(a) for a in advisories}
        before = installed_versions(self.workspace)
        steps = []
        risk = self.upgrade(package, before, steps)
        left = self.remaining(ids)
        queue, tried, blockers = [package], {package}, set()
        while left and queue:
            target = queue.pop(0)
            if target == package:
                specs = sorted({"{}@{}".format(target, v) for a in left.values() for v in a["versions"]})
                if not specs:
                    specs = [target]
            else:
                specs = [target]
            packages, projects = set(), set()
            for spec in specs:
                found, owners = dependents(self.workspace, spec, target)
                packages |= found - self.projects
                projects |= owners | (found & self.projects)
            blockers |= {"{} -> {}".format(p, target) for p in projects}
            for parent in sorted(packages - tried):
                tried.add(parent)
                risk = max(risk, self.upgrade(parent, before, steps), key=RISKS.index)
                left = self.remaining(ids)
                if not left:
                    break
                queue.append(parent)
        problem = ""
        if left:
            problem = ("Workspace packages pin a vulnerable range ({}). Consult an expert.".format(
                ", ".join(sorted(blockers))) if blockers else
                "Version ranges of upstream dependents still require a vulnerable version.")
            if len(left) == len(ids):
                raise Failure(problem)
        after = installed_versions(self.workspace)
        how = "{}. {}".format(version_change(before, after, package), "; ".join(steps))
        if risk == "minor":
            how += ". Minor upgrade: review the changelog."
        if problem:
            how += ". Partial fix: " + problem
        return how


def _fix_workspace(workspace, args, checks, initial):
    registry = args.registry
    if args.audit_only:
        return [dict(a, status="persisting" if a["severity"] in SEVERE else "deferred",
                     detail="Audit only. No changes attempted." if a["severity"] in SEVERE else
                     "Deferred until a normal dependency upgrade.") for a in initial.values()]
    if not any(a["severity"] in SEVERE for a in initial.values()):
        return [dict(a, status="deferred", detail="Deferred until a normal dependency upgrade.")
                for a in initial.values()]
    install(workspace)
    original = snapshot(workspace)
    how, why = {}, {}
    log.info("%s: %d advisories (%d high/critical)", workspace, len(initial),
             sum(a["severity"] in SEVERE for a in initial.values()))
    repair = Repair(workspace, registry, args.allow_major)
    by_package = {}
    for advisory in initial.values():
        if advisory["severity"] in SEVERE:
            by_package.setdefault(advisory["package"], []).append(advisory)
    for package, advisories in sorted(by_package.items()):
        if not repair.remaining({advisory_key(a) for a in advisories}):
            how[package] = "Fixed by an earlier upgrade in this run."
            continue
        saved = snapshot(workspace)
        try:
            how[package] = repair.fix(package, advisories)
            log.info("UPGRADE %s: %s", package, how[package])
        except Failure as exc:
            why[package] = str(exc)
            log.info("NOT FIXED %s: %s", package, exc)
            if snapshot(workspace) != saved:
                restore(workspace, saved)

    severe_ids = {key for key, a in initial.items() if a["severity"] in SEVERE}
    override_failure = None
    if args.allow_override and manager(workspace) == "pnpm" and any(
        has_patch(a) for a in repair.remaining(severe_ids).values()
    ):
        log.info("Last resort: pnpm audit --fix")
        saved = snapshot(workspace)
        try:
            current = audit(workspace, registry)
            eligible = {a["id"] for a in current.values() if a["severity"] in SEVERE and has_patch(a)}
            ignored = {a["id"] for a in current.values()} - eligible
            command = ["pnpm", "audit", "--registry=" + registry, "--audit-level", "high", "--fix"]
            # --audit-level limits printed findings, not the overrides.
            command += ["--ignore=" + identity for identity in sorted(ignored)]
            run(command, workspace, allowed=(0, 1))
            install(workspace, frozen=False)
            left = repair.remaining(severe_ids)
            for package in list(why):
                if not any(a["package"] == package for a in left.values()):
                    how[package] = OVERRIDE_NOTE
                    del why[package]
        except Failure as exc:
            log.info("Override failed: %s", exc)
            override_failure = "Last-resort override failed: {}.".format(exc)
            restore(workspace, saved)

    check_failure = None
    if snapshot(workspace) != original:
        for name, argv in checks.items():
            try:
                run(argv, workspace)
            except Failure as exc:
                check_failure = "Check '{}' failed after the upgrades, so all upgrades in this " \
                                "workspace were reverted ({}).".format(name, exc)
                log.info(check_failure)
                restore(workspace, original)
                break

    final = audit(workspace, registry)
    results = []
    for key, advisory in sorted(initial.items(), key=lambda item: (item[1]["package"], item[0])):
        package = advisory["package"]
        if key not in final:
            results.append(dict(advisory, status="solved",
                                detail=how.get(package, "Fixed by other upgrades in this run.")))
            continue
        if check_failure and package in how:
            detail = check_failure
        elif advisory["severity"] not in SEVERE:
            detail = "Deferred until a normal dependency upgrade."
        else:
            detail = why.get(package, how.get(package, "Still reported after the upgrades of this run."))
            if not args.allow_override and has_patch(advisory) and package in why:
                detail += " Last resort not tried: run again with --allow-override."
            if args.allow_override and manager(workspace) == "npm":
                detail += " npm force-fix is not automatic. Review a manual fix with an expert."
            if override_failure:
                detail += " " + override_failure
        results.append(dict(advisory, status="persisting" if advisory["severity"] in SEVERE else "deferred",
                            detail=detail))
    for key, advisory in sorted(final.items()):
        if key not in initial:
            results.append(dict(advisory, status="persisting" if advisory["severity"] in SEVERE else "deferred",
                                detail="Appeared after the upgrades of this run."))
    if check_failure:
        for result in results:
            result["error"] = check_failure
    return results


def fix_workspace(workspace, args, checks):
    initial = audit(workspace, args.registry)
    saved = snapshot(workspace) if not args.audit_only else None
    try:
        return _fix_workspace(workspace, args, checks, initial)
    except (Failure, OSError, ValueError) as exc:
        detail = "Workspace repair failed: {}.".format(exc)
        if saved is not None and snapshot(workspace) != saved:
            try:
                restore(workspace, saved)
                detail += " Dependency files were restored."
            except (Failure, OSError) as rollback_error:
                detail += " Restore failed: {}. Review dependency files before continuing.".format(rollback_error)
        log.info("ERROR %s: %s", workspace, detail)
        return [dict(a, status="persisting" if a["severity"] in SEVERE else "deferred", detail=detail, error=detail)
                for a in initial.values()]


def load_checks(path, repo):
    if not path:
        return {}
    checks = {}
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise Failure("Checks must map workspace paths to command objects")
    for directory, commands in data.items():
        if not isinstance(commands, dict) or not all(
                   isinstance(argv, list) and argv and all(isinstance(arg, str) for arg in argv)
                   for argv in commands.values()):
            raise Failure("Each check must be a non-empty argument array of strings")
        checks[(repo / directory).resolve()] = commands
    return checks


def default_checks(workspace):
    manifest = json.loads((workspace / "package.json").read_text())
    tool = manager(workspace)
    if tool == "pnpm" and (workspace / "pnpm-workspace.yaml").exists():
        return {name: ["pnpm", "-r", "--if-present", "run", name] for name in ("build", "lint", "test")}
    if tool == "npm" and manifest.get("workspaces"):
        return {name: ["npm", "run", name, "--if-present", "--workspaces", "--include-workspace-root"]
                for name in ("build", "lint", "test")}
    return {name: [tool, "run", name] for name in ("build", "lint", "test")
            if name in manifest.get("scripts", {})}


def summary(results, errors):
    lines = []
    for status in ("solved", "persisting", "deferred"):
        items = [r for r in results if r["status"] == status]
        lines.append("{} ({}):".format(status.upper(), len(items)))
        for r in items:
            lines.append("  [{}] {} {} {} ({}): {}".format(
                r["severity"], r["workspace"], r["package"], r["id"],
                ", ".join(r["cves"]) or "no CVE id", r["detail"]))
            lines.append("    Vulnerable: {}. Patched: {}. Versions: {}".format(
                r["vulnerable"], r["patched"] or "none reported", ", ".join(r["versions"]) or "not reported"))
            lines.append(textwrap.fill("Paths: " + (", ".join(r["paths"]) or "not reported"), width=120,
                                       initial_indent="    ", subsequent_indent="      "))
    lines.extend("ERROR: " + error for error in errors)
    return "\n".join(lines)


def render_html(meta, results, errors):
    def row(r):
        advisory = '<a href="{}">{}</a>'.format(escape(r["url"]), escape(r["id"])) if r["url"] else escape(r["id"])
        paths = r["paths"]
        details = (
            '<details><summary>Dependency details ({} paths)</summary>'
            '<dl><dt>Workspace</dt><dd>{}</dd><dt>Installed versions</dt><dd><code>{}</code></dd>'
            '<dt>Vulnerable</dt><dd><code>{}</code></dd><dt>Patched</dt><dd><code>{}</code></dd></dl>'
            '<ul class="paths">{}</ul></details>'
        ).format(len(paths), escape(r["workspace"]), escape(", ".join(r["versions"]) or "not reported"),
                 escape(r["vulnerable"] or "not reported"), escape(r["patched"] or "none reported"),
                 "".join("<li><code>{}</code></li>".format(escape(path)) for path in paths))
        cells = [
            escape(r["severity"]), "<code>{}</code>".format(escape(r["package"])),
            "{}<br><small>{}</small>".format(advisory, escape(" ".join(r["cves"] + [r["title"]]))),
            escape(r["detail"]) + details,
        ]
        return "<tr class='{}'>{}</tr>".format(
            escape(r["severity"]), "".join("<td>{}</td>".format(cell) for cell in cells))

    def table(status, heading, column):
        items = [r for r in results if r["status"] == status]
        if not items:
            return "<h2>{} (0)</h2>".format(heading)
        return ("<h2>{} ({})</h2><div class='table-scroll'><table><thead><tr><th>Severity</th><th>Package</th>"
                "<th>Advisory</th><th>{}</th></tr></thead><tbody>{}</tbody></table></div>").format(
                    heading, len(items), column, "".join(row(r) for r in items))

    facts = "".join("<dt>{}</dt><dd>{}</dd>".format(escape(key), value) for key, value in meta)
    error_html = "<h2 class='err'>Errors</h2><ul class='err'>{}</ul>".format(
        "".join("<li>{}</li>".format(escape(e)) for e in errors)) if errors else ""
    return """<!doctype html><html><head><meta charset="utf-8"><title>CVE fix report</title><style>
body{{font:14px system-ui,sans-serif;margin:2em;color:#222}} table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ccc;padding:6px;text-align:left;vertical-align:top;overflow-wrap:anywhere}} th{{background:#f3f3f3}}
.table-scroll{{overflow-x:auto}} td:first-child{{width:6em}} td:nth-child(2){{width:17%}}
td:nth-child(3){{width:30%}} tbody tr:nth-child(even){{background:#fafafa}}
details{{margin-top:10px}} summary{{cursor:pointer;color:#245a91;font-weight:600}}
.paths{{max-height:22em;overflow:auto;padding-left:20px}} .paths li{{margin:6px 0}}
tr.critical td:first-child{{background:#b00020;color:#fff}} tr.high td:first-child{{background:#e65100;color:#fff}}
dl{{display:grid;grid-template-columns:max-content auto;gap:4px 16px}} dt{{font-weight:bold}} .err{{color:#b00020}}
</style></head><body><h1>CVE fix report</h1><dl>{}</dl>{}{}{}{}</body></html>
""".format(facts, table("solved", "Solved", "How"), table("persisting", "Still open", "Why not fixed"),
           table("deferred", "Deferred (moderate/low)", "Reason"), error_html)


def publish(repo, base, branch, results, push):
    changed = [
        line[3:].strip('"') for line in run(["git", "status", "--porcelain"], repo).splitlines()
        if Path(line[3:].strip('"')).name in MANIFESTS
    ]
    if not changed:
        log.info("No dependency files changed, so no branch was created.")
        return None, None
    solved = [r for r in results if r["status"] == "solved"]
    run(["git", "checkout", "-b", branch], repo)
    run(["git", "add", "--"] + changed, repo)
    message = "fix: upgrade dependencies for high/critical advisories\n\n" + "\n".join(
        "- {} {} ({})".format(r["package"], r["id"], ", ".join(r["cves"]) or r["severity"]) for r in solved)
    message += "\n\nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
    run(["git", "commit", "-m", message], repo)
    if not push:
        return branch, None
    run(["git", "push", "-u", "origin", branch], repo)
    templates = [repo / ".github/pull_request_template.md", repo / ".github/PULL_REQUEST_TEMPLATE.md"]
    templates += sorted((repo / ".github/PULL_REQUEST_TEMPLATE").glob("*.md"))
    template = next((path.read_text() for path in templates if path.is_file()), "autoclose none\n")
    template = template.replace("autoclose LOOP-xxxx", "autoclose none")
    if not re.search(r"^autoclose (?:none|LOOP-\d+)", template, re.MULTILINE):
        template = "autoclose none\n\n" + template
    body = template + "\n\nAutomated by fix_cves.py.\n\n```\n{}\n```\n".format(summary(results, []))
    pr = run(["gh", "pr", "create", "--base", base, "--head", branch,
              "--title", "fix: high/critical CVEs ({})".format(branch), "--body", body], repo).strip()
    return branch, pr


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", default=".", help="Git repository (default: current directory)")
    parser.add_argument("--base", help="Base branch name (default: current branch; required on a detached HEAD)")
    parser.add_argument("--workspace", action="append", default=[],
                        help="npm/pnpm root relative to the repository (repeatable; default: discover roots)")
    parser.add_argument("--dryrun", "--audit-only", dest="audit_only", action="store_true",
                        help="Audit only. No pull, repository dependency changes, or report files")
    parser.add_argument("--commit", action="store_true", help="Create a fix branch and commit dependency changes")
    parser.add_argument("--checks", help='Override automatic build/lint/test commands. JSON: '
                        '{"<workspace>": {"<name>": ["argv", ...]}}')
    parser.add_argument("--out", default="cache/fix-cves-report",
                        help="Report directory (default: ./cache/fix-cves-report)")
    parser.add_argument("--registry", default=REGISTRY)
    parser.add_argument("--allow-major", action="store_true", help="Permit major upgrades (explicit approval)")
    parser.add_argument("--allow-override", action="store_true",
                        help="Last resort: permit `pnpm audit --fix` overrides (explicit approval)")
    parser.add_argument("--push", action="store_true", help="Push the branch and create a PR with gh")
    args = parser.parse_args(argv)
    if args.audit_only and (args.commit or args.push):
        parser.error("--dryrun cannot be combined with --commit or --push")

    out = Path(args.out).resolve()
    if not args.audit_only:
        out.mkdir(parents=True, exist_ok=True)
    log.setLevel(logging.INFO)
    console = logging.StreamHandler(sys.stdout)
    color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    console.setFormatter(LogFormatter(color=color))
    handlers = [console]
    if not args.audit_only:
        report_log = logging.FileHandler(out / "report.log", mode="w")
        report_log.setFormatter(LogFormatter())
        handlers.append(report_log)
    for handler in handlers:
        log.addHandler(handler)

    repo, base = Path(args.repo).resolve(), args.base or "?"
    results, errors, fix_branch, pr = [], [], None, None
    engine_mismatch, engine_tools = False, None
    engine_env = {key: os.environ.get(key) for key in ("PATH", "COREPACK_HOME", "COREPACK_ENABLE_STRICT")}
    try:
        repo = Path(run(["git", "rev-parse", "--show-toplevel"], repo).strip())
        engine_tools = require_engines(repo)
        if not args.audit_only:
            untracked = run(["git", "ls-files", "--others", "--exclude-standard", "-z"], repo).split("\0")
            if any(Path(path).name in MANIFESTS for path in untracked if path):
                raise Failure("The repository has untracked dependency files. Track them before running repairs.")
        current = (run(["git", "branch", "--show-current"], repo).strip() if args.audit_only else
                   pull_latest(repo, args.base))
        base = args.base or current
        branch = branch_name(base, dt.date.today())
        if (args.commit or args.push) and run(["git", "branch", "--list", branch], repo).strip():
            raise Failure("Branch {} already exists".format(branch))
        checks = load_checks(args.checks, repo)
        workspaces = candidate_workspaces(repo, args.workspace)
        if not workspaces:
            raise Failure("No npm/pnpm workspace found")
        for workspace in workspaces:
            if not workspace.is_relative_to(repo):
                raise Failure("Workspace must be inside the repository: {}".format(workspace))
            name = str(workspace.relative_to(repo))
            saved = snapshot(workspace) if not args.audit_only else None
            try:
                commands = checks[workspace] if workspace in checks else default_checks(workspace)
                workspace_results = fix_workspace(workspace, args, commands)
                results.extend(dict(r, workspace=name) for r in workspace_results)
                errors.extend("{}: {}".format(name, message)
                              for message in sorted({r["error"] for r in workspace_results if r.get("error")}))
            except (Failure, OSError, ValueError) as exc:
                errors.append("{}: {}".format(name, exc))
                log.info("ERROR %s: %s", name, exc)
                if saved is not None and snapshot(workspace) != saved:
                    try:
                        restore(workspace, saved)
                    except Failure as rollback_error:
                        errors.append("{}: Restore failed: {}".format(name, rollback_error))
        if not args.audit_only and not errors and (args.commit or args.push):
            fix_branch, pr = publish(repo, base, branch, results, args.push)
    except (Failure, OSError, ValueError) as exc:
        errors.append(str(exc))
        engine_mismatch = isinstance(exc, EngineMismatch)
        log.info("ERROR %s", exc)

    meta = [
        ("Repository", escape(str(repo))), ("Base branch", escape(base)),
        ("Fix branch", escape(fix_branch or "none")),
        ("Pull request", '<a href="{0}">{0}</a>'.format(escape(pr)) if pr else "none"),
        ("Date", escape(dt.datetime.now().isoformat(timespec="seconds"))),
        ("Options", escape(" ".join(sys.argv[1:] if argv is None else argv) or "defaults")),
    ]
    log.info("SUMMARY\n%s", summary(results, errors))
    if not args.audit_only:
        (out / "report.html").write_text(render_html(meta, results, errors))
        log.info("Reports: %s, %s", out / "report.log", out / "report.html")
    for handler in handlers:
        log.removeHandler(handler)
        handler.close()
    if engine_tools:
        engine_tools.cleanup()
    for key, value in engine_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    if errors:
        return EXIT_ENGINE_MISMATCH if engine_mismatch else 2
    return 1 if any(r["status"] == "persisting" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
