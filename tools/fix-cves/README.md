# Fix CVEs

`fix_cves.py` repairs high and critical `pnpm audit` findings in a Git repository.
It runs locally and in CI.
It needs Python 3.9 or later, Git, pnpm, and registry access.
`--push` also needs an authenticated `gh` CLI.
The script uses only the Python standard library.

## Procedure

The script follows the team procedure for each pnpm workspace:

1. Run `pnpm install --frozen-lockfile`.
2. Run `pnpm audit --registry=https://registry.npmjs.org/ --audit-level high`.
   Keep only high and critical advisories.
3. For each vulnerable package:
   1. If the advisory has no patched version, stop. Report "no patched version".
   2. Run `pnpm -r up <package>` and `pnpm dedupe`, then audit again.
   3. If the advisory remains, find the direct dependents with `pnpm -r why <package>@<version>`.
      Upgrade each dependent with `pnpm -r up` and `pnpm dedupe`, breadth-first.
      If a dependent does not solve the advisory, continue with the dependents of that dependent.
   4. If a workspace package pins the vulnerable range, stop. Report the package that pins it.
   5. If an upgrade causes a major version jump, stop. Report it.
   6. After a failure, restore `package.json`, `pnpm-lock.yaml`, and `pnpm-workspace.yaml`, then reinstall.
4. Last resort, only with `--allow-override`: run `pnpm audit --registry=https://registry.npmjs.org/ --audit-level high --fix`.
5. Run the verification checks for the workspace.
   If a check fails, revert all upgrades in that workspace.
6. Audit again and compare the result with the first audit.

If dependency files changed, the script creates the branch `venus/fix-cves-YYMMDD-<BASE>` and commits these files.
A `/` in the base name becomes `-`.
With `--push`, the script pushes the branch and creates a PR against the base branch.

## Usage

Check out and update the base branch first.
The repository must have no uncommitted changes to tracked files.

```sh
python3 tools/fix-cves/fix_cves.py --repo /path/to/cms --out /tmp/fix-cves-report
```

| Option | Purpose |
|---|---|
| `--repo DIR` | Git repository. Default: current directory |
| `--base NAME` | Base branch name. Default: current branch. Required on a detached HEAD |
| `--workspace DIR` | Workspace relative to the repository, for example `apps/studio-client`. Repeatable. Default: each directory with a `pnpm-lock.yaml` |
| `--checks FILE` | Verification commands, see below |
| `--out DIR` | Report directory. Default: `./fix-cves-report` |
| `--registry URL` | Audit registry. Default: `https://registry.npmjs.org/` |
| `--allow-major` | Permit major upgrades. Use only after explicit approval |
| `--allow-override` | Permit the `pnpm audit --fix` override. Use only after explicit approval |
| `--push` | Push the branch and create a PR with `gh` |

Minor upgrades are permitted.
The report marks them for a changelog review.
In `0.x` versions, a minor jump counts as major.

### Verification checks

The checks file maps a workspace directory to named commands.
Each command is an argument array, not a shell string.

```json
{
  "apps/studio-client": {
    "build": ["pnpm", "run", "build"],
    "test": ["pnpm", "run", "test"]
  }
}
```

The script runs the checks in the workspace directory, only when that workspace changed.

## Reports

The script writes two files in the `--out` directory:

- `report.log`: all commands, results, and a summary.
- `report.html`: solved advisories and how the script solved them, and open advisories and why the script could not solve them.

pnpm 10 and later omit CVE IDs from the audit JSON.
The script then gets each CVE ID from the GitHub advisory API.
If `GH_TOKEN` or `GITHUB_TOKEN` is set, the script uses it for that request.
A failed lookup does not stop the run.

| Exit code | Meaning |
|---|---|
| `0` | No high or critical advisory remains |
| `1` | At least one high or critical advisory remains |
| `2` | An error occurred, for example a failed install or audit |

## Overrides

An override breaks semver.
A dependent built for `^1.0.0` can get `3.2.1`, and the tests of third-party packages do not run against it.
After you merge an override:

- Make sure that the package maintainers know about the issue.
- Create a follow-up CMS ticket to remove the override, with links to the upstream issues.
- Write a release note that warns customers about possible conflicts.

## CI example

```yaml
- run: |
    git config user.name "ci-bot"
    git config user.email "ci-bot@example.com"
    python3 tools/fix-cves/fix_cves.py --base "$BASE_BRANCH" --out fix-cves-report --push
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: fix-cves-report
    path: fix-cves-report
```

The script removes `GH_TOKEN` and `GITHUB_TOKEN` from the environment of pnpm and check commands.
Other variables, for example registry credentials, stay available.
Run the script only in repositories that you trust.

## Development

```sh
python3 -m unittest tests/test_fix_cves.py -v
```
