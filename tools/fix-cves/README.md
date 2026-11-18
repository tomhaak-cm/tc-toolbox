# Fix CVEs

`fix_cves.mjs` repairs high and critical audit findings in pnpm and npm workspaces of a Git repository.
It runs locally and in CI.
It needs Node.js 18 or later, Git, NVM, Corepack, and registry access.
The script scans the repository for `package.json` files with an `engines` field.
It selects a Node.js version that satisfies all declared ranges with NVM.
It uses Corepack to select compatible npm, pnpm, or Yarn versions when necessary.
If a version is missing, NVM or Corepack installs it.
The selected versions apply only to the script and its subprocesses.
If the selection or installation fails, the script shows an error and exits with code `3`.
`--push` also needs an authenticated `gh` CLI.
The script uses only Node.js built-in modules.

## Procedure

The script follows the team procedure for each pnpm or npm workspace:

1. Run `pnpm install --frozen-lockfile` (npm: `npm ci`).
   If the pnpm lockfile formats differ, the script first removes `node_modules` from the workspace root and its member packages.
2. Run `pnpm audit --registry=https://registry.npmjs.org/ --audit-level high` (npm: `npm audit`).
   Keep only high and critical advisories.
3. For each vulnerable package:
   1. If the advisory has no patched version, stop. Report "no patched version".
   2. Run `pnpm -r up <package>` and `pnpm dedupe`, then audit again (npm: `npm update` and `npm dedupe`).
   3. If the advisory remains, find the direct dependents with `pnpm -r why <package>@<version>` (npm: `npm explain`).
      Upgrade each dependent with `pnpm -r up` and `pnpm dedupe`, breadth-first.
      If a dependent does not solve the advisory, continue with the dependents of that dependent.
   4. If a workspace package pins the vulnerable range, stop. Report the package that pins it.
   5. If an upgrade causes a major version jump, stop. Report it.
   6. After a failure, restore the manifest and lockfile snapshots of the workspace, then reinstall.
4. Last resort, only with `--allow-override`: run `pnpm audit --registry=https://registry.npmjs.org/ --audit-level high --fix`.
5. Run the verification checks for each workspace that the script upgraded.
   If a check fails, revert all upgrades in that workspace.
6. Audit again and compare the result with the first audit.

With `--commit` or `--push`, and only when dependency files changed, the script creates the branch `venus/fix-cves-YYMMDD-<BASE>` and commits these files.
A `/` in the base name becomes `-`.
With `--push`, the script also pushes the branch and creates a PR against the base branch.
The PR uses the repository's pull request template when one exists, and appends the run summary.

## Usage

Check out the base branch first.
If tracked files have uncommitted changes, the script offers four options: discard, stash and pull, skip the pull, or exit.
The discard option deletes untracked files only if they block the pull.
In non-interactive runs, the script exits if tracked files have uncommitted changes.
For `--commit` or `--push`, dependency files must not have uncommitted changes, and no files can be staged.
Without `--commit` or `--push`, the script changes dependency files in the working tree and commits nothing.

```sh
node tools/fix-cves/fix_cves.mjs --repo /path/to/cms --out /tmp/fix-cves-report --commit
```

| Option | Purpose |
|---|---|
| `--repo DIR` | Git repository. Default: current directory |
| `--base NAME` | Base branch name. Default: current branch. The run pulls the branch, so it needs a checked-out branch |
| `--workspace DIR` | Workspace relative to the repository, for example `apps/studio-client`. Repeatable. Default: discovered npm and pnpm workspace roots |
| `--dryrun`, `--audit-only` | Audit only. No pull, repository dependency changes, or report files. Can install engine versions. Cannot combine with `--commit` or `--push` |
| `--commit` | Create the fix branch and commit dependency changes |
| `--checks FILE` | Replace the automatic build, lint, and test commands, see below |
| `--out DIR` | Report directory. Default: `./fix-cves-report` |
| `--registry URL` | Audit registry. Default: `https://registry.npmjs.org/` |
| `--allow-major` | Permit major upgrades. Use only after explicit approval |
| `--allow-override` | Permit the `pnpm audit --fix` override. Use only after explicit approval |
| `--push` | Commit if needed, push the branch, and create a PR with `gh`. Implies `--commit` |

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

Without `--checks`, the script uses the `build`, `lint`, and `test` scripts that each workspace defines.
For pnpm and npm workspace roots, it runs them across all packages with `--if-present`.
The script runs the checks in each workspace directory after its upgrades.

## Reports

Unless `--dryrun` is set, the script writes two files in the `--out` directory:

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
| `3` | The script could not select or install compatible engine versions |

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
    node tools/fix-cves/fix_cves.mjs --base "$BASE_BRANCH" --out fix-cves-report --push
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
node --test tests/fix_cves.test.mjs
```
