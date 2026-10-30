# Fix CVE

The script requires Python 3.9 or later, Git, and an authenticated `gh` CLI.
Automatic dependency repair also requires the repository's pnpm version and registry access.
The script supports macOS and Linux.
It uses only the Python standard library.

The script handles ticket collection, branch groups, worktrees, pnpm upgrades, verification, Jira updates, commits, pushes, and PRs.
The agent handles changelog reviews, ambiguous matches, non-pnpm dependencies, code changes, and dependency overrides.
The script never creates an override automatically.

### Credentials

Set these variables in the shell that runs the script:

| Variable | Purpose |
|---|---|
| `JIRA_BASE_URL` | Jira base URL, including a context path when necessary |
| `JIRA_TOKEN` | Jira API token or personal access token |
| `JIRA_EMAIL` | Optional. Selects Basic authentication with `email:token`. Without it, the script uses Bearer authentication |
| `CONFLUENCE_BASE_URL` | Confluence base URL. Required for CMS. Include `/wiki` for Confluence Cloud |
| `CONFLUENCE_TOKEN` | Optional. Defaults to `JIRA_TOKEN` |
| `CONFLUENCE_EMAIL` | Optional. Defaults to `JIRA_EMAIL` |

Keep credentials outside this repository.
The script never saves credentials to the run file.
It removes Jira, Confluence, and GitHub token variables from the environment of dependency commands and verification commands.
These commands still inherit other variables, including registry credentials.
Run dependency commands only in repositories that you trust.

The script uses Jira Agile board pagination and Jira REST API v2.
Confluence supplies storage-format HTML through its content API.
Your account must have access to the board, release page, and required fields.
GitHub access must include Dependabot alerts and permission to create PRs.
Authentication and permissions must work before the script can collect a run.

### Collect

In the examples, `SCRIPT` names this script's absolute path:

```sh
SCRIPT=/absolute/path/to/tc-skills/skills/fix-cve/scripts/fix_cve.py
STATE="$HOME/.local/state/tc/cms-cve-20261029/run.json"

python3 "$SCRIPT" collect \
  --repo /absolute/path/to/cms \
  --board 109 --prefix CMS \
  --status-category "To Do" \
  --state "$STATE"
```

Use a separate state directory for each run.
Keep it outside the repository that you repair.
The run file contains private ticket data.
The script writes it with owner-only permissions and prevents concurrent commands for the same run.
Collection reads remote data but makes no remote changes.

Collection reads every Jira and Dependabot page.
Tickets without either rating field remain `unrated`.
A ticket without a matching open alert becomes `skipped`, not withdrawn.
The script requires a clear CVE and package match.
It retains every matching manifest and its patched version.

For CMS, the script reads the first table after `Release Branches Overview` on page `40869657`.
It accepts EXTENDED, ACTIVE, and UPCOMING release rows.
`--release-page` selects a different page.
Other projects accept only their default branch automatically.

### Decide

Resolve each version decision before repair:

```sh
python3 "$SCRIPT" decide "$STATE" CMS-12345 --base 2406.4
python3 "$SCRIPT" decide "$STATE" CMS-12346 --base 2406.1 --still-do
python3 "$SCRIPT" decide "$STATE" CMS-12347 --wont-fix 2406.1
```

`--wont-fix` updates Jira immediately.
It preserves existing Won't Fix Versions.
Then it skips the ticket.
Ambiguous alert matches require a correction in Jira and a new collection.
Unrated and skipped tickets remain read-only in the current run.

### Define verification commands

Create a JSON file outside Git.
Use the build, lint, and unit-test commands from the target repository's documentation.
Each key names a directory relative to the worktree.
Each command is an argument array, not a shell string.

For a workspace that supplies these package scripts, the file can contain:

```json
{
  "apps/studio-client": {
    "build": ["pnpm", "run", "build"],
    "lint": ["pnpm", "run", "lint"],
    "test": ["pnpm", "run", "test"]
  }
}
```

These example commands are not a CMS command reference.
Select commands that cover every touched package, including dependencies affected by lockfile changes.
Use `"."` for commands that operate on the whole repository.
Each changed file must fall under a configured directory.
The script requires all three phases and rejects commands that change source files.
The directory check proves file coverage, not test quality or package coverage.

### Apply

```sh
python3 "$SCRIPT" apply "$STATE" --checks /absolute/path/to/checks.json
```

The script creates an isolated worktree for each ready group.
It creates branches with the pattern `venus/<YYMMDD>-fix-cve-<BASEBRANCH>`.
It encodes slashes in base names to prevent name collisions.
The original checkout remains unchanged.
Existing local branches with the same name block a new run.

For npm alerts in pnpm workspaces, the script:

1. Installs the locked dependencies.
2. Reads the audit.
3. Upgrades the package within existing ranges.
4. Deduplicates the lockfile.
5. Examines the audit and dependency graph.
6. Tries upstream dependents when a vulnerable version remains.
7. Runs the configured build, lint, and tests.
8. Assigns verified tickets to the authenticated Jira user and starts progress.

The script classifies unsupported repairs as `hard`.
It restores the manifest and lockfile snapshots after a rejected upgrade.
Then it restores installed dependencies from the lockfile.
It preserves earlier fixes in that worktree.
It stops for inspection after an interrupted upgrade or a change outside dependency files.

After a changelog review, approve a minor upgrade:

```sh
python3 "$SCRIPT" decide "$STATE" CMS-12345 --allow-minor
python3 "$SCRIPT" apply "$STATE" --checks /absolute/path/to/checks.json
```

After an explicit user decision, `--allow-major` permits an automatic major upgrade attempt.
Approval does not permit code changes or overrides.
The agent handles those repairs manually.
Moderate-or-lower findings get only easy fixes.
The agent reports harder repairs for these findings with the option to defer them.

### Handle hard repairs

Show the report and ask which hard repairs to implement.
Create a worktree for a hard group when necessary:

```sh
python3 "$SCRIPT" report "$STATE"
python3 "$SCRIPT" prepare "$STATE" --base 2406.4
```

Read the worktree's repository instructions before you change code.
For pnpm repairs, read [PNPM.md](PNPM.md).
After an approved manual repair, record the change and run verification:

```sh
python3 "$SCRIPT" record "$STATE" CMS-12345 \
  --status changed --summary "Updated the pinned dependency"
python3 "$SCRIPT" verify "$STATE" --base 2406.4 \
  --checks /absolute/path/to/checks.json
```

`record` also accepts `hard` and `failed`.
Only successful verification marks a ticket `fixed`.
A failed build, lint, or test phase leaves the changes available for repair.
After a repair, run `verify` again.
After an interruption, inspect and restore or finish the affected upgrade before you record its outcome.
The script preserves the `applying` status until that inspection.

If a repair uses an override, the agent must obtain explicit approval.
The agent must also track its removal and add the required customer release notes.
[PNPM.md](PNPM.md) defines these requirements.

### Publish and clean

After the user accepts the report and selects no more hard repairs, publish:

```sh
python3 "$SCRIPT" publish "$STATE" --yes
python3 "$SCRIPT" cleanup "$STATE"
python3 "$SCRIPT" report "$STATE"
```

Publication requires the exact worktree contents from successful verification.
It commits with a Copilot co-author trailer, pushes the branch, and creates one PR per changed group.
The PR lists ticket keys and CVE IDs.
Existing PRs prevent duplicate creation on a retry.
A committed group accepts no further repairs.

After PR creation, the script resolves fixed tickets with Customer Impact `non-breaking`.
It uses Jira transition IDs `4`, `5`, and `301`, as the skill requires.
If resolution fails, it attempts Stop Progress and reports the result.
Resolution errors remain visible as `resolve_failed`.
The script does not silently retry those transitions.

Cleanup removes clean worktrees after publication.
It also removes clean worktrees without new commits.
It preserves dirty worktrees and unpublished commits.
Local branches remain available.
If a remote branch disappears or changes after publication, cleanup stops for inspection.

Commands save progress after each remote action.
Retries reuse saved worktrees, commits, and PRs.
A retry also recognizes a matching commit after an interrupted state write.
Unexpected branch changes block publication.
For unresolved remote errors, inspect the run file and remote state before another command.

## Development

Run the focused tests from the repository root:

```sh
python3 -m unittest discover -s tests -v
```

The tests use temporary directories and mock remote calls.
They do not require credentials or network access.
