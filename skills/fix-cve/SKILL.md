---
name: fix-cve
description: Repair CVE tickets from a Jira board with the bundled script. Review difficult repairs, then publish one PR per base branch.
disable-model-invocation: true
---

# Fix CVE

Run deterministic operations with `scripts/fix_cve.py` in this skill directory.
Read [README.md](README.md) in this skill directory for credentials, command arguments, state, and recovery.
Keep all run data outside the repository under repair.
The script requires direct REST credentials. MCP authentication does not supply these credentials.

A **group** contains tickets with one base branch.
A **skipped** ticket remains in the report without a repair.
A **difficult** repair needs an explicit user decision.

## 1. Credentials

Check that `~/.config/tc/fix-cve.env` exists.
If it is missing, create the directory with mode `700`, create the file from the template in [README.md](README.md) with mode `600`, and ask the user to fill in the values in their editor.
Never ask for the token in chat or print its value.
Each bash call starts a new shell, so load the file in every command that runs the script: `set -a; . ~/.config/tc/fix-cve.env; set +a`.

Done when the file exists, has mode `600`, and contains the required variables.

## 2. Collect

Ask once for the Jira board ID, project prefix, and status categories.
Default the categories to `To Do`.
Use the current repository as the target.
Create a separate state directory for this run.
Run `collect`.

The script reads all Jira pages, both rating queries, and all open Dependabot alerts.
It keeps unrated tickets untouched and reports unclear alert matches.
No matching open alert means skipped, not confirmed withdrawal.
For CMS, the script gets supported release branches from Confluence.

Done when the report accounts for every collected ticket.

## 3. Decide branch groups

Ask once about tickets with several affects versions or an unsupported version.
Run `decide --base` for each selected version.
For unsupported versions, use the user's choice of `--still-do` or `--wont-fix`.
The latter updates Won't Fix Versions immediately and skips the ticket.
Resolve unclear alert matches before a new collection.

Done when every actionable ticket has one permitted base branch.

## 4. Repair

Read the target repository's instructions and documented verification commands.
Create a verification JSON file with build, lint, and unit-test commands that cover all affected packages.
Pass `--checks` to `collect` so the path is saved, then run `apply`.
The script owns worktree creation, automatic pnpm upgrades, verification, assignment, and Start Progress.

Use these repair rules:

- **Easy:** A dependency version change without new code or public-API changes. All required checks must pass.
- **Difficult:** A major upgrade, code change, public-API change, or Rating Statement that requests upstream action.
- **Minor upgrade:** Review its changelog before `decide --allow-minor` and another `apply`.
- **Other ecosystems:** Repair manually in the group's worktree, then use `record --status changed` and `verify`.
- **pnpm:** Read [PNPM.md](PNPM.md) before manual dependency repair or a severity decision.
- **Overrides:** Offer these only as difficult options. Obtain explicit approval and obey the follow-up requirements in PNPM.md.

An automatic attempt that cannot complete an easy repair becomes difficult.
For missing upstream fixes, research the upstream issue and give options with risk and effort.
For harder moderate-or-lower findings, include "defer to the next dependency upgrade".

If the user reserves test execution for themselves, stop before `apply` or `verify`.
Give them the exact command and wait for the results.
Never mark an unverified repair fixed.

Done when every attempted ticket has a status, change summary, and verification result.

## 5. Review difficult repairs

Show the HTML report (`<state>.html`) with ticket, branch, status, and possible difficult repairs.
Ask which difficult repairs to implement, or let the user approve, skip, or record them in the report.
The report's **Next commands** block gives the exact commands for each step, so run those instead of composing them.
For each selected repair, run `prepare` when necessary and work in that group's worktree.
Read its repository instructions before edits.
Use `--allow-major` only after explicit approval of that upgrade.
Record manual changes with `record --status changed`.
Run `verify` after the repair.

Repeat until the user selects no more difficult repairs.

## 6. Publish

After the user accepts the report, run the report's **Publish** block: `publish --yes`, `cleanup`, and `report`.
The script commits, pushes, opens one PR per changed group, and resolves fixed Jira tickets.
If Resolve fails, the script attempts Stop Progress and reports the ticket.
Run `cleanup`.
Report the PR URLs and all fixed, difficult, failed, skipped, unrated, and unresolved tickets.
Preserve worktrees when the script reports unpublished or dirty work.

Done when every verified group has a PR and every ticket has a final status.
