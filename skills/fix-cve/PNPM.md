# Fix a CVE in a pnpm workspace

Use this for a ticket whose package lives in a pnpm workspace (for example `apps/studio-client` or `frontend/blueprint`). Run every command in the workspace root, after `pnpm install`.

## Severity

Act on **high** and **critical** findings. For **moderate** or lower, apply only an easy fix; otherwise classify the ticket as difficult, with the option "defer to the next dependency upgrade".

## Step 1: Audit

```sh
pnpm audit --registry=https://registry.npmjs.org/ --audit-level high
```

Read "Patched versions" for the package. With no patched version, classify the ticket as difficult: search the package's GitHub issues for a fix in progress, and offer "wait and check again in a few days" or "replace the package".

Done when the package has a patched version, or the ticket is difficult.

## Step 2: Upgrade the package

```sh
pnpm -r up <package>
pnpm dedupe
pnpm audit --registry=https://registry.npmjs.org/ --audit-level high
```

`pnpm -r up` respects the semver ranges of every dependent, so a pinned or narrow range keeps the vulnerable version. Check the version jump: patch is safe, minor needs a changelog check, major makes the ticket difficult.

Done when the audit is clean for the package (easy fix: the changed `pnpm-lock.yaml` and any `package.json` files), or the vulnerable version remains (go to Step 3).

## Step 3: Upgrade the dependents

Walk the dependency tree breadth-first, starting with the vulnerable package as the target:

1. List the dependents of the vulnerable versions: `pnpm -r why <target>@"<vulnerable-range>"` (quote the range).
2. Take the shallowest direct dependent of the target.
3. If the dependent is a workspace package, it is already the latest version: classify the ticket as difficult and name that package in the report.
4. Otherwise run `pnpm -r up <dependent>`, then repeat the `why` command.
5. If the dependent is gone from the list, continue with the next dependent. If it remains, repeat from 1 with the dependent as the target.

Done when `pnpm -r why <package>@"<vulnerable-range>"` is empty, or the ticket is difficult.

## Last resort: override

`pnpm audit --registry=https://registry.npmjs.org/ --audit-level high --fix` writes an override into the workspace `package.json`. The override breaks semver: a dependent built for `^1.0.0` can get `3.2.1`, and the tests of third-party packages never run against it.

Offer the override only as a difficult-fix option, ranked below "wait for an upstream fix". Apply it only when the user selects it in Step 6 of the skill. Then:

- Make sure the package maintainers know about the issue (link or open the upstream issue).
- Create a follow-up ticket to remove the override, with links to the upstream issues.
- On the fixed ticket, fill "Release Note Summary" (`customfield_10682`) and "Release Note" (`customfield_10681`) to warn customers about possible conflicts.
