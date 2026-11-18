---
name: fix-cves
description: Repair high or critical npm or pnpm dependency advisories. Use when asked to triage open CVEs, upgrade affected dependencies, or review a proposed override.
---

# Fix dependency advisories

1. Read the [CLI guide](../../tools/fix-cves/README.md). Check that the target branch is current.
2. Run `fix_cves.mjs` against the requested package. Start without major upgrade or override approval.
3. Read the HTML report. For each open advisory, use the matching action:

| Result | Action |
|---|---|
| No patch | Check upstream issues for a patch. Link the issues and set a recheck date. If upstream has no plan, discuss package replacement |
| Workspace dependency blocks a patch | Identify the blocking package and range. Consult the workspace owner before you change the range |
| Major upgrade necessary | Identify the version change and breaking changes. Get explicit approval before you use `--allow-major` |
| No normal upgrade works | Prefer an upstream fix or wait for a patch. If the risk requires an override, explain the compatibility risk and get explicit approval before you use `--allow-override` |

4. Review the changelog for minor or major upgrades. Run the project checks.
5. If the user requests publication, create a fix branch and commit the dependency files. Open a PR and check its CI result.
6. If the changes include an override, notify the upstream maintainers. Create a follow-up CMS ticket with the upstream links. Consider a release note if the override ships.

Keep the report and ticket data out of Git. Report the results, the remaining work, and the HTML report path.
