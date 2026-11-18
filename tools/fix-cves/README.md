# Fix CVEs

`fix_cves.mjs` attempts to fix high and critical dependency advisories.
It accepts a standalone npm or pnpm project, a workspace root, or a workspace member.
For a workspace member, it audits and repairs the complete shared lockfile.

## Run locally

1. Check out the affected branch and update it.
2. Make sure that you can run the package manager version that the project requires.
3. Run the script with Node.js 18 or later:

   ```sh
   node tools/fix-cves/fix_cves.mjs /path/to/cms/apps/studio-client
   ```

4. Open `report.html` at the path that the script prints.

The script needs an existing `pnpm-lock.yaml`, `package-lock.json`, or `npm-shrinkwrap.json`.
Run it only in a project that you trust. Do not edit the dependency files during the run.
The script does not check out branches, pull changes, or create commits, PRs, or tickets.
An audit sends dependency names and versions to the selected registry. For private projects, use a registry that your organization approves.

| Option | Purpose |
|---|---|
| `--audit-only` | Write the report without installing or changing dependencies |
| `--out DIR` | Write `report.html` in this directory. The default is a new system temporary directory |
| `--registry URL` | Set the audit registry. The default is `https://registry.npmjs.org/` |
| `--allow-major` | Approve major upgrades. A minor change in `0.x` also requires this approval |
| `--allow-override` | Approve a pnpm override after normal upgrades fail. Major upgrades still require separate approval |

## Repair order

1. Audit the lockfile. Skip advisories with lower severity.
2. If pnpm reports no patched version, leave the advisory open.
3. Install from the existing lockfile with lifecycle scripts disabled.
4. Update the affected package within the declared ranges. Deduplicate the dependency tree and audit it again.
5. If the advisory remains, use `pnpm why` or `npm explain` to find its dependents. Try updates breadth-first.
6. If approved, try `pnpm audit --fix` as a last resort for patchable high and critical advisories.

The script keeps an update only if it removes an advisory or reduces its affected paths.
It restores rejected changes. An update that introduces a high or critical advisory does not qualify.
npm does not tell the script which version patches an individual advisory. The script can still try a range-compatible update.
The script does not force npm resolutions.

## Results

The terminal and HTML report list fixed and open advisories, including why the script kept or rejected changes.
For the default audit registry, the script can look up missing CVE IDs through the public GitHub advisory API.
If the lookup fails, the report still shows the advisory ID.

| Exit code | Meaning |
|---|---|
| `0` | No high or critical advisory remains |
| `1` | At least one high or critical advisory remains |
| `2` | The run did not complete |

Review the dependency changes and run the project checks before you submit a fix branch.
For open advisories and override follow-up, see the [fix-cves skill](../../skills/fix-cves/SKILL.md).

## Development

```sh
node --test tests/fix_cves.test.mjs
```
