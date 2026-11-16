# tc toolbox

This repository contains the `tc` agent plugin.
Each skill folder contains its documentation:

| Skill | Purpose |
|---|---|
| [delegate](skills/delegate/README.md) | Delegate tasks to agents |
| [fix-cve](skills/fix-cve/README.md) | Repair CVE tickets with a resumable script |
| [improve-codebase-general](skills/improve-codebase-general/README.md) | Find opportunities to improve code structure |

The `tools/` folder contains standalone scripts. They are not skills:

| Tool | Purpose |
|---|---|
| [fix-cves](tools/fix-cves/README.md) | Repair high and critical `pnpm audit` findings and write a log and HTML report, locally or in CI |

`plugin.json` and `skills/` preserve the installed plugin layout.
This repository is the source of truth.
The installed plugin remains unchanged until you update it from this repository.
The imported skills can refer to other skills that you must install separately.
