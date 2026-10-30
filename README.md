# tc skills

This repository contains the `tc` agent plugin.
Each skill folder contains its documentation:

| Skill | Purpose |
|---|---|
| [delegate](skills/delegate/README.md) | Delegate tasks to agents |
| [fix-cve](skills/fix-cve/README.md) | Repair CVE tickets with a resumable script |
| [improve-codebase-general](skills/improve-codebase-general/README.md) | Find opportunities to improve code structure |

`plugin.json` and `skills/` preserve the installed plugin layout.
This repository is the source of truth.
The installed plugin remains unchanged until you update it from this repository.
The imported skills can refer to other skills that you must install separately.
