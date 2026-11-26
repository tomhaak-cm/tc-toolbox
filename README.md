# tc toolbox

This repository contains the `tc` agent plugin.
Each skill folder contains its documentation:

| Skill | Purpose |
|---|---|
| [commit](skills/commit/README.md) | Write commit messages with a `Models:` trailer |
| [delegate](skills/delegate/README.md) | Delegate tasks to agents |
| [fix-cves](skills/fix-cves/SKILL.md) | Triage dependency advisories and review upgrade decisions |
| [improve-codebase-general](skills/improve-codebase-general/README.md) | Find opportunities to improve code structure |

The `tools/` folder contains standalone scripts. They are not skills:

| Tool | Purpose |
|---|---|
| [fix-cves](tools/fix-cves/README.md) | Repair high and critical npm and pnpm audit findings and write an HTML report |

`plugin.json` and `skills/` preserve the installed plugin layout.
This repository is the source of truth.
The installed plugin remains unchanged until you update it from this repository.
The imported skills can refer to other skills that you must install separately.
