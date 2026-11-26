---
name: commit
description: Write a caveman-commit style message and always add a `Models:` trailer that lists every model the session used, including Auto-mode picks and subagents. Use when the user invokes /tc:commit or asks for a commit message with models.
---

# commit

Write the commit message with all `caveman-commit` rules: Conventional
Commits, terse subject, body only when the why is not obvious.
This skill is the user rule that `caveman-commit` allows for an
AI-attribution trailer. It adds exactly one extra trailer:

```
Models: <model-a>, <model-b>
```

## Get the models

Use real usage data. Never guess a model from memory or from the mode name
("Auto" is not a model).

**Copilot CLI.** Take the session id from the session folder path
(`~/.copilot/session-state/<session-id>`). Query the local session store
(`session_store_sql`, `source: "local"`):

```sql
SELECT DISTINCT model FROM assistant_usage_events
WHERE session_id = '<session-id>' AND model IS NOT NULL
ORDER BY model
```

The `model` column holds the concrete model per call, also in Auto mode.
Rows with `agent_id` set are subagent calls; keep them.
Do not use cloud `session_usage`: it lags behind the live session.

**Claude Code or other agents without a session store.** List your own
model ID and the model of each subagent you started in this session.

**No data.** Ask the user for the model list. Do not write the trailer
with a guess.

## Format

- Dedupe and sort the models. Separate them with `, `.
- Always add the trailer, also for a subject-only commit.
- Put a blank line between subject/body and the trailers.
- Put `Models:` first in the trailer block, before `Co-authored-by:`.

Subject-only example:

```
fix(fix-cves): skip lockfile-only advisories

Models: claude-opus-5.5, gpt-6-luna
Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
```

## Boundaries

Output only the message, as a code block ready to paste. Do not stage,
commit, or amend unless the user asks for it.
