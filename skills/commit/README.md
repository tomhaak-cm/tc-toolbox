# Commit

This skill writes a commit message in the `caveman-commit` style.
It always adds a `Models:` trailer.
The trailer lists all models that the session used.

## Usage

Invoke `/tc:commit`.
The skill gives the message as a code block.
It does not stage or commit files.

## Model source

In Copilot CLI, the skill reads the local session store table `assistant_usage_events`.
This table records the real model of each call, also in Auto mode and in subagents.
In other agents, the agent lists its own model and the models of its subagents.
If no data is available, the skill asks you for the models.

## Example

```
feat(api): add GET /users/:id/profile

Models: claude-opus-5.5, gpt-6-luna
```

## Requirements

Install the `caveman-commit` skill. This skill uses its rules.
