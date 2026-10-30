# Delegate

This skill delegates tasks to agents that commit and push their changes to `main`.
The mode remains active until you stop it.

## Usage

Invoke `/tc:delegate`, then describe the task.
To leave the mode, say `stop delegating`, `normal mode`, or `exit delegate`.

The skill separates independent tasks and queues tasks that can conflict.
Concurrent agents use separate worktrees.
The default limit is three concurrent agents.
After each task, the report includes its commit and push result.

## Requirements

The agent environment must support subagents and isolated worktrees.
The target repository must permit commits and pushes to `main`.
Repository hooks and instructions remain binding.

[SKILL.md](SKILL.md) contains the agent instructions.
