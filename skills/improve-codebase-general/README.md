# Improve Codebase Architecture

This skill examines a repository for opportunities to simplify its architecture.
It produces an HTML report with proposed changes and before-and-after diagrams.

## Usage

Invoke `/tc:improve-codebase-general` in the target repository.
For a narrower review, name a module, subsystem, or problem.
After the report, select a proposal to examine its risks and design choices.

The report resides in the operating system's temporary directory.
The skill opens it in your browser.
The report uses Tailwind and Mermaid from CDNs.

## Requirements

The skill uses the separate `codebase-design`, `grilling`, and `domain-modeling` skills.
The agent environment must support subagents.
The skill reads the repository's domain glossary and architecture decisions when present.
Later design decisions can update `CONTEXT.md` or add an architecture decision record.

[SKILL.md](SKILL.md) contains the agent instructions.
[HTML-REPORT.md](HTML-REPORT.md) contains the report format and diagram guidance.
