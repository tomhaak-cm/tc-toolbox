---
name: delegate
description: Enter subagent delegation mode — every task is handed to a subagent that resolves it, then commits and pushes to main itself. Invoke by hand only.
disable-model-invocation: true
---

# delegate

Persistent mode. Once invoked, every task you receive — for the rest of the session, or until the user says "stop delegating" / "normal mode" — is handled by dispatching a subagent, never by doing the work yourself.

## Loop

For each task:

1. **Classify.** If the message hands over a list of multiple tasks, sort each pair: can Task A and Task B be done without touching the same files and without one waiting on the other's output? If yes, they're **independent**. If no, they're **dependent** — put them in one subagent dispatch, or run them sequentially; never let two subagents race a push to the same file. A single task skips classification.
2. **Check for collision, then dispatch or queue.** A **collision** is a file, module, or area an in-flight subagent is already touching that a new task would also touch — including anything upstream of a merge/rebase the in-flight subagent will still need to do (shared config, a barrel file, the same test suite). Before launching any subagent, walk every task cleared as independent against every subagent still in flight:
   - **No collision, and under the concurrency ceiling (see below)** — dispatch now. Independent, collision-free tasks launch together in one message, each its own subagent.
   - **Collision with an in-flight subagent** — queue it. Dispatch only once that subagent has reported back, committed, and pushed. A second subagent editing a colliding area doesn't finish the work faster; it produces a merge conflict, a rebase, or a lost push that then has to be resolved on top of the original work.
   - **At the ceiling, no collision** — queue it behind whichever in-flight subagent will finish first. More concurrent subagents past the ceiling split your attention across more finish lines than you can verify, so slow completions and missed pushes go unnoticed longer, not shorter.

   **Any time 2+ subagents run concurrently in the same repo, dispatch each with `isolation: "worktree"`** (the Agent tool creates a separate git worktree + branch per subagent). Target files looking disjoint is not the same as collision-free: a shared i18n file, a shared stylesheet, a shared config — infra any component can reach into — is the collision you don't see by reading target file lists, and it's invisible right up until two subagents' uncommitted edits sit in the same tree and the repo's own pre-commit/pre-push gate (which tests the whole tree, not just staged files) blocks both on each other. Worktree isolation removes this class of collision entirely; skip it only for a single subagent running alone.

   **Probe once before the first worktree dispatch of the session.** A user PreToolUse hook that rewrites `git …` into a wrapper (RTK, caveman) trips Claude Code's worktree-isolation guard, which then refuses every git command in the worktree, `git status` included. Dispatch one `isolation: "worktree"` subagent whose only job is to run `git status` and report the output or the refusal verbatim. A probe beats reading settings: such hooks also arrive through plugins. If git is refused, worktree isolation is off for the session: run each task that would need it alone in the main tree, one after another. Exempting worktrees in the hook config is the user's call (auto mode blocks it as [Self-Modification]); name the option to the user and leave the config alone.

   For each dispatch, launch a subagent (Agent tool) with a self-contained prompt: the task, the relevant file paths/context, and the instruction "resolve this, then commit and push your changes to `main` yourself." Do not touch implementation files or run implementation commands in this turn — that work belongs to the subagent.
3. **Wait.** The subagent works. Do not edit files or run implementation commands directly while a task is in flight.
4. **Confirm.** When the subagent reports back, verify it actually committed and pushed — its summary must state the commit hash and push result, not just "done." If it didn't push, tell it to (or dispatch a follow-up subagent) rather than pushing yourself. Verify and clean up its worktree in one shell call (see **Worktree cleanup**).
5. **Report.** Relay a finished task in one line (what, hash). Add words only when the user must decide something. If tasks are queued behind it, dispatch the next collision-free one now.

### Concurrency ceiling

More parallel subagents only speeds up resolution while you can still tell, for each one, whether it finished cleanly. Past that point extra subagents cost more in verification and conflict cleanup than they gain in wall-clock time. Default ceiling: 3 subagents in flight at once. Lower it for a session where tasks tend to touch shared files (a small, tightly-coupled codebase); raise it only when tasks are clearly siloed (separate packages, unrelated directories) and the user hasn't said otherwise.

## Scoping a dispatch

Goal: keep the main conversation context-efficient. A subagent's context is discarded when it finishes — yours isn't. So when a task needs digging (reading files, grepping, running commands, fetching docs) to find out *what to do*, fold that digging into the same dispatch rather than doing it yourself first and handing the subagent pre-gathered context. Every fact you pull into this conversation to hand off stays here permanently; the same fact pulled inside the subagent vanishes with it. Give the subagent the goal and enough pointers to start (file paths if known, the task), and let it resolve unknowns itself.

**Combine small tasks.** Every fresh subagent pays a fixed start cost: re-reading project instructions, decisions, code. Put small, related tasks into one dispatch (still one commit per task) on the cheapest model that fits, so that cost is shared. Heavy tasks, and tasks needing different models, get their own dispatch.

**Reset context at milestones.** Your context is re-read on every turn, so each kept token is paid again on every later turn. After a large milestone (a whole spec done, a review finished), tell the user to run `/compact` or `/clear` — you cannot run them — and to re-invoke this skill afterwards. Prefer one spec or major goal per session.

## Choosing the model

Set the Agent tool's `model` per dispatch, by what a wrong result costs:

- `haiku` — probes, checks, cleanup, lookups; mechanical, well-specified, low-risk: renames, run a check and report, the worktree git-status probe, salvage patch-apply.
- `sonnet` — routine, well-scoped tickets with clear pointers and tests that confirm them.
- `opus`, or omit `model` to inherit yours — ambiguous, cross-cutting, design-heavy, debugging, measure-then-decide; anything where a wrong call costs a redo.

**Escalate.** When a cheaper-tier subagent fails, or reports low-quality or unverified work, re-dispatch the task one tier up. The fix stays with a subagent, not you.

`subagent_type: "fork"` runs on your model and ignores `model`.

## Subagent dispatch must include

Every dispatch prompt carries these — a fresh subagent shares none of this session's context:

- The `model` for this task (see **Choosing the model**) — chosen at every dispatch, set on the Agent call itself.
- The specific issue/task, self-contained — no "as discussed above."
- Run `git status` before committing; stage only files relevant to the task.
- Commit with a clear message, then `git push` to `main`.
- Never `--no-verify`, never force-push, never discard uncommitted work without checking first.
- Report back in **≤5 lines** — hard cap, stated in the prompt. The report is the only part that stays in your context for good. Ask for exactly: commit hash, push confirmation (`git log origin/main -1 --oneline`), test pass counts, headings of any open questions it recorded, and a one-line summary. All detail goes to files (repo tickets, ADRs, or a notes file in the scratchpad), and the report gives the path.
- Keep the subagent's start cost low: point it at the project's agent quick-start or code map (e.g. `docs/agents/seams.md`) to read first instead of searching the codebase, and pass paths to prior notes files instead of restating context. Suggest the user keep such a doc lean and current.
- **When dispatched with `isolation: "worktree"`**: instead of pushing straight to `main`, before the final push run `git fetch origin main && git rebase origin/main`, resolve any real conflict by reading both sides and merging intent (never just pick one side), then `git push origin HEAD:main`. If git is refused there, finish the code anyway and report the changed file list and the test result, so the salvage step (see **Worktree cleanup**) knows exactly what to apply.
- If a hook or guard refuses a command, stop and report the refusal. Run tools by their plain names — calling an absolute-path binary (e.g. `/usr/bin/git`) to get past a guard is a bypass.

## Worktree cleanup

Each `isolation: "worktree"` dispatch leaves a worktree under `<repo>/.claude/worktrees/agent-*` on a `worktree-agent-*` branch; nothing removes it, so they pile up. Cleanup is yours, in step 4, per finished subagent. Leave a worktree in place while its subagent is in flight or its commit is not on `origin/main`.

**Salvage when git was refused in the worktree.** The work sits uncommitted in the worktree. Dispatch one non-isolated subagent in the main tree per worktree, one at a time: it runs `git -C <worktree> diff -- <files>` on the reported files (`git -C <worktree> add -N <file>` first for new files, or the diff omits them), applies the patch with `git apply`, runs the tests, commits once for that task, and pushes. Patches, not whole-file copies: a copy overwrites whatever main gained since. Once that commit is on `origin/main`, clean up below; the salvaged worktree stays dirty, so step 1's empty-status check reads "the salvage commit is on `origin/main`" instead, and removal needs `git worktree remove --force`.

Run verify-push and cleanup as **one shell call** (haiku subagent or you, never several calls). Template, per worktree (`P` path, `B` branch, `H` hash from the report):

```bash
P=<path>; B=<branch>; H=<hash>; git fetch origin -q && git log origin/main -1 --oneline && [ -z "$(git -C $P status --porcelain)" ] && git merge-base --is-ancestor $H origin/main && git worktree remove $P && git branch -D $B && git worktree prune && git worktree list
```

It stops at the first failed check and leaves the worktree. The steps below say what each part does; for a cherry-picked commit use `git cherry` instead of the ancestor check.

1. **Safe-to-delete check.** `git -C <path> status --porcelain` is empty, and `git fetch origin && git cherry origin/main <branch>` prints no `+` lines. A `-` line means a patch-equivalent commit is already on main (e.g. cherry-picked) — `git branch -d` won't see it as merged, so use `-D`.
2. **Remove.** `git worktree remove <path>`, then `git branch -d <branch>` (`-D` per step 1), then `git worktree prune`. Done when `git worktree list` no longer shows it.

In auto mode the permission classifier may deny the removal ("Irreversible Local Destruction"). Accept the denial: hand the user a ready-to-run `! git worktree remove … && git branch -D … && git worktree prune` line, or suggest a permission rule for it.

## Push gate is a shared, contended resource

A full pre-push suite (e2e included) runs again on every concurrent subagent's push. On one machine, several pushes landing close together compete for the same CPU/browser slots — a browser-driven test can time out from that contention alone, with no relation to any subagent's diff. That looks exactly like a flaky test. Before accepting "flaky" from a subagent: have it re-run the suspected test in true isolation (fresh checkout of the base branch, single worker, no other subagents pushing at that moment). If it passes clean there, the failure was contention — serialize retries (let one push/e2e run finish before the next starts) rather than debug the diff.

**Fix flaky checks early.** When a gate test fails, then passes alone, more than once, queue a task to fix the flakiness (find the cause: contention, timing, shared state) instead of letting every subagent re-run it. Each flaky failure makes every later subagent re-run the suite and read its output — tokens spent on every task.

## Escalate what the project's own rules block

If a subagent's diagnosis surfaces a genuine, pre-existing bug unrelated to its task that's blocking the shared push gate for everyone, and the project's rules forbid every way around it (no skipped test, no bypassed hook, no exception clause) — that is not the subagent's or your call to resolve solo. Surface it to the user as a real decision with real options (fix it properly / quarantine with a tracked follow-up issue / wait), and don't authorize a workaround yourself in the meantime.

## Staying in mode

Every subsequent user message is a new task for the loop, not a request to answer directly — including follow-up questions about a subagent's work (dispatch a subagent to investigate and answer; don't answer from your own head). Exception: a one-word scope clarification for the next dispatch can be answered directly. Exit only on explicit "stop delegating" / "normal mode" / "exit delegate".
