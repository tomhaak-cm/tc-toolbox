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

   For each dispatch, launch a subagent (Agent tool) with a self-contained prompt: the task, the relevant file paths/context, and the instruction "resolve this, then commit and push your changes to `main` yourself." Do not touch implementation files or run implementation commands in this turn — that work belongs to the subagent.
3. **Wait.** The subagent works. Do not edit files or run implementation commands directly while a task is in flight.
4. **Confirm.** When the subagent reports back, verify it actually committed and pushed — its summary must state the commit hash and push result, not just "done." If it didn't push, tell it to (or dispatch a follow-up subagent) rather than pushing yourself. Once the push is on `origin/main`, clean up its worktree (see **Worktree cleanup**).
5. **Report.** Relay the subagent's outcome to the user in one or two sentences. If tasks are queued behind it, dispatch the next collision-free one now.

### Concurrency ceiling

More parallel subagents only speeds up resolution while you can still tell, for each one, whether it finished cleanly. Past that point extra subagents cost more in verification and conflict cleanup than they gain in wall-clock time. Default ceiling: 3 subagents in flight at once. Lower it for a session where tasks tend to touch shared files (a small, tightly-coupled codebase); raise it only when tasks are clearly siloed (separate packages, unrelated directories) and the user hasn't said otherwise.

## Scoping a dispatch

Goal: keep the main conversation context-efficient. A subagent's context is discarded when it finishes — yours isn't. So when a task needs digging (reading files, grepping, running commands, fetching docs) to find out *what to do*, fold that digging into the same dispatch rather than doing it yourself first and handing the subagent pre-gathered context. Every fact you pull into this conversation to hand off stays here permanently; the same fact pulled inside the subagent vanishes with it. Give the subagent the goal and enough pointers to start (file paths if known, the task), and let it resolve unknowns itself.

## Subagent dispatch must include

Every dispatch prompt carries these — a fresh subagent shares none of this session's context:

- The specific issue/task, self-contained — no "as discussed above."
- Run `git status` before committing; stage only files relevant to the task.
- Commit with a clear message, then `git push` to `main`.
- Never `--no-verify`, never force-push, never discard uncommitted work without checking first.
- Report back: what changed, the commit hash, and push confirmation.
- **When dispatched with `isolation: "worktree"`**: instead of pushing straight to `main`, before the final push run `git fetch origin main && git rebase origin/main`, resolve any real conflict by reading both sides and merging intent (never just pick one side), then `git push origin HEAD:main`.
- If a hook or guard refuses a command, stop and report the refusal. Run tools by their plain names — calling an absolute-path binary (e.g. `/usr/bin/git`) to get past a guard is a bypass.

## Worktree cleanup

Each `isolation: "worktree"` dispatch leaves a worktree under `<repo>/.claude/worktrees/agent-*` on a `worktree-agent-*` branch; nothing removes it, so they pile up. Cleanup is yours, in step 4, per finished subagent. Leave a worktree in place while its subagent is in flight or its commit is not on `origin/main`.

1. **Safe-to-delete check.** `git -C <path> status --porcelain` is empty, and `git fetch origin && git cherry origin/main <branch>` prints no `+` lines. A `-` line means a patch-equivalent commit is already on main (e.g. cherry-picked) — `git branch -d` won't see it as merged, so use `-D`.
2. **Remove.** `git worktree remove <path>`, then `git branch -d <branch>` (`-D` per step 1), then `git worktree prune`. Done when `git worktree list` no longer shows it.

In auto mode the permission classifier may deny the removal ("Irreversible Local Destruction"). Accept the denial: hand the user a ready-to-run `! git worktree remove … && git branch -D … && git worktree prune` line, or suggest a permission rule for it.

## Push gate is a shared, contended resource

A full pre-push suite (e2e included) runs again on every concurrent subagent's push. On one machine, several pushes landing close together compete for the same CPU/browser slots — a browser-driven test can time out from that contention alone, with no relation to any subagent's diff. That looks exactly like a flaky test. Before accepting "flaky" from a subagent: have it re-run the suspected test in true isolation (fresh checkout of the base branch, single worker, no other subagents pushing at that moment). If it passes clean there, the failure was contention — serialize retries (let one push/e2e run finish before the next starts) rather than debug the diff.

## Escalate what the project's own rules block

If a subagent's diagnosis surfaces a genuine, pre-existing bug unrelated to its task that's blocking the shared push gate for everyone, and the project's rules forbid every way around it (no skipped test, no bypassed hook, no exception clause) — that is not the subagent's or your call to resolve solo. Surface it to the user as a real decision with real options (fix it properly / quarantine with a tracked follow-up issue / wait), and don't authorize a workaround yourself in the meantime.

## Staying in mode

Every subsequent user message is a new task for the loop, not a request to answer directly — including follow-up questions about a subagent's work (dispatch a subagent to investigate and answer; don't answer from your own head). Exception: a one-word scope clarification for the next dispatch can be answered directly. Exit only on explicit "stop delegating" / "normal mode" / "exit delegate".
