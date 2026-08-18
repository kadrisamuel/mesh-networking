# Project Agent Instructions

These instructions apply when an agent is implementing an assigned task from `ENGINEERING_TASKS.md`. Read-only reviews and coordinator operations explicitly requested by the user do not create implementation commits.

## Task boundaries

- Read `MVP_PLAN.md`, `ENGINEERING_TASKS.md`, the assigned phase file, and every specification named by the task before editing.
- Implement exactly one assigned task and stay within its allowed paths.
- Stop and report a blocker when a prerequisite, specification, fixture, tool, credential, device, or security decision is missing.
- Preserve unrelated changes and do not perform opportunistic refactors or dependency upgrades.
- Do not edit `TASK_TRACKER.md`; task status is controlled by the coordinator.

## Commit policy

- Create local commits on the assigned task branch unless the coordinator explicitly says `NO-COMMIT`.
- Before editing, record the starting HEAD and confirm that the assigned task branch is checked out. Stop on `main`, `master`, a coordinator-designated protected branch, or detached HEAD.
- Inspect the initial worktree state. Stop and report any pre-existing change outside the task's allowed paths.
- Use one commit for a small atomic task. For a long task, commit coherent, independently reviewable milestones.
- Before committing, run the verification applicable to the milestone and inspect the staged diff for secrets and out-of-scope files.
- Stage explicit allowed paths only; never use `git add .` or `git add -A`.
- Commit only allowed task paths. Never commit real credentials, production private keys, real recovery material, temporary files, unrelated changes, or knowingly broken output. Deterministic secret inputs are allowed only when the task explicitly requires public test vectors and the files clearly identify them as public, test-only fixtures that must never be used in production.
- Use commit messages in the form `<TASK-ID>: <imperative summary>`.
- Do not merge, push, rebase, reset, amend, force-update, otherwise rewrite history, edit `TASK_TRACKER.md`, or mark the task complete unless the coordinator explicitly authorizes that exact action.
- On a successful implementation handoff, commit all task-owned changes and leave no uncommitted task changes. If blocked, preserve earlier safe checkpoint commits but do not commit incomplete or unsafe output merely to clean the worktree; report every remaining change.
- Return the starting HEAD, each ordered task commit and its purpose, the final HEAD, and final `git status --short` output.

Implementation commits are checkpoints, not acceptance. The coordinator verifies the complete `<starting-HEAD>..<final-HEAD>` range, final worktree state, evidence, and required human gates before merging or updating task status. The commit policy in `ENGINEERING_TASKS.md` is authoritative if wording differs.
