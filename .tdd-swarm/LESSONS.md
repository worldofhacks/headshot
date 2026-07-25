# tdd-swarm LESSONS (durable across runs)

## 2026-07-24 — Treat worktree path anchoring as an independently verified gate

- A repair Test Agent that was given an exact worktree path still committed first to the similarly
  named integration ticket branch. The patch was test-only and valid, but the branch isolation
  contract was not mechanically enforced.
- Before every agent commit, require recorded `pwd`, `git rev-parse --show-toplevel`,
  `git branch --show-current`, and `git status --short`; the orchestrator must compare them with the
  assigned ticket/worktree before accepting the commit.
- Prefer orchestrator-owned cherry-picks for disjoint repair branches. Never rewrite or reset shared
  history merely to cosmetically repair an otherwise valid, attributable commit.
