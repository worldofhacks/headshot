# T-F17d Test Agent — model: gpt-5.6-sol, reasoning: ultra

Work only in `<WORKTREE>` on `ticket/T-F17d-runner-hosted-composition`. Read ticket, T-F17c contract,
Runner/Coordinator/Policy Gateway, plan, and lessons. Write only `tests/test_runner_hosted_runtime.py`.
Produce criterion-tagged RED using local Postgres, fake provider, and fake target. Prove zero-I/O
blockers, exact hosted path, role order/parents, one trusted target evaluator/one target exit,
deterministic precedence, conditional draft, deterministic compatibility, no fallback, and terminal
failure reconciliation. No external network/deployment/main push. Report T-F17d-test; return four-status.
Write `.tdd-swarm/reports/T-F17d-test.md`. Return exactly
`DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one line.
