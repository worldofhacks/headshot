# T-F17e Implementation Agent — model: gpt-5.6-sol, reasoning: ultra

Work only in `<WORKTREE>` on `ticket/T-F17e-hosted-capability-deployment`. Read ticket, frozen tests,
review, T-F17d interface, and lessons. Write only `src/agentforge/telemetry/outbound.py`,
`src/agentforge/api/postgres.py`, `src/agentforge/app.py`, `.env.example`, `railway/**`, and the two
deployment runbooks. Never edit tests. Run local/container/config gates within three loops. Do not
touch Railway, resolve real credentials, call providers/targets, or push main. Report
to `.tdd-swarm/reports/T-F17e-implement.md`. Return exactly
`DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)`, commits, and gates.
