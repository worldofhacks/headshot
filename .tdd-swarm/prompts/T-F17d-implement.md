# T-F17d Implementation Agent — model: gpt-5.6-sol, reasoning: ultra

Work only in `<WORKTREE>` on `ticket/T-F17d-runner-hosted-composition`. Read ticket, frozen tests,
review, T-F17c interface, and lessons. Write only `src/agentforge/runner.py`,
`src/agentforge/agents/hosted_composition.py`, and the declared migration note. Never edit tests.
Keep provider and target credentials Runner-only and preserve Policy Gateway as sole target exit.
Run local gates within three loops. No external calls/deployment/main push. Report T-F17d-implement;
write `.tdd-swarm/reports/T-F17d-implement.md`. Return exactly
`DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)`, commits, and one-line gates.
