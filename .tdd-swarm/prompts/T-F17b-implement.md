# T-F17b Implementation Agent — model: gpt-5.6-sol, reasoning: ultra

Implement the frozen Runner-owned `begin_physical_attempt(logical_context, sequence)` factory,
per-physical atomic/idempotent terminal events, final-only logical terminalization,
outcome-unknown recovery, composite identity, and canonical nullable cost; never manufacture zero.
Work only in `<WORKTREE>` on `ticket/T-F17b-provider-call-lineage`. Read ticket, frozen tests/review,
and lessons. Write only `src/agentforge/providers/lineage.py`, `src/agentforge/storage/models.py`,
`src/agentforge/control_plane/store.py`, the uniquely named `*_provider_call_lineage.py` migration,
and its migration note. Never edit tests. Run the local gate within three loops, including disposable
Postgres migration/grants. No external network/deployment/main push. Report to
`.tdd-swarm/reports/T-F17b-implement.md`; return four-status, commits, one-line gates.
