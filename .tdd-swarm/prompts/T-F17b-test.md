# T-F17b Test Agent — model: gpt-5.6-sol, reasoning: ultra

Work only in `<WORKTREE>` on `ticket/T-F17b-provider-call-lineage`. Read the ticket, plan, and
lessons. Write only `tests/test_provider_call_lineage.py`. Produce criterion-tagged RED covering
success, every named failure, retry ordering, unavailable measurements, no invented zero, DB grants,
append-only enforcement, indexes, migration round-trip, org isolation, and secret-content refusal.
Use local disposable Postgres only; no provider/target network. Record worktree identity. Write
`.tdd-swarm/reports/T-F17b-test.md`; return the four-status contract plus one line.
