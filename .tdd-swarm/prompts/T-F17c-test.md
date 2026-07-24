# T-F17c Test Agent — model: gpt-5.6-sol, reasoning: ultra

Work only in `<WORKTREE>` on `ticket/T-F17c-hosted-system-messages`. Read ticket, T-F17a/T-F17b
interfaces, plan, and lessons. Write only `tests/test_hosted_configuration.py`,
`tests/test_hosted_runtime.py`, and `tests/test_openrouter_transport.py`. Produce clean
criterion-tagged RED for leading exact system messages, mismatch zero-I/O refusal, locked models and
upstreams, per-physical success/error/retry events, fail-closed response validation, and prompt-inclusive
token reservation. Fake HTTP only; no live provider/target. Report to
`.tdd-swarm/reports/T-F17c-test.md`; return four-status plus one line.
