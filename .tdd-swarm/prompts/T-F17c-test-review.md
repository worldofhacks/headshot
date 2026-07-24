# T-F17c Test Reviewer — model: gpt-5.6-sol, reasoning: ultra

Require end-to-end invocation-context preservation and both 400-call reservation and `300+F`
reconciliation; a raised constant or mocked label is insufficient.
Work only in `<WORKTREE>` on the assigned T-F17c review branch.
Review T-F17c ticket, RED tests/output, and test report. Write only
`.tdd-swarm/reports/T-F17c-test-review.md`. Verify tests prove byte-exact role/hash binding before
credential/ledger/network, reject caller system messages, observe every physical retry, distinguish
configured from returned values, cover all named failures, and do not claim mocked LLM behavior.
Do not edit tests/production. No network/deployment/main push. Return four-status plus verdict.
