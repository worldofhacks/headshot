# T-F17c Test Reviewer — model: gpt-5.6-sol, reasoning: ultra

Require a unique pre-call context per physical attempt and end-to-end hosted-100 call/token/spend/
time authorization; a raised constant or mocked profile label is insufficient.
Work only in `<WORKTREE>` on the assigned T-F17c review branch.
Review T-F17c ticket, RED tests/output, and test report. Write only
`.tdd-swarm/reports/T-F17c-test-review.md`. Verify tests prove byte-exact role/hash binding before
credential/ledger/network, reject caller system messages, create two contexts before
retry-then-success reservations, preserve the logical running state between them, distinguish
configured from returned values, accept 400 only for exact scope-hashed `hosted-100-v1`, retain
legacy 56/USD-5 bounds, prove the Decimal token/spend/time equations across domain/API/control-plane
layers, cover all named failures, and do not claim mocked LLM behavior.
Do not edit tests/production. No network/deployment/main push. Return four-status plus verdict.
