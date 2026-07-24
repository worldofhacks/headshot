# T-F16b Implement — Model: gpt-5.6-sol (capable)
Worktree `<WORKTREE>`; branch `ticket/T-F16b-physical-operation-gateway`; baseline `1ac3ee0`. Inputs: ticket, frozen test/review, lessons, T-F16a. Allowed writes only: `src/agentforge/target/base.py`, `src/agentforge/policy/gateway.py`, `src/agentforge/campaign/coordinator.py`, `.tdd-swarm/reports/T-F16b-implement.md`. Extend—not duplicate—the landed work-unit controls with gateway-owned flow and retry-inclusive capacity; never edit tests.

Run `.tdd-swarm/run-local-gates.sh tickets/T-F16b.md <DIFF_BASE>` each loop; maximum three GREEN attempts. No network, credentials, owner files, main merge, or push. Return the four-status contract plus commits/gates.
