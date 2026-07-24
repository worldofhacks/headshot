# T-F00 Test — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F00-swarm-gates`. Inputs: `tickets/T-F00.md`, `.claude/skills/tdd-swarm/references/quality-gates.md`. Allowed writes: `tests/swarm/test_spec_lint.py`, `test_gate_wrapper.py`, `test_import_cycles.py`. Own RED tests; tag every AC; run `.venv/bin/pytest tests/swarm -q` and prove feature-missing failures, not errors.
No network/spend/live traffic; no main merge/push; maximum 3 attempts. Output `.tdd-swarm/reports/T-F00-test.md`. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` + one line.
Strict local contract: exact ticket input `tickets/T-F00.md`; Test Agent owns only the ticket test_scopes; it must prove clean RED before freeze. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F00.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F00.md` and repository interfaces named by that ticket; exact output: `.tdd-swarm/reports/T-F00-test.md`.
