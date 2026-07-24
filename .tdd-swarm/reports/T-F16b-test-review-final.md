# T-F16b Final Test Review and Freeze

Status: `DONE`

Freeze verdict: `PASS — FROZEN`

Reviewer: independent of the authoring agent; reviewed against `tickets/T-F16b.md`,
`docs/planning/final-target-adapters.md`, and the accepted T-F16a contract.

## Frozen identity

- Test commit: `dc7232f7ba793eebc4804425400a5a115095448b`
- Test SHA-256: `1db1a755e8616ffd780e8fcfc75d3d4860839919df0405ebf9eb267cf9350eaf`
- Git blob: `8535b226c98505eb1b6c2edbe56c40b6ab4dd155`
- Product baseline: `77978d9c366d76bfda5b1150eb6f766f5dbf760f`

Both digests were re-verified against the working tree after the lane merged shared `12eb13e`
and `723be15..9f5721b`. `tests/test_surface_operation_gateway.py` is byte-identical to the
candidate across both merges, so the freeze identity is unchanged by integration.

## Verification

- Isolated RED, from a `git archive` export of `dc7232f` into a scratch tree so no repository
  state was mutated: `51` failed, `1` passed, `52` collected. Exit `1`.
- All `51` failures are the same intentional assertion at
  `tests/test_surface_operation_gateway.py:277`:
  `T-F16b operation-flow boundary is absent; missing OperationFlowAborted,
  PolicyGateway.execute_operation_flow, SurfaceOperation, SurfaceOperationResponse`.
  Zero import, syntax, collection, or fixture errors — RED for the intended reason.
- Absence confirmed in product code: `src/agentforge/target/base.py` declares no
  `SurfaceOperation` / `SurfaceOperationResponse`; `src/agentforge/policy/gateway.py` declares no
  `OperationFlowAborted` / `execute_operation_flow`.
- The single inherited pass is
  `test_spec_t_f16b_ac_6_existing_atomic_and_sequential_chat_paths_remain_exact` — a regression
  control proving the existing chat paths are untouched.
- `dc7232f` touches exactly two files: this test module and `.tdd-swarm/reports/T-F16b-test.md`.
  No product, migration, or policy artifact. The Test-Agent ownership boundary holds.
- No `skip`, `xfail`, or `TODO` markers. The prior review's `inspect.getsource` finding is gone.
- Ruff check and format check on the module -> exit `0`.
- Durable-fixture pre-validation: `_require_operation_api()` aborts before
  `_running_operation_run`, so the PostgreSQL scaffold is never exercised while RED and could
  otherwise fail for the first time at GREEN. It was therefore executed directly against a
  migrated throwaway database and is sound: the run builds for both cap variants, scope resolves
  `adapter_kind=openemr` / `exact_host=synthetic.invalid`, `RunPolicy` constructs from the
  canonical cap payload, `_clean_control_plane`'s TRUNCATE list is complete, work-unit
  reserve/observe round-trips, and both the replay `RecordConflictError` and the append-only
  immutability trigger reject as intended.

## Whole-suite context at the freeze baseline

`1,697` collected. `51` failed — every one of them this module's intentional RED. No other
module fails. The `16` T-F17b fixture collisions previously reported are resolved and
`tests/test_provider_call_lineage.py` now passes `33/33` in a normal full-suite run.

Note that the `5` setup errors this module showed earlier in the lane worktree were not a T-F16b
defect: the lane carried two alembic revisions both named `0016`, so `migrated_db` could not be
built at all. That is repaired (single head `0018`) and the module now reports a clean
`51 failed, 1 passed`.

## Uncovered criteria

None. Every acceptance criterion in `tickets/T-F16b.md` has at least one covering case, and no
case asserts an implementation detail or encodes a contract that would lock in a defect.

`tests/test_surface_operation_gateway.py` is frozen at the identity above. Implementation agents
must not modify it.
