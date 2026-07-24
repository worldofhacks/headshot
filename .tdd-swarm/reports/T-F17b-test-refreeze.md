# T-F17b Test Re-Freeze

Status: `RE-FROZEN — pending independent code and security review`

The T-F17b test contract changed after its original freeze, so the previous identity no longer
describes the module. This records the new one and exactly why it moved.

## New frozen identity

- Test file: `tests/test_provider_call_lineage.py`
- Test SHA-256: `b854348b68dd667fbb2ce43aa6844c9b94fdd3cb178ff526f36db620ad194f22`
- Git blob: `4a3004dbd020ce74c68ad5b1e148b1719d1b094c`
- Change commit: `77978d9c366d76bfda5b1150eb6f766f5dbf760f`
- Case count: `33` (was `29`)

## Superseded identity

- Test SHA-256: `717ec3e316becc39bf3d5f02cdd1ad6970c3cc6c1f54815b23fa05b20afa8f8b`
- Git blob: `a4f2e3964771a80b5da6bb34fdf7860e2e0a3838`
- Implementation commit: `c29b73ab92dc94c017a8951bc3dab76f23e94604`

That identity was measured on the ticket branch `c29b73a`, whose migration graph no longer exists.
On the merged lane the branch's `0016_provider_call_lineage` collided with
`0016_agent_langfuse_delivery`, alembic reported two heads, and `migrated_db` could not be built at
all — so the original evidence never described the integrated state.

## Why the contract moved

**1. Per-case isolation (infrastructure repair, no assertion changed).**
`migrated_db` is session-scoped (`tests/conftest.py:29`) and `_seed_logical_execution` derives every
identifier from `sha256(f"{organization_id}:{run_id}")[:16]` over two constant defaults, so each
seeding case after the first collided on `pk_campaign_authorization_requests` — 16 of 29 cases
failed in a normal run. The `29/29` was only ever reachable with one database per case.

Added an autouse per-case `TRUNCATE ... RESTART IDENTITY CASCADE`, which is the convention already
used by `tests/test_queue.py:50-57`, rather than migrating a fresh database per case. It is guarded
on `request.fixturenames` so the eight cases that need no database still run without one.

**2. Four new precision cases (contract strengthened).**
`agent_executions.measured_cost` is `NUMERIC(20, 12)` after `0017`, but
`provider_call_events.measured_cost_usd` was `NUMERIC(14, 6)` and `ProviderTerminalEventV1`
quantized to a microdollar. The physical record therefore could not represent a cost the logical
record could. A routine OpenRouter charge of `0.0000391` was rejected outright as "measured cost
exceeds storage precision", and anything below a microdollar rounded to `0.000000` — a fabricated
zero, which the unknown-cost invariant forbids. Sub-microdollar per-call charges are ordinary on the
cheaper roles (Red Team `qwen/qwen3.5-397b-a17b` is $0.39/M input).

Both cost columns, the terminal-contract hash format, and `_COST_QUANTUM`/`_MAX_COST` are now twelve
places, and `test_spec_T_F17b_AC_8_sub_microdollar_cost_is_preserved_not_zeroed` asserts
`0.0000391`, `0.000001234567` and `0.00000078` each survive exactly and never equal zero.

No existing assertion was weakened or removed.

## Verification

- `tests/test_provider_call_lineage.py` -> `33` passed, in a **normal full-suite run**, not in
  isolation and not with a database per case.
- Whole suite -> `1,697` collected, `51` failed, every failure the intentional T-F16b RED.
- `ruff check` and `ruff format --check` -> clean.

## Outstanding

This ticket still needs an **independent code and security review**; none was ever committed for
T-F17b, and this session did not produce one. Two design questions belong in that review:

1. `cost_measurement_state` has a `'not_observed'` server default, so any writer that supplies a
   cost without declaring provenance produces a check-constraint violation. Three fixtures already
   hit this. Either drop the default so it fails loudly as a NOT NULL violation, or extend
   `normalize_agent_execution_unknown_cost` to derive `measured` from a non-NULL cost. The call
   sites were fixed explicitly here rather than deciding this mid-merge.
2. The requested-vs-observed identity conflict recorded in `HANDOFF.md`: `provider_call_events`
   carries `model_mismatch` as a first-class status, while `agent_executions` constrains
   `returned_model = model` and cannot represent the divergence at all.
