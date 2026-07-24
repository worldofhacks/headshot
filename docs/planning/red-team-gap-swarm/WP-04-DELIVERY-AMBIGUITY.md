# WP-04 — Prevent ambiguous POST retries and duplicate turns

**Branch:** `rtg/wp04-delivery-ambiguity`

**Model:** capable

**Depends on:** WP-01, WP-03

**Implements toward (live validation pending):** RT-13

Read the adapter error taxonomy, OpenEMR send path, Gateway retry loop, outbound telemetry,
catalog capabilities, and RT-13.

**Implementation writes only**

- `src/agentforge/target/base.py`
- `src/agentforge/target/openemr_adapter.py`
- `src/agentforge/policy/gateway.py`
- `src/agentforge/target/catalog.py`
- `src/agentforge/telemetry/outbound.py`
- `src/agentforge/storage/models.py`
- `src/agentforge/control_plane/store.py`
- `src/agentforge/contracts/v1/errors.json`
- `migrations/versions/<MIGRATION_REV>_delivery_certainty.py`

**Test writes only**

- `tests/test_delivery_ambiguity.py`

## Required result

Replace the broad default `retryable=True` behavior with a closed
delivery-certainty/retry-disposition contract. Unknown and base adapter failures are not
retry-safe.

Distinguish:

- failure proven before request transmission;
- explicit reviewed target rejection such as rate limiting;
- ambiguous write/read timeout or connection loss after possible delivery;
- complete target response;
- non-retryable session/auth failure.

Only proven pre-send failures or an explicitly catalog-authorized rejection may retry. An
ambiguous POST performs exactly one send, atomically persists bounded correlation and
delivery certainty through the control-plane store, and enters the single terminal state
`quarantined_delivery_unknown`. It cannot be returned to a runnable state without a new,
explicit human disposition. Multi-turn delivery never replays an earlier successful turn.
Every permitted retry still uses WP-01 and all caps/accounting.

Do not invent `Idempotency-Key` support. It may be enabled only by a server-owned target
capability bound into authorization and proven by contract tests.

Tests cover DNS/connect failure, write/read timeout, reset after write, malformed response,
generic exception, 429 handling, multi-turn interruption, error subclass confusion,
catalog capability forgery, correlation collision, and secret/prompt-free queue metadata.

**Focused verifier**

```bash
python -m pytest tests/test_delivery_ambiguity.py tests/test_gateway.py tests/test_openemr_adapter.py tests/test_openemr_adapter_chat.py tests/test_outbound_telemetry.py tests/test_migrations.py tests/test_readiness_m1d.py -q
```

**Handoff:** WP-05 uses persisted delivery certainty when deciding whether expired work can
be requeued. Do not implement lease recovery here.
