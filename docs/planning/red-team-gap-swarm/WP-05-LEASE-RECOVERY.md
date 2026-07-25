# WP-05 — Recover expired leases without duplicate target traffic

**Branch:** `rtg/wp05-lease-recovery`

**Model:** capable

**Depends on:** WP-01, WP-02, WP-04

**Implements toward (live validation pending):** RT-12

Read the queue lease lifecycle, Runner loop, Scheduler, control-plane campaign states,
persisted delivery certainty, and RT-12.

**Implementation writes only**

- `src/agentforge/storage/queue.py`
- `src/agentforge/control_plane/store.py`
- `src/agentforge/runner.py`
- `src/agentforge/scheduler.py`

**Test writes only**

- `tests/test_runner_lease_recovery.py`

## Required result

Wire a bounded, concurrency-safe expired-lease recovery pass into the private worker
runtime. Use database time and `SKIP LOCKED`; never hold recovery locks while executing
campaign work.

Recovery classification must use authoritative persisted execution profile, physical
dispatch checkpoint, and WP-04 delivery certainty—not mutable job payload or attempts
remaining:

- synthetic no-socket work may be requeued below max attempts;
- every expired live lease defaults to terminal `quarantined_delivery_unknown`, including
  a row whose last checkpoint says pre-dispatch;
- live work may be retried automatically only when a server-owned, authorization-bound
  idempotency contract makes replay safe or an authoritative target receipt proves the
  operation was rejected before acceptance;
- max-attempt work is dead-lettered;
- terminal campaigns are never rewritten;
- dead-letter and campaign-state reconciliation are atomic/idempotent.

Tests must cover two concurrent reapers, crash before send, crash after ambiguous delivery,
heartbeat race, completion race, max attempts, duplicate recovery, stale job payload,
bounded cadence/limit, `--once`, no-claim cycles, failure visibility, and identifier-only
sanitized recovery records. Prove an untrusted pre-dispatch checkpoint never requeues
expired live work.

**Focused verifier**

```bash
python -m pytest tests/test_runner_lease_recovery.py tests/test_queue.py tests/test_runner_campaign.py tests/test_scheduler_regression.py -q
```

**Security focus:** duplicate live sends, forged safe checkpoint, terminal-state rewrite,
starvation, unbounded DB loop, swallowed reaper failure, and cross-worker races.

**Handoff:** WP-19 regression jobs and WP-20A runtime integration must use the same rules.
