# WP-19 — Execute continuous, right-reason regressions

**Branch:** `rtg/wp19-continuous-regression`

**Model:** capable

**Depends on:** WP-01, WP-04, WP-05, WP-10, WP-11, WP-14

**Implements toward (live validation pending):** RT-08

Read regression admission/replay/scheduler code and schema, queue recovery, coverage states,
trusted observations, full corpus, and RT-08.

**Implementation writes only**

- `src/agentforge/regression/replay.py`
- `src/agentforge/regression/executor.py`
- `src/agentforge/scheduler.py`
- `src/agentforge/contracts/v1/regression_replay_plan.json`
- `src/agentforge/contracts/v1/regression_replay_result.json`
- `src/agentforge/contracts/v1/regression_reappearance_event.json`
- `src/agentforge/storage/models.py`
- `migrations/versions/<MIGRATION_REV>_regression_execution.py`

**Test writes only**

- `tests/test_regression_execution.py`

## Required result

Implement:

confirmed finding → fresh deterministic reproduction observations → fail-closed admission
→ immutable regression case → trigger-generated blocked plan → distinct human
approval of exact replay scope → fresh attempts through injected governed executor →
required-oracle right-reason comparison → persisted result → internal reappearance event.

The Scheduler creates blocked content-addressed plans only; it has no adapter, credential,
or approval power. Trigger candidates on bounded periodic cadence and changes to target/
surface, release, model/provider, prompt/policy, tool/configuration, corpus, observation/
oracle, dependency, or prior finding state. Coalesce duplicate trigger sets and never
enqueue runnable work. Never reuse old verdicts, transcripts, attempts, observations,
authorizations, or campaign IDs. Every repetition is a fresh physical dispatch bound to
target/surface/release/case/sequence/oracle/baseline/repetition/caps/expiry hashes.

A replay passes only when all required complete trusted WP-11 oracles demonstrate safe
behavior consistently. Exploit states, error, abstention, missing evidence, disagreement,
nondeterminism, or a weaker cross-category baseline cannot pass. Wording similarity is not
right-reason proof.

Persist partial evidence on abort. Jobs must be idempotent, lease-aware, crash-recoverable,
and duplicate-delivery safe under WP-05/WP-04 rules. Emit duration metrics and one internal
reappearance event; it is not publication authority.

Tests cover missing/stale/self-approved authorization with zero calls, all hash drift,
old-result injection, duplicate observations, abort between repetitions, crash/reclaim,
ambiguous delivery, safe wording without oracle proof, exploit reappearance, Judge
indeterminate/error, cross-category worsening, version change during execution, and
concurrent exactly-once result/event. Also cover each trigger, coalescing, periodic bounds,
configuration/oracle drift, and trigger storms with zero unauthorized calls.

Tests validate executor logic only. `regression_replayed`/`regression_protected` requires
WP-21E to run fresh authorized physical attempts against the deployed target with complete
trusted observations, decisive right-reason adjudication, and independently approved live
evidence.

**Focused verifier**

```bash
python -m pytest tests/test_regression_execution.py tests/test_regression_replay.py tests/test_scheduler_regression.py tests/test_runner_lease_recovery.py tests/test_migrations.py tests/test_readiness_m1d.py -q
```

Direct-validate new schemas in this package; WP-19B owns final registry/package parity.

**Handoff:** WP-20A/WP-20B connect the executor to Runner/API and WP-10 replay stages.
