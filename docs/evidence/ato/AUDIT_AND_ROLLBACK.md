# Audit, failure drills, and rollback

## Audit reconstruction

PostgreSQL is the authoritative audit and evidence store. A reviewer should be able to reconstruct:

1. the authenticated human launcher and immutable session/Organization attribution;
2. the exact authorization request, scope hash, expiry, nonce, and different Approver decision;
3. target, surface, corpus, configuration, prompt/policy, and release hashes;
4. the queue job, lease, Runner, and physical work-unit reservation;
5. ordered Orchestrator, Red Team, and Judge execution rows and parent IDs, plus Documentation when
   a validated finding triggered a draft;
6. each physical provider invocation/event and target request, attempt/retry coordinate, outcome,
   latency, exact configured/observed endpoint identity, and safe hashes;
7. recorder content hash and the Judge's oracle/model decision authority;
8. finding evidence links, approval decision reason, draft report, and regression disposition;
9. provider/model/request identity, supplied token fields, retries, errors, and measured cost; and
10. Langfuse role/physical delivery state plus the exact remote query-back timestamp when verified.

The durable IDs and hashes may be retained in redacted evidence. Bearer tokens, target sessions,
provider keys, Langfuse keys, raw hostile transcripts, and real or synthetic clinical bodies must not
appear in release transcripts.

Audit-event cursors and campaign events are append-only. Agent/request lifecycle rows have constrained
one-way terminal transitions; they are not optimistic UI state. Retention duration and an external
WORM/archive policy are **not specified in this source snapshot** and remain a production hardening
item.

## Migration audit

The inspected source graph was checked with:

```text
python -m alembic heads
0018 (head)
```

The chain is serialized `0001 -> ... -> 0018`; there is exactly one head. Migration notes through
`0017` are indexed by
[`../../integration/INTEGRATION_PACKET.md`](../../integration/INTEGRATION_PACKET.md), and the
`0018` physical provider-call correction is documented in
[`../../integration/migrations/provider-call-lineage-v1.md`](../../integration/migrations/provider-call-lineage-v1.md).

The current live review records deployment only through `0013`. Applying `0014`-`0018` in staging is
a release action and must be bound to the exact final commit, backup/recovery posture, and compatible
rollback image.

## Failure-drill matrix

| Drill | Expected fail-closed behavior | Existing test/control evidence | Final release evidence |
|---|---|---|---|
| Off-allowlist target or near-match host | Zero target dispatch; auditable denial | Policy Gateway/target binding tests | Deployed drill unavailable |
| Missing, expired, or scope-mismatched authorization | Zero dispatch | Campaign authorization tests | Deployed drill unavailable |
| Same user launches and approves | Generic 403/database rejection; no authorized run | Auth/control-plane tests; migration `0012` | Two-user acceptance unavailable |
| Budget/rate/attempt/timeout/physical cap reached | Abort before the next send; preserve completed evidence | Gateway/coordinator tests | Final campaign unavailable |
| Target/provider rate limit or timeout | Bounded retry/backoff, queue or abort; no synthetic success | Adapter/gateway/hosted-runtime tests | Live observation unavailable |
| Runner crash after reserving a physical coordinate | Reservation stays ambiguous/unobserved; no blind replay | Migration `0014` and reservation tests | Staged crash drill unavailable |
| Duplicate job or event | Idempotency/uniqueness prevents duplicate authoritative side effects | Queue/control-plane tests | Staged replay drill unavailable |
| Evidence hash mismatch | Judge/coverage fail closed; no confirmed/safe state | Recorder/reconciliation/Judge tests | Deployed corruption drill unavailable |
| Provider route/model substitution or physical retry drift | Fail closed; preserve exact configured/observed identity and unresolved call state | Migration `0018`, hosted transport/lineage tests | Staged provider evidence unavailable |
| Judge model unavailable or identity-drifted | Deterministic oracles remain decisive; model-only authority disabled/advisory | Judge calibration/hosted lineage checks | Exact-route human enablement unavailable |
| Langfuse unavailable or flush succeeds without query-back | PostgreSQL remains authoritative; delivery stays queued/error, never exported | Migration `0016`/`0018`, verifier tests | Exact remote query-back unavailable |
| Database is below packaged head | `/ready` fails and private workers do not consume | Readiness/container migration tests | Final staging deployment unavailable |
| Target session expires mid-run | Abort; no silent refresh/rotation; new scope and approval required | Session lease/runbook controls | Live drill unavailable |
| Critical finding publication/remediation | Remains blocked until required different human approval | Finding decision/storage tests | Final workflow unavailable |

## Pre-deploy rollback binding

Staging deployment must at minimum bind the candidate/image, current and target revisions, compatible
application rollback, and queue state before migration. Production promotion requires **every** field
below, including a confirmed database recovery point and named human grant:

| Binding | Required value |
|---|---|
| Candidate commit | Exact 40-character Git SHA on both remotes |
| Candidate image | Immutable image digest or Railway deployment artifact identity |
| Current database revision | Exact Alembic revision before migration |
| Target database revision | Exact single Alembic head |
| Rollback deployment | Known-compatible prior Railway deployment ID and commit |
| Rollback schema compatibility | Written confirmation that the prior image tolerates the expanded schema |
| Database recovery | Confirmed backup/PITR point and restore procedure |
| Queue/checkpoint state | Depth, active leases, payload versions, and drain/quiesce result |
| Human grant | Named approval for production deployment; no self-promotion |

No completed final binding is present in this packet. Railway retains application deployment
rollback history, but production currently has no confirmed database backup schedule/recovery point
or tested restore binding, and no human deploy grant has been issued. Those are independent hard
blockers: an application rollback entry is not a database rollback. Production promotion remains
blocked.

## Containment and rollback procedure

1. Stop new schedules, launches, and configuration changes.
2. Hard-abort unsafe active campaigns; otherwise drain active leases within a bounded window.
3. Preserve redacted audit IDs, active reservation coordinates, queue depth, deployment identity,
   migration revision, and Langfuse delivery status.
4. Confirm the named rollback image is compatible with the already-expanded database.
5. Roll Web, Runner, and Scheduler back to the same known-compatible release; do not mix commits.
6. Do **not** automatically downgrade PostgreSQL. Expand/contract compatibility is the primary code
   rollback strategy.
7. If data restoration is necessary, restore the confirmed PITR/backup into a new isolated database,
   validate it, then explicitly rebind services. Never overwrite the only copy first.
8. Re-run migration identity, `/health`, `/ready`, unauthenticated 401, wrong-scope denial, private
   ingress, queue/lease, exact provider identity/physical lineage, and agent/Langfuse query-back
   checks.
9. Re-enable schedules and launches only after the incident owner records recovery acceptance.

Migration `0008` once introduced a demo self-approval exception; migration `0012` revoked it. A
rollback below `0012` would re-enable an intentionally retired authorization behavior and is
prohibited for a release. See
[`../../integration/migration-notes/0008-godmode-self-approval.md`](../../integration/migration-notes/0008-godmode-self-approval.md).

## Post-rollback validation

Successful process health alone is insufficient. Confirm the release commit, database head,
protected-route behavior, exact authorization denial, private service topology, queue ownership,
evidence integrity, physical provider lineage, and observation state. Any incomplete reconciliation
remains explicitly degraded/unavailable.
