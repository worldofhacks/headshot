# Audit, failure drills, and rollback

## Audit reconstruction

PostgreSQL is the authoritative audit and evidence store. A reviewer should be able to reconstruct:

1. the authenticated human launcher and immutable session/Organization attribution;
2. the exact authorization request, scope hash, expiry, nonce, and different Approver decision;
3. target, surface, corpus, configuration, prompt/policy, and release hashes;
4. the queue job, lease, Runner, and physical work-unit reservation;
5. ordered Orchestrator, Red Team, Judge, and Documentation execution rows and parent IDs;
6. each physical target request, attempt/retry coordinate, outcome, latency, and safe hashes;
7. recorder content hash and the Judge's oracle/model decision authority;
8. finding evidence links, approval decision reason, draft report, and regression disposition;
9. provider/model/request identity, supplied token fields, retries, errors, and measured cost; and
10. Langfuse delivery state plus the exact remote query-back timestamp when verified.

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
0021 (head)
```

The packet preparation chain is serialized `0001 -> ... -> 0021`; there is exactly one head.
Migration notes and compatibility references are linked from
[`../../integration/INTEGRATION_PACKET.md`](../../integration/INTEGRATION_PACKET.md).

Staging historically proved `0013 -> 0021` at `2069036e`; production remains at `0013`. The release
target is the incoming revision `0022`, which must be rebased onto the current integration line and
rechecked as the only head. Applying it is a release action and must be bound to the exact final
commit, image digest, staging proof, and compatible rollback image.

## Failure-drill matrix

| Drill | Expected fail-closed behavior | Existing test/control evidence | Final release evidence |
|---|---|---|---|
| Off-allowlist target or near-match host | Zero target dispatch; auditable denial | Policy Gateway/target binding tests | Pending deployed drill |
| Missing, expired, or scope-mismatched authorization | Zero dispatch | Campaign authorization tests | Pending deployed drill |
| Same user launches and approves | Generic 403/database rejection; no authorized run | Auth/control-plane tests; migration `0012` | Pending two-user acceptance |
| Budget/rate/attempt/timeout/physical cap reached | Abort before the next send; preserve completed evidence | Gateway/coordinator tests | Pending final campaign |
| Target/provider rate limit or timeout | Bounded retry/backoff, queue or abort; no synthetic success | Adapter/gateway/hosted-runtime tests | Pending live observation |
| Runner crash after reserving a physical coordinate | Reservation stays ambiguous/unobserved; no blind replay | Migration `0014` and reservation tests | Pending staged crash drill |
| Duplicate job or event | Idempotency/uniqueness prevents duplicate authoritative side effects | Queue/control-plane tests | Pending staged replay drill |
| Evidence hash mismatch | Judge/coverage fail closed; no confirmed/safe state | Recorder/reconciliation/Judge tests | Pending deployed corruption drill |
| Judge model unavailable or calibration not enabled | Deterministic oracles remain decisive; model-only authority disabled/advisory | Judge calibration/hosted lineage checks | Final calibration identity pending |
| Langfuse unavailable or flush succeeds without query-back | PostgreSQL remains authoritative; delivery stays queued/error, never exported | Migration `0016`, verifier tests | Pending exact remote query-back |
| Database is below packaged head | `/ready` fails and private workers do not consume | Readiness/container migration tests | Pending final staging deployment |
| Target session expires mid-run | Abort; no silent refresh/rotation; new scope and approval required | Session lease/runbook controls | Pending live drill |
| Any finding/report publication or remediation | Remains blocked until required different human approval | Finding decision/storage tests | Pending final workflow |

## Pre-deploy rollback binding

Before deploying staging or granting production promotion, record all of the following in the release
evidence:

| Binding | Required value |
|---|---|
| Candidate commit | Exact 40-character Git SHA on both remotes |
| Candidate image | Immutable image digest or Railway deployment artifact identity |
| Current database revision | Exact Alembic revision before migration |
| Target database revision | Exact single Alembic head |
| Rollback deployment | Known-compatible prior Railway deployment ID and commit |
| Rollback schema compatibility | Written confirmation that the prior image tolerates the expanded schema |
| Queue/checkpoint state | Depth, active leases, payload versions, and drain/quiesce result |
| Environment sequence | Staging proof, then production; Runner first, then Web and Scheduler |

No completed final binding is present in this packet. A database-backup artifact is not required for
this synthetic assignment; clean staging migration proof, additive serialized revisions, quiescence,
and compatible image rollback are the release safety controls.

## Containment and rollback procedure

1. Stop new schedules, launches, and configuration changes.
2. Hard-abort unsafe active campaigns; otherwise drain active leases within a bounded window.
3. Preserve redacted audit IDs, active reservation coordinates, queue depth, deployment identity,
   migration revision, and Langfuse delivery status.
4. Confirm the named rollback image is compatible with the already-expanded database.
5. If only the public surface is blank, roll back **Web only** and keep Runner/data intact while
   investigating. For a whole-release failure, roll Web, Runner, and Scheduler to the same
   known-compatible release; do not mix commits.
6. Do **not** automatically downgrade PostgreSQL. Expand/contract compatibility is the primary code
   rollback strategy.
7. Re-run migration identity, `/health`, `/ready`, unauthenticated 401, wrong-scope denial, private
   ingress, queue/lease, and agent/Langfuse delivery checks.
8. Re-enable schedules and launches only after the incident owner records recovery acceptance.

Migration `0008` once introduced a demo self-approval exception; migration `0012` revoked it. A
rollback below `0012` would re-enable an intentionally retired authorization behavior and is
prohibited for a release. See
[`../../integration/migration-notes/0008-godmode-self-approval.md`](../../integration/migration-notes/0008-godmode-self-approval.md).

## Post-rollback validation

Successful process health alone is insufficient. Confirm the release commit, database head,
protected-route behavior, exact authorization denial, private service topology, queue ownership,
evidence integrity, and observation state. Any incomplete reconciliation remains explicitly
degraded/unavailable.
