# Sample incident and postmortem

> **TABLETOP SAMPLE - NOT AN ACTUAL HEADSHOT INCIDENT.** All times are relative, no real campaign,
> person, credential, environment, cost, patient, or deployment is described. This artifact
> demonstrates the incident process required by the canonical brief. Candidate migrations and
> controls named below are locally tested design evidence, not a claim that this scenario occurred or
> that migration `0018` is deployed.

## Incident summary

During a synthetic-only staging campaign, the private Runner is hypothetically terminated after a
target request returns but before the corresponding physical work-unit reservation is marked
observed. At the same time, Langfuse is unavailable. The queue lease later expires.

The safety objective is to avoid replaying an ambiguous physical request, preserve partial evidence,
keep PostgreSQL authoritative, and prevent the console from claiming a completed or remotely observed
execution.

| Field | Sample value |
|---|---|
| Severity | SEV-2 operational integrity event |
| Data classification | Synthetic-only; no real PHI |
| Customer/clinical impact | No clinical system change claimed; campaign progress halted |
| Security impact | One physical coordinate has an ambiguous outcome; duplicate dispatch risk if replayed blindly |
| Detection source | Expired job lease + unobserved reservation + queued/error Langfuse delivery |
| Status | Resolved in the tabletop after containment and reconciliation |

## Relative timeline

| Time | Sample event |
|---|---|
| T+00 | Runner reserves `(run, attempt, turn, retry)` and sends through the Policy Gateway. |
| T+01 | Target returns; the process is terminated before the reservation observer commits. |
| T+02 | PostgreSQL retains the immutable reservation with no terminal observation. Langfuse delivery remains queued/error. |
| T+05 | Lease reaper detects the expired job. The replacement worker refuses to replay the ambiguous coordinate. |
| T+07 | Alert routes the campaign to an operator; new sends and scheduler enqueues are paused. |
| T+12 | Incident owner confirms the target request ledger/evidence boundary and marks the campaign degraded/aborted. |
| T+20 | No duplicate request is issued. Existing evidence and audit identifiers are retained. |
| T+30 | Staging recovery checks pass; a new campaign would require a new nonce and authorization. |

## What worked in the sample

- Migration `0014` gives each physical send an immutable coordinate and permits only one terminal
  observation update.
- An unobserved reservation is treated as ambiguous, not as proof that no request occurred.
- Queue at-least-once delivery does not become blind target at-least-once execution.
- PostgreSQL remains the campaign/evidence authority during the Langfuse outage.
- Migration `0016` prevents an SDK flush from being mislabeled as verified export.
- Migration `0018` separates logical agent execution from append-only physical provider
  invocation/event lineage so unresolved retries cannot be hidden in one logical row.
- Abort preserves completed evidence and blocks publication, remediation, or regression promotion.
- Resuming work requires a fresh run nonce and authorization rather than mutating the old scope.

## Root cause

**Sample root cause:** process termination occurred in the gap between the external target returning
and the database observer recording the terminal outcome. That interval cannot be made atomic with an
external HTTP service by a local database transaction.

**Contributing sample condition:** Langfuse projection lacked a durable outbox/reconciler, so the
observation could not be reconstructed from in-memory handles after the process exited. This is an
observability recovery gap, not evidence loss in PostgreSQL.

## Resolution

The sample incident owner:

1. pauses scheduling and launches;
2. hard-aborts the affected campaign;
3. preserves the reservation, job, request-ledger, agent-execution, and audit identifiers;
4. confirms no later coordinate was sent;
5. keeps Langfuse status queued/error rather than marking it exported;
6. records the outcome as ambiguous/degraded; and
7. requires a new authorized run for any continuation.

## Corrective actions

| Action | Priority | Acceptance criterion |
|---|---|---|
| Add a transactional, safe-metadata Langfuse observation outbox and idempotent private reconciler | High | Runner restart reproduces native parentage/query visibility without raw payload export |
| Alert on unobserved reservations older than the active lease window | High | Alert links exact safe IDs and never triggers automatic replay |
| Add a staged kill-point drill after target return and before observation commit | High | Zero duplicate target sends; campaign ends degraded/aborted |
| Add stable cursor pagination and total counts to audit/trace drill-ins | Medium | Operator can enumerate every contributing execution |
| Define retention/WORM policy for audit and evidence records | Medium | Approved durations and archive restore drill are documented |
| Add a production database backup/restore drill and bind it to every promoted release | High | Restore to an isolated database succeeds and the compatible rollback image passes readiness before promotion |

## Lessons

Exactly-once database writes do not make an external HTTP side effect exactly once. The defensible
behavior is to reserve before sending, make ambiguity visible, and refuse blind replay. Observability
is useful but not authoritative: an outage must degrade visibility without changing evidence,
authorization, or retry semantics.

## Evidence required if this were real

An actual postmortem would attach the exact release/deployment, migration, redacted campaign/job/
reservation/agent/provider-event IDs, queue and lease transitions, request/evidence hashes, Langfuse
query result, alert timestamps, containment approval, and recovery checks. It would never attach
credentials, session values, Langfuse keys, or raw clinical/adversarial bodies.
