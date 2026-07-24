# Eval-result inventory and evidence boundary

This directory contains retained historical and target-functional artifacts. It does **not** contain
a final-release, frozen 100-case, four-agent, Langfuse-reconciled campaign result. File presence is
not proof that the current release produced or accepted an observation.

| Artifact family | What it records | Accepted use | Not accepted as |
|---|---|---|---|
| `bruno-20260724/` | Credential-scrubbed target functional/regression checks | Historical target behavior and latency context | A Headshot campaign, Judge result, or agent trace |
| `live-campaign-20260724*/` | Historical live-target response/envelope/verdict exports | Dated pre-final target evidence with its own scope caveats | Current durable Runner/Langfuse evidence or authorization |
| `platform-live-run-20260724/` | Nine-case deterministic platform run and continuation artifacts | Historical coordinator/Recorder/oracle evidence | Real Clerk acceptance, hosted four-role execution, frozen 100 evidence, or migration `0018` query-back |

The platform-run summary itself records that the former command bypassed the current durable
agent/Langfuse ledger and must not be rerun. Its distinct-human stand-in is not the real
Operator/Approver workflow. All nine verdicts were `INDETERMINATE`; they are not confirmed exploits
or evidence that the target is safe.

The active authored seeds under `evals/seeds/` remain authoring records with
`execution_status: NOT_EXECUTED`. Ground-truth examples under `evals/ground-truth/` are calibration
labels, not target observations. The security owner's frozen corpus, final Judge evidence,
performance baseline, and reports 004–006 remain on the owner-controlled integration path until its
final commit is reviewed.

A result becomes final-release evidence only when it is bound to the exact release, target/surface,
frozen corpus hash, Judge identity, immutable authorization, and campaign/run IDs; created by the
private durable Runner; persisted and hash-verified in PostgreSQL; and reconciled by exact Langfuse
Cloud query-back. Simulated, scanner-only, stale-schema, hand-rolled, or manually assembled artifacts
remain visibly separate.

Offline admission checks:

```sh
PYTHONPATH=src python -m agentforge.evals validate-corpus evals
PYTHONPATH=src python -m agentforge.evals detect-duplicate-sequence evals/seeds
```
