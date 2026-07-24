# Proposal — stage the full Co-Pilot surface contract

This is the separately reviewable catalog-owner companion to the T-F16a surface-policy contract
and the Co-Pilot adapter mechanism. It does **not** modify
`config/targets/clinical-copilot-20260724.json`, authorize a campaign, or enable a live surface.
Apply it only through the target-authorization workstream with that surface's own RED/GREEN,
code/security review, and independent human approval.

## Canonical catalog shape

Do not add a target-wide `payload_profiles` array. T-F16a intentionally rejects that ambiguous
shape. Instead:

1. Preserve each immutable `1.0.0` entry as rollback and audit history. Its additional staged
   surfaces remain disabled; the legacy target-wide policy permits only one enabled surface.
2. Stage new target and surface definitions at `2.0.0`.
3. Put one complete `surface_policy` plus its canonical `surface_policy_sha256` on every v2
   surface, and omit the legacy target-wide `transport_policy`.
4. Bind the exact policy bytes and digest into every new authorization scope. A v1 approval cannot
   authorize a v2 surface.
5. Keep every document workflow disabled at `2.0.0`. Stage document workflows at `2.1.0` only
   after the private fixture binding and physical-operation gateway pass their bounded proofs.

The exact fields and rollout/rollback rules are in
`docs/migrations/final-target-surface-policy-v2.md`.

## Surface-to-adapter composition

The reviewed policy uses one logical policy per surface. The adapter exposes the smaller physical
request-shaping profiles shown below. A physical-operation gateway must select a profile from the
authorized operation template; a path heuristic or mutable environment setting is not authority.

| Logical policy | Authorized operation | Exact route | Physical adapter profile |
|---|---|---|---|
| `copilot_chat` | `chat` | `POST chat` | `copilot_chat` |
| `copilot_evidence_search` | `evidence_search` | `POST evidence/search` | `copilot_evidence_search` |
| `copilot_document_workflow` | `upload`, `duplicate_check` | `POST documents` | `copilot_document_upload` |
| `copilot_document_workflow` | `status_poll` | `GET documents/{document_id}/status` | `copilot_document_read` |
| `copilot_document_workflow` | `report` | `GET documents/{document_id}/extraction-report` | `copilot_document_read` |
| `copilot_document_workflow` | `preview` | `GET documents/{document_id}/pages/{page}` | `copilot_document_read` |
| `copilot_document_workflow` | `readback` | `GET documents/{document_id}/readback-verification` | `copilot_document_read` |

The v2 UI-shell policies remain session-bound (`GET app` for Week 1 and `GET week2` for Week 2,
with `sid` in the query). The current adapter's `copilot_public_get` profile is deliberately
credential-free and covers only `health`/`ready`; it must not be used for those authenticated UI
surfaces. Do not register or enable `health`/`ready` under T-F16a until a separate reviewed policy
extension defines their explicit no-auth contract.

## Versioned activation set

At `2.0.0`, stage chat, UI, and anonymous evidence surfaces for both
`clinical-copilot-week1` and `clinical-copilot-week2`. Each definition must carry the exact
authentication facts, operation template, retry-inclusive limits, response types, and policy hash.
Only surfaces that have completed their separate authorization and review may be enabled.

At `2.1.0`, stage two disabled document workflow surfaces for Week 2:

- the clean/lab workflow: one upload, bounded status polling, extraction report, page preview, and
  readback verification;
- the full/intake workflow: one upload plus one duplicate-check upload.

Each workflow must carry one complete private synthetic fixture descriptor
(`opaque_ref`, SHA-256, byte length, media type, document type, and workflow ID). No path, URL,
credential, or fixture bytes belong in the catalog.

## Preconditions before any live enablement

- Land the physical-operation gateway that consumes the exact authorized `surface_policy`.
  The current legacy Runner reads `transport_policy`; therefore a v2 catalog entry must remain
  non-dispatchable until that bridge is merged and reviewed.
- Resolve fixture bytes only through a private Runner binding, then verify all descriptor fields
  before constructing a request. A missing/mismatched fixture fails closed without a target call.
- Derive `document_id` and `page` only from prior authorized workflow results. The adapter rejects
  missing or unsafe path parameters.
- Enforce `maximum_logical_operations` and retry-inclusive `physical_request_limit` from the
  approved policy. Upload and duplicate-check operations are never retried.
- Preserve exact host allowlisting, synthetic-data attestation, budget/rate/timeout caps, abort
  controls, and the distinct launcher/approver invariant.
- Recompute and independently approve every `surface_policy_sha256`; never copy a v1 approval or
  mutate a previously approved version.

## Offline verification

```console
python scripts/validate_target_catalog.py
pytest -q tests/test_final_target_surface_policy.py \
  tests/test_openemr_adapter_surfaces.py \
  tests/target/test_relative_path_parameters.py
```

These checks are network-free. Catalog-owner and security review remain required before any
surface changes from disabled to enabled.

## Integration review delta

The source T-F16a review completed at `cda81d8`. This composition additionally aligns the document
operation templates with the adapter's reviewed Bruno routes, permits extra legacy surfaces only
while they remain disabled, and makes the legacy Runner refuse v2 dispatch until the separate
physical-operation gateway exists. Those integration deltas require fresh review before merge.
The adapter implementation from `acbe17d` is already present on the integration base (with later
hardening); replaying its older file snapshots is intentionally not part of this change.
