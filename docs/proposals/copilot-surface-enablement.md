# Proposal — enable the full Co-Pilot surface set (for the target-catalog owner)

**Companion to PR #27** (`feat(target): full Co-Pilot Bruno surface adapter support`). That PR lands
the adapter/spec/runner *mechanism*; this doc is the *catalog change* that turns it on. It is
delivered **separately** because `config/targets/clinical-copilot-20260724.json` is owned/edited by
the target-authorization workstream — **do not** apply this blindly; reconcile it with the current
file and run that surface's own RED/GREEN + code/security review (per T-F05p AC-3) before enabling.

## What to change

For each of the two targets, (1) add/enable the non-chat surfaces and (2) add a `payload_profiles`
array to the target's `transport_policy`. The runner derives each surface's profile from its
`(relative_path, method, auth_mode)` and requires it to be a member of `payload_profiles`.

### `clinical-copilot-week1` — `transport_policy`
```json
"allowed_methods": ["GET", "POST"],
"allowed_content_types": ["application/json", "text/plain"],
"payload_profiles": ["copilot_public_get", "copilot_evidence_search", "copilot_chat"]
```
Surfaces (all `authentication_required: true`, `enabled: true`):

| surface_id | kind | method | relative_path | derived profile |
|---|---|---|---|---|
| `week1-health` | custom | GET | `health` | `copilot_public_get` |
| `week1-ready` | custom | GET | `ready` | `copilot_public_get` |
| `week1-evidence-search` | rag | POST | `evidence/search` | `copilot_evidence_search` |
| `week1-chat` | chat | POST | `chat` | `copilot_chat` |

### `clinical-copilot-week2` — `transport_policy`
```json
"allowed_methods": ["GET", "POST"],
"write_upload_allowed": true,
"allowed_write_resource_refs": [
  "fixture://clinical-copilot/week2/clean-pdf-20260724",
  "fixture://clinical-copilot/week2/intake-full-valid-pdf-20260724"
],
"response_size_limit_bytes": 10485760,
"allowed_content_types": ["application/json", "text/plain", "application/pdf", "image/png"],
"payload_profiles": [
  "copilot_public_get", "copilot_evidence_search", "copilot_chat",
  "copilot_document_upload", "copilot_document_read"
]
```
Surfaces (all `authentication_required: true`, `enabled: true`):

| surface_id | kind | method | relative_path | derived profile |
|---|---|---|---|---|
| `week2-health` | custom | GET | `health` | `copilot_public_get` |
| `week2-ready` | custom | GET | `ready` | `copilot_public_get` |
| `week2-evidence-search` | rag | POST | `evidence/search` | `copilot_evidence_search` |
| `week2-chat` | chat | POST | `chat` | `copilot_chat` |
| `week2-document-upload` | file | POST | `documents` | `copilot_document_upload` |
| `week2-document-status` | custom | GET | `documents/{document_id}/status` | `copilot_document_read` |
| `week2-document-extraction-report` | custom | GET | `documents/{document_id}/extraction-report` | `copilot_document_read` |
| `week2-document-page-preview` | file | GET | `documents/{document_id}/pages/{page}` | `copilot_document_read` |
| `week2-document-readback` | custom | GET | `documents/{document_id}/readback-verification` | `copilot_document_read` |

## Preconditions for live dispatch (beyond enabling the surface)

- **Upload** (`copilot_document_upload`) requires a synthetic-only fixture resolver injected into the
  runner (`fixture_resolver`) that maps each `allowed_write_resource_refs` entry to
  `(filename, bytes, content_type)`. Absent → fail-closed at the send boundary. Only the two
  synthetic PDFs above are permitted.
- **Document-read** surfaces require the campaign case to supply `path_params`
  (`{"document_id": "<from a prior upload>", "page": "1"}`) in the attempt metadata; the adapter
  substitutes them into the path and refuses any unsafe value.
- Every OWASP mapping, `oracle_refs`, `trust_boundary`, and `risk` must be filled per your catalog
  conventions; each surface still needs `authentication_required: true` to satisfy the registry's
  target↔surface auth invariant (the public GETs send no credential regardless).

## Verification
```
python scripts/validate_target_catalog.py     # loads the catalog through the trusted code path
```
Then, per surface, RED/GREEN adapter test + code review + security review before flipping `enabled`.
