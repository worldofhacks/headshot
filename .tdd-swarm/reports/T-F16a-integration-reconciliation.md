# T-F16a Integration Reconciliation

Status: `REVIEW_REQUIRED`

This record supersedes the four source-lane reports' use of the word “current” for PR #34. It does
not rewrite or invalidate their historical freeze. It records the deliberate composition delta that
must receive a fresh, exact-head catalog/security review before merge.

## Integration identity

- Post-documentation base: `802a63a1880dfd732584a9e246d3401e967cfaa7`
- Base-reconciliation merge commit: `ec77a1d9a9f7363d1fd4a61c2938845212cd916e`
- Source frozen test blob: `af6df0ff25e4e53aa0b6aca691d6494ff1d1e501`
- Source frozen SHA-256:
  `fdf129e50018a13d7e69e74d9eb9f08821daba1312dc5bf84d7492583890145e`
- Composed test blob: `6afe831b2be9272695333d3690a43b0aa691eebc`
- Composed SHA-256:
  `5b21a586f996767cee644ded255043fb9ca5428186fa8f2f784e7efe2e60a10c`
- Composed focused count: `111` tests, all passing locally

## Exact test delta

The composed blob is 88 insertions and 5 deletions beyond the frozen source blob:

1. Document report retrieval is
   `GET documents/{document_id}/extraction-report`, not
   `GET documents/{document_id}/report`.
2. Page retrieval is `GET documents/{document_id}/pages/{page}`, not
   `GET documents/{document_id}/preview`.
3. Readback verification is
   `GET documents/{document_id}/readback-verification` with an
   `application/json` response, not `GET documents/{document_id}` returning a PDF.
4. A 104th test proves a legacy target-wide policy may retain additional staged surfaces only while
   they remain disabled; enabling a second surface fails closed.
5. Three collected cases prove enabled document workflows cannot bypass the exact
   `2.0.0 -> 2.1.0` activation set by using `2.0.1`, `2.2.0`, or `3.0.0`.
6. Three collected cases keep the target at a valid activation while proving surface versions
   `1.0.0`, `2.0.1`, and `3.0.0` cannot be substituted.
7. An explicit staged-activation control rejects enabled documents at `2.0.0` and accepts the
   canonical enabled candidate at `2.1.0`.

These are integration corrections against the retained Bruno route evidence. They are not
independently approved merely because this record or a green test exists.

## Additional integration safety delta

- `CatalogEntry` admits only the exact reviewed `2.0.0` and `2.1.0` targets, with every surface
  version equal to its target version. Later patch, minor, major, and mixed-version definitions
  require a new reviewed activation set.
- A Runner preflight regression persists a real v2 catalog and matching authorization scope, then
  proves `surface_policy_dispatch_not_integrated` is the sole blocker before credential lease,
  prepared execution, or adapter construction. Fixture resolution, destination validation, and
  target-call paths are therefore unreachable.
- The tracked staging and production catalogs remain unchanged and chat-only: staging SHA-256
  `399e75626a5d6e268dcb9fbcc161643edb92b7980fb305c948ea020181613ce9` and production
  SHA-256 `ab14bf118d3d44e6022fa01550668063483ee5e0d15b7f30c4c708a16a925467`.
  No v2 definition is deployed or enabled by this PR.
- Trusted catalog loading uses the canonical nested `surface_policy` deserializer; browser-authored
  nested policy remains intentionally forbidden. Activation is still blocked by the absence of a
  reviewed tracked v2 catalog, physical-operation gateway/private fixture composition, and the
  required catalog, security, and human approvals.

## Exact-head review gate

Before PR #34 may merge, an independent catalog-owner review must identify the final head SHA and
attest that it reviewed:

- the source-to-composed blob transition above;
- the corrected routes, methods, content types, credential placement, retry bounds, and descriptor
  identities;
- the resolved `CatalogEntry` conflict and the unchanged registration/idempotency behavior;
- unchanged tracked catalog/configuration bytes, chat-only current enablement, and inert v2
  proposals; and
- the evidence limitations for unexercised UI routes and unserialized document-upload credential
  placement.

A distinct security approval is also required unless the designated catalog owner is explicitly the
security owner. It must attest that v2 has no target-call path, no legacy fallback or path heuristic,
and remains blocked by `surface_policy_dispatch_not_integrated` until the separately reviewed
physical operation gateway lands.
