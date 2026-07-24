---
id: T-F05e
title: Define and project the canonical SMART session lease context
status: backlog
wave: 10
depends_on: [T-F05a, T-F05d, T-F05h, T-F05i, T-F05p]
branch: ticket/T-F05e-smart-session-lease-context
file_scopes:
  - src/agentforge/contracts/registry.py
  - src/agentforge/contracts/v1/smart_session_lease_context.json
  - contracts/v1/smart_session_lease_context.json
  - src/agentforge/policy/smart_session_lease.py
  - scripts/project_smart_session_lease_context.py
test_scopes: [tests/test_smart_session_lease_context.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, scoped credentials, and synthetic-only data
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34, USR-04, USR-07, LEAD-09
  - .tdd-swarm/reports/session-binding-readiness.md SB-001, SB-002, SB-003
  - .tdd-swarm/reports/session-lease-scope-review.md C1, I1, I2, I3
---

## Context
[locked-decision] This ticket owns one immutable, strict, secret-free
`SmartSessionLeaseContext/v1`, its canonical serializer/validator, raw-identifier shape validator,
and projection API/CLI. It consumes T-F05h and T-F05i immutable authenticated producer artifacts,
never a caller-composed combined rotation document. The context pins campaign identity, policy, and
source trust bindings but never pins an ephemeral observation time/hash/count/abort/drain state.
T-F05m, T-F05f, and T-F05c import the same immutable-context and fresh-state validators; no mirror
parser is allowed. T-F05m is the sole production composer of fresh T-F05l/T-F05h and T-F05i
observations. Canonical `SmartSessionLeaseMetadata/v1` remains a create-only secret-free projection
from the private provisioning boundary, where the value digest is derived without exporting the value.

## Acceptance Criteria
- **AC-1**: Schema URI `agentforge.smart-session-lease-context`, `schema_version:1`, rejects duplicate/unknown/missing fields. Accepted files are RFC 8785 canonical UTF-8 JSON with no BOM or trailing newline; `context_sha256` is the lowercase SHA-256 of the exact detached bytes and is not a self-field. The timestamp lexical language is exactly 20 ASCII bytes `YYYY-MM-DDTHH:MM:SSZ` with fixed digit/separator positions and a semantically valid Gregorian whole-second UTC instant. Python 3.12 uses `re.fullmatch(r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z", value, flags=re.ASCII)` plus semantic validation. JSON Schema uses portable pattern `^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$` with `minLength:20`, `maxLength:20`; fractions, leap seconds, offsets, case changes, whitespace/control characters, prefixes/suffixes, and terminal CR/LF fail.
- **AC-2**: The credential reference is exactly `secretref://staging/<adapter-kind>/session/<generation>`. Adapter kind is 2..32 ASCII characters, first `[a-z]`, remainder `[a-z0-9-]`; generation is 1..64 ASCII characters, first `[a-z0-9]`, remainder `[a-z0-9._-]`. Python 3.12 uses `re.fullmatch` bodies `r"[a-z][a-z0-9-]{1,31}"` and `r"[a-z0-9][a-z0-9._-]{0,63}"` with `re.ASCII`. Portable JSON Schema uses the corresponding `^...$` patterns, exact min/max lengths, and a separate rejection of `U+0000..U+001F` and `U+007F`, so terminal CR/LF cannot exploit end-anchor behavior. Userinfo/query/fragment/port/percent encoding/dot or empty segments fail; trusted code derives `credential_reference_sha256` from exact UTF-8 bytes.
- **AC-3**: Immutable binding contains generation, canonical lease times, lowercase `value_sha256`, exact staging target ID/version/surface ID/version/adapter/HTTPS host/port/POST relative path/session auth, the exact complete T-F05d tuple, and release binding `(release_sha, deployment_manifest_sha256, deployment_generation_id)`. Release SHA is exactly 40 lowercase hexadecimal characters and SHA-256 values are 64. Target facts come only from T-F05p's tracked catalog/hash and must select exactly one of its two targets, one enabled chat surface, one credential generation, and the T-F05d patient/context identity; the context pins that target/session/patient tuple. Persisted grant, lease metadata, and reviewed deployment manifest supply the remaining values; one-field substitution or target/session/patient switching fails.
- **AC-4**: Runner-only `AGENTFORGE_SMART_SESSION_MAX_LIFETIME_SECONDS` is mandatory at provision/startup, has no code/example default, and accepts only an ASCII base-10 integer in `[60,3600]`. The immutable policy is exactly `{schema:"agentforge.smart-session-lease-policy",schema_version:1,max_lifetime_seconds:<n>,clock_skew_seconds:5,release_sha:<sha>,deployment_manifest_sha256:<sha>}`. `policy_sha256` is `SHA-256(UTF8("agentforge.smart-session-lease-policy/v1") || 0x00 || RFC8785(policy))`; grants/metadata cannot expand or replace it.
- **AC-5**: The fixed code-owned conservative clock margin is exactly 5 seconds: `now - 5s >= not_before`, `now + 5s < expires_at`, `expires_at - not_before <= max_lifetime_seconds`, and expiry strictly exceeds `min(grant expiry, Runner start + authorized timeout)`. Early/equal/expired/overlong/far-future or invalid-clock input fails closed.
- **AC-6**: Immutable `state_authority_binding` contains only T-F05h/T-F05i schema IDs/versions, deployment-controller ID and trust-root SHA-256, control-projector trust-root SHA-256, workload-database identity SHA-256, environment, release SHA, deployment-manifest SHA-256, and deployment generation ID. It contains no source `observed_at`, source artifact hash, active/stopped ID list, count, admission, drain, abort, snapshot, or no-overlap result. The context can remain pinned for its full lifetime while fresh observations change.
- **AC-7**: `validate_fresh_runner_state_for_context(context, deployment_artifact, control_artifact, now, current_claim)` imports T-F05h/T-F05i validators, reparses canonical bytes, recomputes both digests, re-verifies attestations/trust, and requires matching environment/release/manifest/generation/database identity and source age `0..30` seconds. Production callers obtain the pair only through T-F05m, which first acquires a fresh signed envelope through T-F05l; the validator itself accepts no source path/channel override. Deployment state must show the one context generation, disabled Web launch, zero/disabled Scheduler, and stopped predecessors. `current_claim` is either `None` or a non-serializable trusted binding constructed from the just-acquired queue record `(campaign_run_id, job_id, worker_id, lease_token_sha256)`, never a CLI/artifact field. With `None` (context projection/public preflight), active campaigns and live leases must both be zero. With a claim, live leases must be exactly that job/worker/lease binding, active campaigns may contain only that campaign, and its persisted abort state must be non-aborted; any other campaign/lease or any hard abort fails. Source disagreement, mixed snapshot, false no-overlap, or a caller-authored combined object fails.
- **AC-8**: `validate_smart_session_lease_context` and `validate_fresh_runner_state_for_context` are the sole validators; `project_smart_session_lease_context` is the sole typed producer. The exact command is `python scripts/project_smart_session_lease_context.py --lease-metadata <LEASE_METADATA> --authorization docs/evidence/authorizations/campaign.json --catalog config/targets/clinical-copilot-20260724.json --target-session-fixture-manifest <TARGET_SESSION_FIXTURE_MANIFEST> --deployment-manifest <CURRENT_DEPLOYMENT_MANIFEST> --runner-deployment-state <RUNNER_DEPLOYMENT_STATE> --runner-control-state <RUNNER_CONTROL_STATE> --output-root docs/evidence/lease-contexts`. It authenticates/recomputes the fixed T-F05p catalog and two fresh artifacts with `current_claim=None` before creating without replacement the sole `<release_sha>/<generation>/smart-session-lease-context.v1.json` plus exact detached digest. Alternate/inline catalog, combined-state, serialized/current-claim, trust override, raw-value/value-file/stdin, arbitrary output, and overwrite options are rejected; exits are `0`, `2`, or `4`.
- **AC-9**: Stable failures are `lease-context-schema-invalid`, `lease-context-noncanonical`, `lease-context-reference-invalid`, `lease-context-time-invalid`, `lease-context-policy-invalid`, `lease-context-binding-mismatch`, `lease-context-source-stale`, `lease-context-source-untrusted`, and `lease-context-secret-input-refused`. The raw-value validator accepts inclusively 16..2048 strict UTF-8 bytes and rejects invalid UTF-8; ASCII `0x00..0x20`, `0x7f`, `"`, `,`, `:`, `;`, `=`, `\`; every Unicode separator/control/format/surrogate/private-use/unassigned code point; and case-insensitive leading `sid=` or `Cookie:`. It never strips, normalizes, rewrites, or includes the value in errors/repr/logs.

## Test Plan
- Unit (deterministic): schema/canonical bytes/duplicates; Python 3.12 fullmatch and portable-schema timestamp/reference grammars including terminal CR/LF; fixed skew/policy/domain/release/fixture/immutable-authority binding; raw byte/shape boundaries.
- Integration (deterministic): exact projection CLI/create-only output, authenticated T-F05h/T-F05i artifact digest recomputation, every trust/release/generation/freshness/no-overlap mutation, absence of a combined-state input, and proof raw-value inputs are impossible.
- Eval/E2E: none; injected clocks and synthetic signed/fake-read-only producer artifacts only, with all network hooks forbidden.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged clean RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05e.md <DIFF_BASE>` exits 0.
- [ ] Root/package schema bytes match and both sole validators/projection interface are importable by later consumers.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No context delivery/job field, resolver call, raw value acquisition/digest derivation, Runner
dispatch, deployment/configuration edit, live source observation, Railway action, network, or spend.
