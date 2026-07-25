# WP-17 — API discovery, principal matrix, and governed ZAP profiles

**Branch:** `rtg/wp17-api-auth-zap`

**Model:** capable

**Depends on:** WP-01, WP-03, WP-12, WP-16A, WP-16B, WP-16D

**Implements toward (live validation pending):** Scanner/API/authentication portions of RT-06

**Implementation writes only**

- `src/agentforge/security_tools/api_schema.py`
- `src/agentforge/security_tools/api_discovery.py`
- `src/agentforge/security_tools/discovery_limits.py`
- `src/agentforge/security_tools/site_map.py`
- `src/agentforge/security_tools/auth_matrix.py`
- `src/agentforge/security_tools/auth_workflow.py`
- `src/agentforge/security_tools/zap.py`
- `src/agentforge/security_tools/zap_profiles.py`
- `src/agentforge/security_tools/scan_egress.py`
- `security-tools/zap/**`
- `security-tools/zap/coverage.v1.json`
- `src/agentforge/contracts/v1/api_surface_manifest.json`
- `src/agentforge/contracts/v1/principal_matrix_plan.json`
- `src/agentforge/contracts/v1/auth_workflow.json`
- `src/agentforge/contracts/v1/site_map.json`
- `src/agentforge/contracts/v1/zap_scan_plan.json`
- `pyproject.toml` only to declare a reviewed pinned safe YAML parser already exercised by
  the development environment

**Test writes only**

- `tests/security_tools/test_api_discovery.py`
- `tests/security_tools/test_auth_matrix.py`
- `tests/security_tools/test_auth_workflow.py`
- `tests/security_tools/test_site_map.py`
- `tests/security_tools/test_zap_profiles.py`
- `tests/security_tools/test_scan_egress.py`
- `tests/security_tools/test_zap_local_process.py`
- `tests/vectors/api_discovery/**`
- `tests/vectors/zap_profiles/**`

## Required result

### API contract ingestion and live discovery boundary

Import bounded OpenAPI 3.0/3.1 JSON/YAML, Postman 2.1 JSON, GraphQL SDL, and saved
introspection JSON. Never fetch a schema or execute Postman scripts/auth/helpers/code/
variables. Reject external/file/network `$ref`, custom YAML tags, alias/recursive bombs,
excessive depth/size/operations, duplicate IDs, invalid encoding, and path escapes.

Ignore document `servers` as authority. Bind output to an existing target/version and
produce content-addressed operations, schemas, security requirements, streaming hints,
surface diffs, and typed payload positions. Imported surfaces remain disabled pending
review/catalog registration and new authorization.

Ingest bounded classic/AJAX crawl artifacts into a reusable, organization-scoped site map
of observed origins, routes, methods, forms, parameters, content types, auth state,
referrers, and first/last artifact hashes. “Observed” never means authorized or safe.
Forms/actions stay disabled until reviewed; cross-origin discoveries are recorded as
blocked edges, never followed.

Imported or saved contracts/crawls validate parsing and planning only. A surface/site-map
claim becomes current and live only when WP-21D binds an owner-provided current contract
and a fresh authorized crawl of the exact deployed target to the same release/surface
identity.

### Provisioned live principal/access matrix

Opaque secret-reference profiles only. Live evidence uses provisioned test principals and
seeded synthetic non-PHI live object namespaces. Cover unauthenticated, own object,
peer/same-role, lower/higher role, cross-tenant, expired/revoked, rotation, fixation,
logout, BOLA, BFLA, forced browsing, and privilege crossing. Expected access is explicit
per cell. Missing instrumentation or a missing live principal is `INDETERMINATE`/blocked,
never simulated.

Provide declarative, same-origin authentication/session workflows using typed navigation,
form fields, fixed-selector/JSON-pointer extraction, CSRF refresh, verification, logout,
rotation, revocation, and expiry steps. Secrets resolve ephemerally inside controlled
egress and never appear in plans, argv, YAML, captures, or artifacts. No scripts, arbitrary
selectors/regex, IdP scanning, MFA bypass, or CAPTCHA bypass.

### ZAP profiles

Create pinned Automation Framework plans for API import, passive baseline, authenticated
classic/AJAX crawl, passive scan, and separately authorized active rules. Active,
authenticated, and live profiles default disabled.

Maintain a pinned rule/capability matrix, with `configured`, `unsupported`, or
`blocked_missing_surface` evidence for relevant OWASP Web and Burp-scanner classes:
injection (SQL/NoSQL/LDAP/command/template), reflected/stored/DOM XSS, path/file traversal,
SSRF, XXE, unsafe deserialization, HTTP parsing/request smuggling and HTTP/2 downgrade,
Host/header/cache poisoning, CORS/CSRF/clickjacking, open redirect, upload/download,
information disclosure, session/auth/access control, and bounded resource/rate behavior.
Never claim a class from a generic active profile or invent a ZAP rule ID. Low-level
protocol probes must be fixed reviewed templates, exact-surface compatible, synthetic,
and routed through the same pin/permit/accounting boundary.

Authorization binds origin/paths/methods, principal profiles, API manifest, ZAP image/
add-on/rule hashes, caps/time, callback domains, output schema/version, artifact
destination, nonce, and output byte/record caps. Artifact hashes are computed and bound
only after execution; do not require an unknowable pre-run output hash. Deny identity-provider,
metadata/private/link-local, non-target, destructive, logout, and unregistered origins.
Credentials remain ephemeral and absent from argv/YAML/artifacts/logs.

Every ZAP physical request must ultimately receive a fresh WP-01 permit through controlled
WP-16D egress; if scanner/permit/send ledger parity cannot be guaranteed, active scanning
remains disabled. Live eligibility requires WP-21D to execute the exact pinned ZAP
image/process in the deployed private runtime against the exact owner-authorized deployed
target, with process isolation, abort/cap observations, and one-to-one scanner-operation,
permit, physical-send, and ledger proof. If the image/process, authorization, live surface,
or live principal matrix is unavailable, keep `blocked_live_zap_evidence`. ZAP results are
advisory.

Tests use non-PHI parser/contract vectors and cover malicious YAML/refs/scripts, GraphQL
cycles, cross-origin crawl, redirects/DNS changes, credential leakage, auth expiry/abort,
session fixation/rotation/logout, site-map poisoning, unsafe forms, cap races, config/
filename injection, active-rule escalation, artifact tampering, and scanner/ledger equality.
Also test rule-matrix drift, false “configured” states, HTTP/1.1 versus HTTP/2 ambiguity,
and unsupported classes. Direct-validate new schemas; WP-19B owns final registry/package
parity. These tests are implementation prechecks only; no saved schema, fixture, mock,
local process, loopback site, or fake target can establish live discovery, auth-matrix, or
scanner status.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_api_discovery.py tests/security_tools/test_auth_matrix.py tests/security_tools/test_auth_workflow.py tests/security_tools/test_site_map.py tests/security_tools/test_zap_profiles.py tests/security_tools/test_scan_egress.py tests/security_tools/test_zap_local_process.py -q
```

No external network, image pull, package install, or live target scan in this package. Keep
all API/auth/ZAP capability states `LIVE_EVIDENCE_REQUIRED` until WP-21D produces
independently approved deployed evidence.
