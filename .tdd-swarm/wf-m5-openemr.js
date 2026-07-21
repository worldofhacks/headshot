export const meta = {
  name: 'm5-openemr-adapter',
  description: 'M5: OpenEMR TargetAdapter behind the Policy Gateway + a fail-closed, NETWORK-FREE activation preflight (HTTPS + exact-host allowlist + auth-mode + exact creds + no-conflict + synthetic + canary + typed errors + no fake fallback). No target request in tests/preflight. TDD + reviewer + security.',
  phases: [
    { title: 'Tests', detail: 'RED: adapter contract + fail-closed preflight (no network)' },
    { title: 'Implement', detail: 'GREEN: target/openemr_adapter.py + preflight.py' },
    { title: 'Review', detail: 'reviewer ∥ security' },
  ],
}

const REPO = '/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine'
const SPEC = `
REPO (main repo): ${REPO}   BRANCH: ticket/m5-openemr-adapter (off swarm/mvp-live-gate; has M2/M4/M6a/M9 + M11
corpus + packaged schemas). venv at ${REPO}/.venv — activate for EVERY command:
  \`cd "${REPO}" && . .venv/bin/activate && <cmd>\`. Python 3.12; Postgres 16 UP. DO NOT git commit/push.
Gates: \`ruff check .\`, \`ruff format --check .\`, \`python -m pytest -q\`.

WHAT M5 DELIVERS — the OpenEMR live TargetAdapter (target #1 ONLY) + a fail-closed ACTIVATION PREFLIGHT.
ARCHITECTURE §2/§5, D14/D16; PRD-01. Deps P9✓ (TargetAdapter interface), M4✓ (gateway/allowlist/credentials),
D1 (deployed URL — NOT provided; stays empty). Read src/agentforge/target/base.py (TargetAdapter interface +
typed AdapterError taxonomy), src/agentforge/target/fake_adapter.py (P9), src/agentforge/config.py
(resolve_target_credential — O1: production-only), src/agentforge/secrets.py (Secret), and
src/agentforge/policy/{gateway,allowlist,credentials}.py (M4 — the adapter is reached ONLY through the gateway).

**ABSOLUTE CONSTRAINT: NO TARGET/NETWORK REQUEST IN ANY TEST OR IN PREFLIGHT.** Preflight is pure config
validation. The adapter's send() would make an HTTPS call in a real authorized campaign, but it is NEVER
invoked against a live target in this wave — tests exercise request-shaping + typed-error mapping with the HTTP
client MOCKED/injected (no socket). No live URL, no live credential, no PHI. Setting the target URL does NOT
authorize traffic. THERE IS NO FALLBACK from a selected live adapter to the P9 fake — a config/preflight failure
is a TYPED ERROR, never a silent switch to the fake.

FILE SCOPE (impl): src/agentforge/target/openemr_adapter.py (the adapter), src/agentforge/target/preflight.py
(the preflight). If the adapter needs an HTTP client at RUNTIME, promote httpx from [dev] to [project].dependencies
and import it LAZILY inside send() (so import + preflight need no httpx and make no connection). Touch NOTHING else
(not policy/observability/agents/storage/evals/config/secrets/contracts).
FILE SCOPE (tests, Test Agent owns): tests/test_openemr_adapter.py, tests/test_preflight.py.

DESIGN:
openemr_adapter.py — OpenEmrAdapter(TargetAdapter): name='openemr'. send(request: TargetRequest) -> TargetResponse
  makes an HTTPS request to the configured base URL using a LAZILY-imported client, mapping transport failures to
  the typed taxonomy (TargetUnreachableError, RateLimitedError with retry_after, AdapterError('adapter-error'))
  and NEVER swallowing a failure into a synthetic 200. Timeout + backoff are config-driven and map to typed
  errors. It holds NO credential itself — the gateway injects a resolved Secret; the adapter uses it by reference
  at the call boundary and never logs/inlines it. It is API-primary. Provide a way to inject the HTTP client (a
  constructor arg / factory) so tests exercise it with a fake client — NO real socket.

preflight.py — a fail-closed, NETWORK-FREE preflight producing TYPED errors (define a TargetPreflightError base +
  specific subtypes / an enumerated reason). Given the target config (from Settings/env: HEADSHOT_TARGET_ID,
  HEADSHOT_TARGET_BASE_URL, HEADSHOT_TARGET_AUTH_MODE, the OPENEMR_* creds, HEADSHOT_SYNTHETIC_ONLY,
  HEADSHOT_CANARY_VALUE, and an exact-host allowlist), it checks — each a distinct typed failure:
    1. URL present + a VALID https:// URL (empty URL -> typed config error, NOT a no-op, NOT a fake fallback;
       http:// or a malformed URL -> typed error).
    2. EXACT-HOST allowlisting — the URL host must equal the target's allowlisted host EXACTLY (no subdomain/
       suffix match, no wildcard). An off-allowlist host -> typed error.
    3. Auth mode is one of {none, bearer, session, oauth}; anything else -> typed error.
    4. EXACTLY the credential fields the chosen mode requires are present, and NO OTHERS:
       none -> no creds; bearer -> a bearer token (OPENEMR_BEARER_TOKEN or the credential ref); session ->
       OPENEMR_SESSION_COOKIE; oauth -> OPENEMR_OAUTH_CLIENT_ID + CLIENT_SECRET + TOKEN_URL. A missing required
       field -> typed error.
    5. CONFLICTING auth — credentials for a DIFFERENT mode than the selected one are set (e.g. bearer selected but
       oauth fields populated) -> typed error (no ambiguous multi-mode config).
    6. SYNTHETIC-fixture requirement — HEADSHOT_SYNTHETIC_ONLY must be true / synthetic provenance asserted;
       otherwise -> typed error (no real PHI, ever).
    7. CANARY — HEADSHOT_CANARY_VALUE is set (deterministic canary) OR an EXPLICIT no-canary state is declared;
       a silently-absent canary -> typed error (canary must be a deliberate decision).
    8. Credential SECRETS are represented by reference (Secret), never inline; preflight never resolves/echoes a
       raw secret and (O1) a non-production environment cannot resolve a live credential (resolve_target_credential
       raises) — so preflight in local/staging reports config-shape validity but a live credential is NOT resolvable.
    9. A fully-valid config PASSES preflight but returns a result that EXPLICITLY does NOT authorize traffic —
       activation still requires a separate, explicit authorization (surface a 'preflight_ok, authorization_required'
       state; setting the URL is not permission).
  Preflight makes ZERO network calls and resolves NO live secret value.

ACCEPTANCE (each test pins an edge/error; NO network anywhere):
  (a) OpenEmrAdapter conforms to the TargetAdapter interface (same contract suite shape as the fake); an injected
  transport failure -> the correct TYPED AdapterError (never a synthetic 200). (b) preflight fail-closed on EACH
  of: empty URL, http:// URL, malformed URL, off-allowlist host, bad auth mode, missing required cred per mode,
  conflicting auth, synthetic-off, absent-canary-without-explicit-unavailable — each a DISTINCT typed error.
  (c) NO fallback to the fake when OpenEMR is selected and misconfigured (assert the result is a typed error, not
  a FakeTargetAdapter). (d) a fully-valid config -> preflight_ok but 'authorization_required' (URL set != authorized).
  (e) assert NO network/socket call occurs in preflight or in any test (patch/monkeypatch the client to raise if
  called; assert it is never called during preflight). (f) no raw secret is inlined/logged; O1 holds (local/staging
  cannot resolve a live credential).

CONSTRAINTS: framework-neutral where the core is (target imports base/config/secrets, NOT fastapi). No network,
no live target, no live credential, no PHI in tests/preflight. httpx (if used) imported lazily inside send() only.
`

phase('Tests')
const TEST_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  test_files: { type: 'array', items: { type: 'string' } }, preflight_cases: { type: 'array', items: { type: 'string' } },
  red_confirmed: { type: 'boolean' }, red_evidence: { type: 'string' }, no_network_proof: { type: 'string' }, notes: { type: 'string' } },
  required: ['test_files', 'red_confirmed', 'red_evidence', 'no_network_proof'] }
const testResult = await agent(
  `You are the TEST AGENT for M5. Write failing (RED) tests ONLY (tests/test_openemr_adapter.py,
tests/test_preflight.py) — no src code. Cover the adapter contract + typed-error mapping (HTTP client MOCKED, no
socket) and EVERY fail-closed preflight case above, plus 'no fake fallback', 'valid config -> authorization_required',
and an explicit assertion that NO network call happens in preflight/tests (patch the client to raise on use).
Run \`. .venv/bin/activate && python -m pytest tests/test_openemr_adapter.py tests/test_preflight.py -q\` and
CONFIRM RED (agentforge.target.openemr_adapter / .preflight import errors). ruff-clean. Do NOT edit src or other
tests. Return the structured result (list the preflight cases + how you prove no-network).
${SPEC}`,
  { label: 'test:m5', phase: 'Tests', schema: TEST_SCHEMA })

phase('Implement')
const IMPL_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  impl_files: { type: 'array', items: { type: 'string' } }, tests_untouched: { type: 'boolean' }, ruff_clean: { type: 'boolean' },
  pytest_summary: { type: 'string' }, green_confirmed: { type: 'boolean' }, no_network_mechanism: { type: 'string' }, design_notes: { type: 'string' } },
  required: ['impl_files', 'tests_untouched', 'ruff_clean', 'pytest_summary', 'green_confirmed', 'no_network_mechanism'] }
const implResult = await agent(
  `You are the IMPLEMENTATION AGENT for M5. Make the frozen RED tests GREEN by creating ONLY
src/agentforge/target/openemr_adapter.py + src/agentforge/target/preflight.py (+ the single httpx dev->runtime
pyproject move IF send() needs an HTTP client, imported lazily). Do NOT edit tests. Build to the DESIGN; every
preflight failure is a DISTINCT typed error; NO fallback to the fake; NO network in preflight; setting the URL
does not authorize traffic.
${SPEC}
Run the FULL suite \`. .venv/bin/activate && python -m pytest -q\` — all green (incl. the pre-existing suites).
ruff check + format clean. \`git status --porcelain tests/\` shows no impl changes. In no_network_mechanism,
describe exactly how preflight makes zero network calls and how a live send() is only reachable in an authorized
campaign. Return the structured result with the exact pytest summary line.`,
  { label: 'impl:m5', phase: 'Implement', schema: IMPL_SCHEMA })

phase('Review')
const REVIEW_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  verdict: { type: 'string', enum: ['approve', 'changes_requested'] },
  findings: { type: 'array', items: { type: 'object', additionalProperties: false, properties: {
    severity: { type: 'string', enum: ['critical', 'important', 'minor'] }, location: { type: 'string' }, problem: { type: 'string' }, fix: { type: 'string' } },
    required: ['severity', 'location', 'problem', 'fix'] } }, summary: { type: 'string' } }, required: ['verdict', 'findings', 'summary'] }
const [review, security] = await parallel([
  () => agent(
    `Independent CODE REVIEWER for M5 in ${REPO} (git --no-pager diff; read openemr_adapter.py, preflight.py, the
two test files). Verify the adapter conforms to the TargetAdapter interface + maps failures to typed errors
(never a synthetic 200); every preflight failure is a distinct typed error; no fake fallback; a valid config
yields authorization_required (URL != permission); and the tests genuinely prevent a network call. Run the
suite. Report real issues only. ${SPEC}`,
    { label: 'review:m5', phase: 'Review', schema: REVIEW_SCHEMA }),
  () => agent(
    `Independent SECURITY REVIEWER for M5 in ${REPO}. Adversarially audit:
  - Can ANY test or the preflight make a network/socket call to a target? (must be NO — prove the client is never
    constructed/called in preflight; find any real connection.)
  - Can a selected-but-misconfigured OpenEMR adapter FALL BACK to the fake or silently proceed? (must be NO)
  - Does setting HEADSHOT_TARGET_BASE_URL alone authorize traffic anywhere? (must be NO — a separate authz gate)
  - Is a live credential ever resolved/inlined/logged in local/staging (O1 must still refuse)? Any raw secret in
    a preflight message or the AttemptResult path?
  - Exact-host allowlist: can a look-alike host (subdomain, suffix, unicode/punycode, userinfo@, port trick,
    trailing dot) bypass the exact match? Try.
  - http:// downgrade or a non-https scheme accepted anywhere? Any PHI in fixtures?
Report concrete bypass vectors with severity + fix. Do NOT print .env.local. ${SPEC}`,
    { label: 'security:m5', phase: 'Review', schema: REVIEW_SCHEMA }),
])

return { test: testResult, impl: implResult, review, security }
