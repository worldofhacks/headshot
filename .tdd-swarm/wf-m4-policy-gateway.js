export const meta = {
  name: 'm4-policy-gateway-recorder',
  description: 'M4: trusted Policy Gateway + Execution Recorder (allowlist, scoped creds, synthetic-data, budget/rate/abort, append-only hashed AttemptResult) verified against the P9 fake — no live target. TDD + reviewer + security.',
  phases: [
    { title: 'Tests', detail: 'RED: gateway policy + recorder evidence' },
    { title: 'Implement', detail: 'GREEN: policy/{gateway,recorder,allowlist,credentials}.py' },
    { title: 'Review', detail: 'reviewer ∥ security, adversarial' },
  ],
}

const REPO = '/Users/quietguy/Documents/Dev/Gauntlet/wt-m4'

const SPEC = `
REPO (git worktree, ISOLATED): ${REPO}   BRANCH: ticket/m4-policy-gateway (off swarm; has M2).
This worktree has its OWN venv at ${REPO}/.venv. Activate it for EVERY command:
  \`cd "${REPO}" && . .venv/bin/activate && <cmd>\`
Do NOT cd to any other repo/worktree. Python 3.12; SQLAlchemy2+Alembic+psycopg3 installed; Postgres 16 UP.
Gates: \`ruff check .\`, \`ruff format --check .\`, \`python -m pytest -q\`. DO NOT git commit/push (the
orchestrator integrates). A local Postgres is up; the M2 schema + migrated_db fixture (tests/conftest.py,
tests/_db.py) already exist on this branch — reuse them for DB-backed tests.

WHAT M4 DELIVERS — the TRUSTED Policy Gateway + Execution Recorder (ARCHITECTURE §3/§4/§5, D14, F2/F5;
PRESEARCH §5.3 #4/#5/#7). Map S1/S3, PRD-25/26/27, PRD-OPT-05/09/11/12. Deps M2✓, P9 fake✓, P10 contracts✓,
P5 skill✓. **VERIFIED AGAINST THE P9 FAKE ONLY — no live target, no live credential, no hosted-model secret,
no network.** Read ARCHITECTURE.md §3/§4/§5, src/agentforge/target/base.py + fake_adapter.py (the P9 adapter
you dispatch through), src/agentforge/config.py (resolve_target_credential O1) and src/agentforge/secrets.py
(Secret) before writing.

FILE SCOPE (impl): src/agentforge/policy/gateway.py, recorder.py, allowlist.py, credentials.py.
  Do NOT touch models.py / migrations / contracts / target / config / secrets / app / health / observability.
FILE SCOPE (tests, Test Agent owns): tests/test_gateway.py, tests/test_recorder.py. Do NOT modify
  tests/conftest.py or tests/_db.py (M2-owned, reuse as-is) or any other existing test.

DESIGN (build to this; ACs are the contract):

allowlist.py — env-scoped allowlist (D16: prod-only live creds; env-scoped allowlist). AllowlistEntry(target_id,
  adapter_name); Allowlist.resolve(target_id) → entry, else raise OffAllowlistDenied (a typed denial that is
  ALSO written to an audit trail — return/emit an audit record: {target_id, decision:'denied', reason, ts}).
  Locally ONLY the P9 fake target is allowlisted; NO live URL is present or resolvable.

credentials.py — scoped credential binding (§5.3 #7: cross-target use impossible by construction).
  CredentialBinding(target_id, secret_ref). resolve(target_id, settings) returns a secrets.Secret (redacted;
  NEVER an inline value) via config.Settings.resolve_target_credential — which in local/staging RAISES
  EnvironmentIsolationError (O1), so a non-prod gateway cannot obtain a production live credential. A binding
  for target A can NEVER yield target B's credential (bound by construction — prove it). The fake target needs
  no credential (synthetic).

gateway.py — the trusted PolicyGateway. A RunPolicy carries the caps: budget_usd, max_attempts_per_run,
  target_requests_per_second, run_timeout_seconds. PolicyGateway.execute(attack_attempt, run_context):
    1. ALLOWLIST check (deny + audit if off-allowlist).
    2. SYNTHETIC-DATA enforcement: in non-production, a live URL/credential is REFUSED (synthetic-only, §5.3 #8).
    3. BUDGET/RATE/ATTEMPT/TIMEOUT enforcement — enforced HERE, in runtime code, BEFORE any dispatch, and
       INDEPENDENT OF TRIGGER (F5 — the gate is the gateway, not a skill flag). A breach of any cap = a HARD
       ABORT (raise a typed AbortError / return an aborted decision) and NO dispatch happens. Use an injectable
       clock + spend/attempt accounting so tests are deterministic (no real sleeping, no real cost). **This is
       the enforcement point the whole platform's live-safety depends on — a live model/target call can only be
       reached AFTER these caps pass. Since we run against the fake, no real inference occurs regardless.**
    4. Resolve the scoped credential by REFERENCE (a Secret) — fake target: none.
    5. Dispatch via the TargetAdapter.send (P9 fake) — the gateway is the SOLE path to the adapter; the Red
       Team never holds the adapter, a credential, or an outbound path (§5).
    6. On a typed AdapterError → backoff → queue → abort (a bounded retry policy; a TargetUnreachable beyond
       backoff surfaces a TYPED error, never a silent 200).
    7. Build an AttemptResult with a FRESH per-dispatch campaign_run_id nonce (S3) + policy_decision_id +
       recorder fields, and hand it to the ExecutionRecorder.

recorder.py — ExecutionRecorder. record(fields, conn): compute content_hash by CANONICAL serialization
  (sorted-key/explicit-field-order bytes — recompute-stable, D14), INSERT append-only into attempt_result
  (INSERT only — never UPDATE/DELETE). verify(record): recompute content_hash and FAIL-CLOSED on any
  mismatch/missing (evidence-integrity-failed typed error). A duplicate (campaign_run_id, attempt_id) is
  rejected by the DB UNIQUE (S3 replay), surfaced as a typed error, never an overwrite.

ACCEPTANCE (each test must pin an edge/error, never happy-path only):
  AC-1 gateway enforces allowlist + scoped creds + synthetic-data + budget + rate + HARD ABORT, in runtime
       code independent of trigger. AC-2 emits canonical-hash append-only AttemptResult with a fresh per-dispatch
       campaign_run_id. AC-3 the Red Team path holds NO credentials (the AttackAttempt has no cred; the gateway
       injects a Secret; prove the RT-facing input cannot carry/leak a credential). AC-4 (S3 invariant)
       UNIQUE(campaign_run_id, attempt_id) rejects a replay; a gated side-effect is idempotent. AC-5 (invariant)
       no dispatch without the gate; each cap (budget/rate/attempt/timeout) trips a hard abort with NO dispatch;
       an off-allowlist target is denied AND audited; a typed AdapterError drives backoff→queue→abort.
  Secrets: only a Secret/redacted reference ever appears; assert no raw credential is inlined or logged. No PHI.

CONSTRAINTS: framework-neutral where the core is (policy imports config/secrets/target/storage, NOT fastapi).
No network, no live target, no hosted-model call. Fake-adapter + local Postgres only.
`

phase('Tests')
const TEST_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    test_files: { type: 'array', items: { type: 'string' } },
    acs_covered: { type: 'array', items: { type: 'string' } },
    red_confirmed: { type: 'boolean' },
    red_evidence: { type: 'string' },
    notes: { type: 'string' },
  },
  required: ['test_files', 'red_confirmed', 'red_evidence'],
}
const testResult = await agent(
  `You are the TEST AGENT for M4. Write failing (RED) tests ONLY (tests/test_gateway.py, tests/test_recorder.py)
— no src/ code. Cover every AC above incl. the edge/error cases (hard-abort on each cap, off-allowlist audit,
no-dispatch-without-gate, RT-holds-no-creds, backoff→queue→abort, S3 replay, canonical-hash recompute-verify
fail-closed). Use the M2 migrated_db fixture for DB-backed recorder tests; use the P9 FakeTargetAdapter
(.script()/.fail()) for dispatch. Deterministic only (injectable clock/accounting — no real sleeping/cost/network).
Run \`. .venv/bin/activate && python -m pytest tests/test_gateway.py tests/test_recorder.py -q\` and CONFIRM RED
(imports of agentforge.policy.* fail → collection errors). Make the tests ruff-clean. Do NOT edit conftest.py/_db.py
or any src/ file. Return the structured result.`,
  { label: 'test:m4', phase: 'Tests', schema: TEST_SCHEMA },
)

phase('Implement')
const IMPL_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    impl_files: { type: 'array', items: { type: 'string' } },
    tests_untouched: { type: 'boolean' },
    ruff_clean: { type: 'boolean' },
    pytest_summary: { type: 'string' },
    green_confirmed: { type: 'boolean' },
    gate_enforcement: { type: 'string' },
    design_notes: { type: 'string' },
  },
  required: ['impl_files', 'tests_untouched', 'ruff_clean', 'pytest_summary', 'green_confirmed', 'gate_enforcement'],
}
const implResult = await agent(
  `You are the IMPLEMENTATION AGENT for M4. Make the frozen RED tests GREEN by editing ONLY
src/agentforge/policy/{gateway,recorder,allowlist,credentials}.py. Do NOT edit ANY tests/ file (if a frozen
test looks wrong, STOP and explain in design_notes). Build to the DESIGN above.
${SPEC}
Run the FULL suite \`. .venv/bin/activate && python -m pytest -q\` — all green (incl. the pre-existing suite).
\`ruff check .\` + \`ruff format --check .\` clean. Verify \`git status --porcelain tests/\` shows no impl-made
changes. In gate_enforcement, describe EXACTLY how each cap (budget/rate/attempt/timeout) forces a hard abort
BEFORE dispatch and how the Red Team path is structurally credential-free. Return the structured result.`,
  { label: 'impl:m4', phase: 'Implement', schema: IMPL_SCHEMA },
)

phase('Review')
const REVIEW_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    verdict: { type: 'string', enum: ['approve', 'changes_requested'] },
    findings: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        properties: {
          severity: { type: 'string', enum: ['critical', 'important', 'minor'] },
          location: { type: 'string' },
          problem: { type: 'string' },
          fix: { type: 'string' },
        },
        required: ['severity', 'location', 'problem', 'fix'],
      },
    },
    summary: { type: 'string' },
  },
  required: ['verdict', 'findings', 'summary'],
}
const [review, security] = await parallel([
  () => agent(
    `Independent CODE REVIEWER for M4 in ${REPO} (git --no-pager diff; read policy/*.py + the two test files).
Verify the gateway enforces allowlist/synthetic/budget/rate/attempt/timeout with a HARD ABORT before dispatch,
the AttemptResult is canonical-hashed + append-only with a fresh campaign_run_id, the Red Team path holds no
creds, and the tests aren't tautologies (would a removed cap-check flip a test to fail?). Run the tests. Report
real issues only. ${SPEC}`,
    { label: 'review:m4', phase: 'Review', schema: REVIEW_SCHEMA },
  ),
  () => agent(
    `Independent SECURITY REVIEWER for M4 in ${REPO}. Adversarially attack the trust boundary:
  - Can ANY dispatch reach the adapter WITHOUT passing the gate (bypass the caps/allowlist)? (must be NO)
  - Can a cap be exceeded before abort (off-by-one on max_attempts, spend checked after the call, rate/timeout
    not enforced)? Prove each cap hard-aborts BEFORE the adapter is called.
  - Does the Red Team path ever hold a credential, the adapter, or an outbound target path? (must be NO)
  - Is a live credential/URL resolvable in local/staging (O1)? Does resolve_target_credential still refuse?
  - Is any raw secret inlined or logged (must be Secret/redacted only)? Any real PHI or live network call?
  - Is the content_hash canonical + fail-closed on tamper; does a replay overwrite or get rejected (S3)?
Report concrete bypass vectors with severity + fix. Do NOT print .env.local/os.environ. ${SPEC}`,
    { label: 'security:m4', phase: 'Review', schema: REVIEW_SCHEMA },
  ),
])

return { test: testResult, impl: implResult, review, security }
