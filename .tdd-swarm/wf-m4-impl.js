export const meta = {
  name: 'm4-policy-gateway-impl',
  description: 'M4 (main-repo re-run): implement Policy Gateway + Execution Recorder against the already-frozen RED tests, then independent reviewer ∥ security. Verified vs P9 fake — no live target.',
  phases: [
    { title: 'Implement', detail: 'GREEN: policy/{gateway,recorder,allowlist,credentials}.py vs frozen tests' },
    { title: 'Review', detail: 'reviewer ∥ security, adversarial' },
  ],
}

const REPO = '/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine'

const SPEC = `
REPO (main repo): ${REPO}   BRANCH: ticket/m4-policy-gateway (off swarm; has M2). Its venv is ${REPO}/.venv.
Activate it for EVERY command: \`cd "${REPO}" && . .venv/bin/activate && <cmd>\`. Python 3.12; SQLAlchemy2 +
Alembic + psycopg3 installed; Postgres 16 UP. Gates: \`ruff check .\`, \`ruff format --check .\`, \`python -m pytest -q\`.
DO NOT git commit/push (the orchestrator integrates).

The FROZEN RED tests ALREADY EXIST in this repo: tests/test_gateway.py and tests/test_recorder.py. They are
Test-Agent-owned and FROZEN — you MUST NOT create, edit, delete, or reformat them (or conftest.py / _db.py).
READ them first; they are the exact interface contract. If a frozen test looks genuinely impossible, STOP and
explain in design_notes rather than editing it.

WHAT M4 DELIVERS — the TRUSTED Policy Gateway + Execution Recorder (ARCHITECTURE §3/§4/§5, D14, F2/F5;
PRESEARCH §5.3 #4/#5/#7). **VERIFIED AGAINST THE P9 FAKE ONLY — no live target, no live credential, no
hosted-model secret, no network.** Read ARCHITECTURE.md §4/§5, src/agentforge/target/base.py + fake_adapter.py,
src/agentforge/config.py (resolve_target_credential — returns a "secretref://production/<id>" STRING in prod,
RAISES EnvironmentIsolationError in local/staging; wrap the reference in secrets.Secret), src/agentforge/secrets.py
(Secret), and src/agentforge/storage/models.py (attempt_result columns + UNIQUE(campaign_run_id,attempt_id))
before/while implementing.

FILE SCOPE (impl, the ONLY files you create/edit): src/agentforge/policy/gateway.py, recorder.py, allowlist.py,
  credentials.py. Touch NOTHING else (not models/migrations/contracts/target/config/secrets/app/health/tests).

DESIGN (match the frozen tests' exact symbol names/signatures — read the tests to confirm):
allowlist.py — env-scoped allowlist (D16). AllowlistEntry(target_id, adapter_name); Allowlist.resolve(target_id)
  → entry else raise OffAllowlistDenied; a denial is ALSO recorded to an audit trail (an .audit_log the tests read).
  Locally ONLY the P9 fake target is allowlisted; NO live URL resolvable.
credentials.py — scoped credential binding (§5.3 #7). CredentialBinding(target_id, secret_ref);
  resolve(target_id, settings) → secrets.Secret wrapping config.Settings.resolve_target_credential(target_id)
  (which RAISES EnvironmentIsolationError in local/staging — O1); a binding for target A can never yield target
  B's credential (raise on mismatch). Never inline/log a raw credential.
gateway.py — trusted PolicyGateway. RunPolicy(budget_usd, max_attempts_per_run, target_requests_per_second,
  run_timeout_seconds). PolicyGateway.execute(...): (1) allowlist check (deny+audit off-allowlist); (2)
  synthetic-data enforcement (refuse a live URL/cred in non-prod); (3) BUDGET/RATE/ATTEMPT/TIMEOUT caps enforced
  in runtime code, BEFORE any dispatch, INDEPENDENT OF TRIGGER (F5) — a breach = HARD ABORT (raise AbortError /
  aborted decision) with ZERO dispatch; injectable clock + accounting so it is deterministic; (4) resolve scoped
  cred by reference (Secret); (5) dispatch via TargetAdapter.send (P9 fake) — the gateway is the SOLE path, the
  Red Team holds no adapter/credential/outbound path; (6) typed AdapterError → backoff→queue→abort (never a
  silent 200); (7) build AttemptResult with a FRESH per-dispatch campaign_run_id nonce + policy_decision_id, hand
  to the recorder. **The budget/rate/abort caps here are the enforcement point the platform's live-safety depends
  on — a live call is only reachable AFTER they pass; against the fake, no real inference occurs regardless.**
recorder.py — ExecutionRecorder: canonical_hash(fields) (sorted-key/explicit-order bytes, D14),
  record(fields, conn) append-only INSERT into attempt_result (INSERT only — never UPDATE/DELETE), verify(record)
  recompute + FAIL-CLOSED on mismatch (EvidenceIntegrityError). A duplicate (campaign_run_id, attempt_id) → the
  DB UNIQUE raises; surface it as a typed ReplayRejectedError, never overwrite (S3).

CONSTRAINTS: policy imports config/secrets/target/storage — NOT fastapi. No network, no live target, no hosted
call. Fake adapter + local Postgres only. Only a Secret/redacted reference ever represents a credential. No PHI.
GOAL: full suite green, ruff clean, tests untouched.
`

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
  `You are the IMPLEMENTATION AGENT for M4. The frozen RED tests tests/test_gateway.py and tests/test_recorder.py
already exist — READ them to learn the exact interface, then make them GREEN by creating ONLY
src/agentforge/policy/{gateway,recorder,allowlist,credentials}.py. Do NOT edit any tests/ file. Build to the DESIGN.
${SPEC}
Run the FULL suite \`. .venv/bin/activate && python -m pytest -q\` — all green (incl. the pre-existing suite).
\`ruff check .\` + \`ruff format --check .\` clean. Verify \`git status --porcelain tests/\` shows no changes you made.
In gate_enforcement, describe EXACTLY how each cap (budget/rate/attempt/timeout) forces a hard abort BEFORE
dispatch and how the Red Team path is structurally credential-free. Return the structured result with the exact
pytest summary line.`,
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
    `Independent CODE REVIEWER for M4 in ${REPO} (git --no-pager diff; read policy/*.py + tests/test_gateway.py +
tests/test_recorder.py). Verify the gateway enforces allowlist/synthetic/budget/rate/attempt/timeout with a HARD
ABORT before dispatch, the AttemptResult is canonical-hashed + append-only with a fresh campaign_run_id, the Red
Team path holds no creds, and the tests genuinely constrain this (not tautologies). Run the tests. Report real
issues only. ${SPEC}`,
    { label: 'review:m4', phase: 'Review', schema: REVIEW_SCHEMA },
  ),
  () => agent(
    `Independent SECURITY REVIEWER for M4 in ${REPO}. Adversarially attack the trust boundary:
  - Can ANY dispatch reach the adapter WITHOUT passing the gate/caps/allowlist? (must be NO)
  - Can a cap be exceeded before abort (off-by-one on max_attempts, spend checked AFTER the call, rate/timeout
    unenforced)? Prove each cap hard-aborts BEFORE adapter.send is called.
  - Does the Red Team path ever hold a credential, the adapter, or an outbound target path? (must be NO)
  - Is a live credential/URL resolvable in local/staging (O1 — resolve_target_credential must still refuse)?
  - Any raw secret inlined/logged (must be Secret/redacted only)? Any real PHI or live network call?
  - content_hash canonical + fail-closed on tamper; a replay rejected not overwritten (S3)?
Report concrete bypass vectors with severity + fix. Do NOT print .env.local/os.environ. ${SPEC}`,
    { label: 'security:m4', phase: 'Review', schema: REVIEW_SCHEMA },
  ),
])

return { impl: implResult, review, security }
