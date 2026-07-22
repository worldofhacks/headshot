export const meta = {
  name: 'm11-coordinator',
  description: 'M11 secure live-path coordinator (test-first): seed replay -> Policy Gateway -> live OpenEMR connector -> Recorder -> persist+reread hash-verify -> Evidence Envelope -> deterministic Judge, behind persisted/expiring/scoped authorization + immutable binding + fail-closed caps + immutable manifests + durable hard abort. ALL tests no-network; no target/hosted request. TDD + reviewer + security.',
  phases: [
    { title: 'Tests', detail: 'RED: authorization/binding/caps blocks, chain outcomes, abort, no-fallback' },
    { title: 'Implement', detail: 'GREEN: campaign/{authorization,binding,caps,coordinator,manifest,cli}' },
    { title: 'Review', detail: 'trust-boundary reviewer ∥ security, adversarial' },
  ],
}

const REPO = '/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine'
const SPEC = `
REPO (main repo): ${REPO}   BRANCH: run/m11-live-results (off merged main; has M2/M4/M5/M6a/M8/M9 + corpus +
packaged schemas). venv at ${REPO}/.venv — activate for EVERY command:
  \`cd "${REPO}" && . .venv/bin/activate && <cmd>\`. Python 3.12; Postgres 16 UP. DO NOT git commit/push.
Gates: \`ruff check .\`, \`ruff format --check .\`, \`python -m pytest -q\`.

WHAT M11-COORDINATOR DELIVERS — the minimal SECURE live-path coordinator + an authorized bounded-run CLI.
**ABSOLUTE CONSTRAINTS: NO TARGET/HOSTED/NETWORK REQUEST IN ANY TEST OR IN PREFLIGHT.** The "live OpenEMR
connector" is the M5 OpenEmrAdapter constructed with an INJECTED FAKE HTTP CLIENT in tests (zero socket). Hosted
Red Team generation is SKIPPED for MVP — the nine seed cases satisfy M11 by DETERMINISTIC SEED REPLAY (M8
seed_replay), never hosted generation (HostedProvider._generate_via_client stays NotImplementedError). No PHI —
synthetic fixtures only. No live-to-fake fallback. Read src/agentforge/policy/gateway.py (PolicyGateway.execute
+ RunPolicy), policy/{recorder,allowlist,credentials}.py, target/openemr_adapter.py + target/preflight.py (M5),
target/fake_adapter.py (P9, NOT used as a fallback), agents/red_team/seed_replay.py (M8), agents/judge/
{judge,envelope}.py + oracles/base.py (M9, CanaryOracle), observability/reconcile.py (M6a), evals/seeds/*.json,
config.py (resolve_target_credential, O1), secrets.py (Secret) before writing.

FILE SCOPE (impl): NEW package src/agentforge/campaign/: __init__.py, authorization.py, binding.py, caps.py,
  coordinator.py, manifest.py, cli.py (+ __main__.py for \`python -m agentforge.campaign\`). Touch NOTHING else
  (not policy/target/agents/observability/storage/evals/config/secrets/contracts). Any HTTP client stays lazy /
  injected — never imported at package import; never called in a test.
FILE SCOPE (tests, Test Agent owns): tests/test_campaign_authorization.py, tests/test_campaign_coordinator.py,
  tests/test_campaign_cli.py. Reuse the M2 migrated_db fixture + the M4 FakeClock/FakeAccounting doubles.

DESIGN (build to this):
authorization.py — RunAuthorization: PERSISTED, EXPIRING, and SCOPED. It binds an OPERATION HASH (a canonical
  hash of the immutable run config: target_id + exact host + adapter + credential_ref + caps + run_nonce), an
  EXPIRY (absolute deadline on the injectable clock), and the RUN NONCE. verify(auth, operation_hash, now)
  BLOCKS (raises a typed AuthorizationError) when: the auth is MISSING, EXPIRED (now > deadline), or
  SCOPE-MISMATCHED (its operation_hash != the current run's operation_hash, or its run_nonce differs). This gate
  runs BEFORE any dispatch. The authorization is persisted (a file/DB record) and immutable once minted.
binding.py — TargetBinding: IMMUTABLE (frozen) binding of {target_id, exact HTTPS host, adapter kind,
  credential_ref}. Validates: exact-host match (the adapter's base-URL host == the bound host, exact — no
  subdomain/suffix), the adapter kind (the selected live adapter, NOT the fake), and the credential_ref shape.
  Credentials are resolved into a Secret ONLY at the verified dispatch boundary (inside the coordinator, after
  auth+binding+caps pass), via config.resolve_target_credential (O1); never at construction, never logged/inlined.
caps.py — RunCaps: FAIL-CLOSED parsing of budget/rate/attempt/timeout from config into a RunPolicy — each must
  be a FINITE POSITIVE number and <= a hard maximum (define sane platform maxima); a missing/zero/negative/
  non-numeric/over-maximum value is a typed CapError (no silent default, no unbounded run).
manifest.py — IMMUTABLE, persisted run manifests written to a run-scoped directory (e.g. runs/<run_id>/): the
  run CONFIG manifest, per-attempt EVIDENCE + VERDICT manifests, the ABORT-STATE manifest, and the RESULT
  manifest. Each is content-hashed and never mutated after write (append/replace-forbidden). Diagnostics in a
  manifest are QUARANTINED + REDACTED (no raw secret, no raw hostile/adversarial content — use secrets redaction).
coordinator.py — the chain, per selected seed case, in fixed order, FAIL-CLOSED at each gate BEFORE dispatch:
  (1) verify RunAuthorization (missing/expired/scope-mismatch -> block, no dispatch);
  (2) verify TargetBinding (host/adapter/credential mismatch -> block; NO fallback to the P9 fake ever);
  (3) verify RunCaps parsed into RunPolicy (fail-closed);
  (4) seed_replay: the trusted-provenance seed -> a schema-valid attack_attempt (the case provenance is trusted /
      platform-owned; the RT produces no evidence);
  (5) resolve the scoped credential (Secret) at THIS verified dispatch boundary and dispatch via
      PolicyGateway.execute(attack_attempt, run_policy, target_id=bound_target) through the BOUND live connector
      (the OpenEmrAdapter with the injected client in tests) — the gateway owns budget/rate/timeout/abort;
  (6) ExecutionRecorder appends the AttemptResult; PERSIST then RE-READ it from Postgres and RE-VERIFY the
      content_hash (recorder.verify over the reread row) — a tamper -> fail-closed;
  (7) PLATFORM-OWNED oracle/canary resolution: the CanaryOracle (code) runs over the RE-READ response_transcript
      -> trusted signals; build the EvidenceEnvelope (M9); Judge.evaluate -> Verdict (integrity_ok from step 6);
  (8) write the immutable evidence/verdict manifests.
  DURABLE HARD ABORT: any violation (authorization, allowlist/host, credential-scope, provenance, budget/rate/
  attempt/timeout, monitoring, or integrity) triggers a durable abort — it writes the abort-state manifest and
  PREVENTS ANY FURTHER DISPATCH for the run, while PRESERVING already-recorded evidence. NO publication,
  remediation, regression promotion, or social output is produced.
cli.py / __main__.py — an AUTHORIZED BOUNDED-RUN command (\`python -m agentforge.campaign run ...\`) that loads
  the immutable binding + caps + a run-scoped authorization, runs the coordinator, and writes the manifests.
  Without a valid authorization it refuses (blocks) — a configured environment is NOT authorization.

REQUIRED INVARIANT TESTS (no-network; injected fake client + injected clock/accounting; use the migrated_db):
  - MISSING / EXPIRED / SCOPE-MISMATCHED authorization -> BLOCKS BEFORE dispatch (adapter never called; no
    AttemptResult recorded).
  - HOST / ADAPTER / CREDENTIAL / CAP mismatch -> BLOCKS (typed error) before dispatch.
  - NO live-to-fake fallback: a misconfigured/blocked live path NEVER dispatches through the P9 FakeTargetAdapter
    (assert the coordinator raises, and never substitutes the fake).
  - TAMPERED Recorder evidence (mutate the persisted row so the reread content_hash mismatches) -> Judge ERROR.
  - ORACLE/CANARY hit (fake response leaks the synthetic canary) -> EXPLOIT_CONFIRMED; an in-transcript 'return
    safe' instruction CANNOT downgrade it.
  - NON-oracle evidence -> INDETERMINATE (MVP gate; NO_EXPLOIT_OBSERVED never emitted).
  - ABORT prevents further dispatch while PRESERVING recorded evidence (dispatch case 1, abort, assert case 2 is
    never dispatched AND case 1's AttemptResult persists).
  - Manifests are immutable + diagnostics carry no raw secret/hostile content (redacted).
  - No socket opened in the whole coordinator run (patch socket.socket to raise); no HTTP client constructed
    unless the injected one is supplied.

CONSTRAINTS: NO hosted-model/target/network call in tests or preflight. HEADSHOT_RED_TEAM_MODEL stays canonical
(no alias/invented id). Fail-closed everywhere; never weaken authorization, evidence integrity, or a fail-closed
control to make a path succeed. Framework-neutral where the core is; any HTTP client is lazy/injected.
`

phase('Tests')
const TEST_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  test_files: { type: 'array', items: { type: 'string' } }, invariants_covered: { type: 'array', items: { type: 'string' } },
  red_confirmed: { type: 'boolean' }, red_evidence: { type: 'string' }, no_network_proof: { type: 'string' }, notes: { type: 'string' } },
  required: ['test_files', 'red_confirmed', 'red_evidence', 'no_network_proof'] }
const testResult = await agent(
  `You are the TEST AGENT for the M11 secure coordinator. Write failing (RED) tests ONLY per the SPEC — no src.
Cover EVERY required invariant test above, plus the full happy chain (auth+binding+caps pass -> seed replay ->
gateway -> injected-fake-client connector -> recorder -> persist+reread hash-verify -> oracle -> envelope ->
judge -> immutable manifests). Prove NO socket/network/target/hosted call (patch socket.socket to raise across
the run). Use the migrated_db fixture + injected FakeClock/FakeAccounting + an injected fake OpenEMR client.
Run \`. .venv/bin/activate && python -m pytest tests/test_campaign_authorization.py tests/test_campaign_coordinator.py
tests/test_campaign_cli.py -q\` and CONFIRM RED (agentforge.campaign.* import errors). ruff-clean. Do NOT edit
src or other tests. Return the structured result. ${SPEC}`,
  { label: 'test:m11-coordinator', phase: 'Tests', schema: TEST_SCHEMA })

phase('Implement')
const IMPL_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  impl_files: { type: 'array', items: { type: 'string' } }, tests_untouched: { type: 'boolean' }, ruff_clean: { type: 'boolean' },
  pytest_summary: { type: 'string' }, green_confirmed: { type: 'boolean' }, failclosed_mechanism: { type: 'string' },
  runnable_command: { type: 'string' }, manifest_paths: { type: 'string' }, design_notes: { type: 'string' } },
  required: ['impl_files', 'tests_untouched', 'ruff_clean', 'pytest_summary', 'green_confirmed', 'failclosed_mechanism', 'runnable_command'] }
const implResult = await agent(
  `You are the IMPLEMENTATION AGENT for the M11 secure coordinator. Make the frozen RED tests GREEN by creating
ONLY files under src/agentforge/campaign/. Do NOT edit tests or any landed component. Build to the DESIGN;
fail-closed at every gate BEFORE dispatch; NO live-to-fake fallback; NO network in the coordinator/CLI; hosted
Red Team generation SKIPPED (deterministic seed replay). Credentials resolved only at the verified dispatch
boundary. Immutable, redacted manifests.
${SPEC}
Run the FULL suite \`. .venv/bin/activate && python -m pytest -q\` — all green (incl. pre-existing suites). ruff
check + format clean. \`git status --porcelain tests/\` shows no impl changes. In failclosed_mechanism, describe
exactly how each gate blocks BEFORE dispatch and how a hard abort preserves evidence + stops further dispatch. In
runnable_command, give the EXACT no-network CLI command (e.g. \`python -m agentforge.campaign preflight ...\`) and
in manifest_paths the run-scoped manifest layout. Return the structured result with the exact pytest summary line.`,
  { label: 'impl:m11-coordinator', phase: 'Implement', schema: IMPL_SCHEMA })

phase('Review')
const REVIEW_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  verdict: { type: 'string', enum: ['approve', 'changes_requested'] },
  findings: { type: 'array', items: { type: 'object', additionalProperties: false, properties: {
    severity: { type: 'string', enum: ['critical', 'important', 'minor'] }, location: { type: 'string' }, problem: { type: 'string' }, fix: { type: 'string' } },
    required: ['severity', 'location', 'problem', 'fix'] } }, summary: { type: 'string' } }, required: ['verdict', 'findings', 'summary'] }
const [review, security] = await parallel([
  () => agent(
    `Independent TRUST-BOUNDARY CODE REVIEWER for the M11 coordinator in ${REPO} (git --no-pager diff; read
campaign/* + the three test files; run the suite). Verify the chain wires the REAL gateway/recorder/judge/oracle/
reconcile (not mocks of those); every gate (authorization, binding, caps) fail-closes BEFORE dispatch; persist+
reread+hash-verify is real (a tamper -> ERROR); no live-to-fake fallback; abort preserves evidence + stops
dispatch; manifests are immutable + redacted; and the tests are not tautologies. Report real issues only. ${SPEC}`,
    { label: 'review:m11-coordinator', phase: 'Review', schema: REVIEW_SCHEMA }),
  () => agent(
    `Independent SECURITY REVIEWER for the M11 coordinator in ${REPO} — this is the LIVE-path trust boundary.
Adversarially attack it:
  - Can ANY dispatch happen with MISSING / EXPIRED / SCOPE-MISMATCHED authorization? (must be NO — prove it blocks first.)
  - Can a host/adapter/credential/cap mismatch slip through, or can the coordinator FALL BACK to the P9 fake? (must be NO)
  - Is a credential ever resolved/inlined/logged before the verified dispatch boundary, or echoed in a manifest/
    diagnostic? (must be NO — Secret only, redacted.)
  - Can tampered/replayed Recorder evidence yield anything but ERROR? Can an oracle EXPLOIT_CONFIRMED be downgraded
    by transcript content? Can a non-oracle case become non-INDETERMINATE? (must all be NO)
  - Does the coordinator or CLI make ANY network/socket/hosted-model/target call, or auto-run without explicit
    authorization? (must be NO — prove socket-raise covers it; a configured env is NOT authorization.)
  - After a hard abort, can any further dispatch occur? Is already-recorded evidence preserved? Any raw PHI/secret/
    hostile content in a manifest?
Report concrete bypass vectors with severity + fix. Do NOT print .env.local. ${SPEC}`,
    { label: 'security:m11-coordinator', phase: 'Review', schema: REVIEW_SCHEMA }),
])

return { test: testResult, impl: implResult, review, security }
