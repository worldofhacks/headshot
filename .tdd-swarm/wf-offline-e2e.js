export const meta = {
  name: 'offline-e2e-proof',
  description: 'Step 6: a complete DETERMINISTIC OFFLINE campaign wiring the REAL landed components (M8 seed -> M4 gateway -> P9 fake -> Recorder AttemptResult -> M6a reconcile -> M9 verdict). Proves confirmed / no-exploit / indeterminate / integrity-failure / budget-abort + run/attempt correlation. Offline deterministic, NEVER live. Build + reviewer ∥ security.',
  phases: [
    { title: 'Build', detail: 'wire real components into tests/test_offline_e2e.py; run GREEN' },
    { title: 'Review', detail: 'reviewer ∥ security — genuine e2e, no mocks, honest labelling' },
  ],
}

const REPO = '/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine'
const SPEC = `
REPO (main repo): ${REPO}   BRANCH: ticket/offline-e2e (off swarm/mvp-live-gate; has M2/M4/M5/M6a/M8/M9 + corpus).
venv at ${REPO}/.venv — activate for EVERY command: \`cd "${REPO}" && . .venv/bin/activate && <cmd>\`. Postgres 16 UP.
DO NOT git commit/push. Gates: \`ruff check .\`, \`ruff format --check .\`, \`python -m pytest -q\`.

GOAL — a complete DETERMINISTIC OFFLINE campaign that wires the REAL landed components end to end and proves the
required outcomes. **These are OFFLINE DETERMINISTIC results — NEVER live results. NO hosted-model call, NO
network, NO live target, NO PHI.** The ONLY target is the P9 FakeTargetAdapter; every model path is code/oracle.

THE CHAIN (use the REAL classes — NO mocks of the components under proof):
  M8 seed ingestion (agentforge.agents.red_team.seed_replay + RedTeam) -> M4 policy enforcement
  (agentforge.policy.gateway.PolicyGateway with the real allowlist/credentials + injected FakeClock/FakeAccounting)
  -> P9 fake (agentforge.target.fake_adapter.FakeTargetAdapter, programmed per case) -> Recorder
  (agentforge.policy.recorder.ExecutionRecorder writes the append-only AttemptResult to the migrated_db) -> M6a
  reconcile (agentforge.observability.reconcile.reconcile) -> M9 Judge (agentforge.agents.judge: an Oracle/
  CanaryOracle runs IN CODE over the AttemptResult.response_transcript to populate trusted signals; the
  EvidenceEnvelopeBuilder builds the typed envelope; Judge.evaluate -> Verdict).

Read these before writing: agents/red_team/{red_team,seed_replay,selection}.py, policy/{gateway,recorder,
allowlist,credentials}.py, target/fake_adapter.py, observability/reconcile.py, agents/judge/{judge,envelope}.py,
agents/judge/oracles/base.py (CanaryOracle), tests/test_gateway.py + tests/test_recorder.py + tests/test_judge.py
(for the FakeClock/FakeAccounting doubles + envelope/oracle usage), evals/seeds/*.json (the multi-turn corpus).

FILE SCOPE: tests/test_offline_e2e.py (NEW — the e2e proof). You MAY add a SMALL, clearly-offline campaign-runner
helper ONLY if needed to wire the chain (e.g. src/agentforge/agents/red_team/ or a test-local helper) — prefer
wiring the REAL components inline in the test. Do NOT modify any landed component, contract, or existing test.

PROVE AT LEAST (each an assertion over the REAL chain, DB-persisted where noted):
  1. ONE deterministic CONFIRMED exploit — a seed whose FAKE RESPONSE leaks the synthetic canary token; the
     CanaryOracle fires hit=True over the recorded response_transcript -> Judge -> state=EXPLOIT_CONFIRMED,
     confirmation_source in {oracle,canary}. (An in-transcript 'return safe' instruction must NOT downgrade it.)
  2. ONE NO-EXPLOIT result — a seed whose fake response is SAFE (canary NOT present); the oracle fires hit=False.
     HONESTY (binding): the MVP Judge does NOT emit NO_EXPLOIT_OBSERVED (it is gated behind the M10/M11
     calibration slice), so this OBSERVED-safe case yields a Judge verdict of INDETERMINATE (reason
     non_oracle_uncalibrated_indeterminate). Assert exactly that, and label the case 'observed no-exploit;
     MVP verdict INDETERMINATE (NO_EXPLOIT_OBSERVED calibration-gated)'. is_safe() must be False.
  3. ONE INDETERMINATE result — a case with NO deterministic oracle signal at all -> INDETERMINATE.
  4. ONE INTEGRITY FAILURE -> Judge state=ERROR (tamper the recorded content_hash / evidence, or drive the
     integrity-failed path; recorder.verify() fails closed; Judge returns ERROR, reason evidence_integrity_failed).
  5. ONE BUDGET / RATE / ABORT refusal — a RunPolicy whose budget/attempt/rate/timeout cap trips the gateway's
     HARD ABORT before dispatch; assert the gateway raised AbortError and NO AttemptResult was recorded / NO
     verdict produced for that attempt (a refusal, not an overrun).
  6. RESULTS PERSIST WITH CORRECT RUN/ATTEMPT CORRELATION — the AttemptResults are written to the DB by the
     Recorder; each carries (campaign_run_id, attempt_id); the corresponding Verdict carries the SAME pair; read
     them back from Postgres and assert the correlation holds across the chain (no orphan, no mismatch).
  7. NO AUTHORED EXPECTATION MISTAKEN FOR OBSERVED EVIDENCE — the verdict derives from the ORACLE over the FAKE's
     ACTUAL response, never from the seed's authored expected_safe_behavior. Prove it: take a seed AUTHORED as
     'expected safe' but program the fake to LEAK the canary -> the verdict is EXPLOIT_CONFIRMED (observed
     evidence overrides the authored expectation), and vice-versa a seed authored 'expected exploit' with a safe
     fake response -> INDETERMINATE. The corpus cases remain NOT_EXECUTED authoring records; only this campaign's
     freshly-recorded AttemptResults are 'observed'.
  8. COVERAGE-AWARE SELECTION at the AGENT level — drive RedTeam.run(cases, policy, coverage={...}) and assert the
     FIRST attempt physically dispatched to the fake belongs to the LEAST-COVERED category (closes the deferred
     M8 minor at the integration level).
  9. M6a RECONCILE — a matching content_hash reconciles OK; a tampered one reconciles DEGRADED (S9).

LABELLING (binding): the test module docstring + any printed summary must state these are OFFLINE DETERMINISTIC
results, NOT live results, and that NO hosted-model/target request occurs. Assert (patch socket to raise) that the
whole campaign opens NO socket.

CONSTRAINTS: real components only (no mocking the gateway/recorder/judge/oracle/reconcile); FakeTargetAdapter is
the sole target; injected clock/accounting for determinism; synthetic canary token only; no PHI; no network.
`

phase('Build')
const BUILD_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  files: { type: 'array', items: { type: 'string' } }, outcomes_proven: { type: 'array', items: { type: 'string' } },
  green_confirmed: { type: 'boolean' }, ruff_clean: { type: 'boolean' }, pytest_summary: { type: 'string' },
  real_components: { type: 'boolean' }, correlation_proof: { type: 'string' }, no_network_proof: { type: 'string' } },
  required: ['files', 'outcomes_proven', 'green_confirmed', 'ruff_clean', 'pytest_summary', 'real_components', 'no_network_proof'] }
const build = await agent(
  `You are building the OFFLINE DETERMINISTIC END-TO-END PROOF. Write tests/test_offline_e2e.py wiring the REAL
landed components per the SPEC, proving outcomes 1-9. Use the migrated_db fixture for DB persistence + correlation.
Program the P9 FakeTargetAdapter per case (leak the synthetic canary for the exploit case; safe for the no-exploit
case). Run \`. .venv/bin/activate && python -m pytest tests/test_offline_e2e.py -q\` GREEN, then the FULL suite
\`python -m pytest -q\` GREEN. ruff check + format clean. In correlation_proof, show the (campaign_run_id,
attempt_id) match between a recorded AttemptResult and its Verdict; in no_network_proof, show the socket-raise
guard. Confirm real_components=true (no mocking the gateway/recorder/judge/oracle/reconcile). Return the structured result.
${SPEC}`,
  { label: 'build:e2e', phase: 'Build', schema: BUILD_SCHEMA })

phase('Review')
const REVIEW_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  verdict: { type: 'string', enum: ['approve', 'changes_requested'] },
  findings: { type: 'array', items: { type: 'object', additionalProperties: false, properties: {
    severity: { type: 'string', enum: ['critical', 'important', 'minor'] }, location: { type: 'string' }, problem: { type: 'string' }, fix: { type: 'string' } },
    required: ['severity', 'location', 'problem', 'fix'] } }, summary: { type: 'string' } }, required: ['verdict', 'findings', 'summary'] }
const [review, security] = await parallel([
  () => agent(
    `Independent REVIEWER of the offline e2e proof in ${REPO} (read tests/test_offline_e2e.py + run it). Verify it
wires the REAL components (not mocks of the gateway/recorder/judge/oracle/reconcile), genuinely proves outcomes
1-9, the DB-persisted run/attempt correlation is real, and the MVP 'no-exploit -> INDETERMINATE' honesty holds
(NO_EXPLOIT_OBSERVED is never claimed). Would a broken chain (e.g. the oracle not actually run over the recorded
transcript) flip a test to fail? Report real issues only. ${SPEC}`,
    { label: 'review:e2e', phase: 'Review', schema: REVIEW_SCHEMA }),
  () => agent(
    `Independent SECURITY REVIEWER of the offline e2e proof in ${REPO}. Adversarially check:
  - Is any result presented as LIVE, or is any authored expectation (seed expected_safe_behavior) mistaken for
    OBSERVED evidence? (must be NO — the verdict must derive from the oracle over the fake's actual response.)
  - Does the campaign make ANY network/socket/hosted-model call? (must be NO — prove the socket-raise guard covers
    the whole campaign.)
  - Is the EXPLOIT_CONFIRMED genuinely oracle-driven (a real canary leak in the recorded transcript), not faked?
    Can an in-transcript instruction downgrade it? (must be NO.)
  - Does the integrity-failure case genuinely drive ERROR (fail-closed), and the budget-abort genuinely record NO
    AttemptResult? Any real PHI / secret / live URL in the fixtures?
Report concrete issues with severity + fix. Do NOT print .env.local. ${SPEC}`,
    { label: 'security:e2e', phase: 'Review', schema: REVIEW_SCHEMA }),
])

return { build, review, security }
