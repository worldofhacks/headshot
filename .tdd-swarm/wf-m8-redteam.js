export const meta = {
  name: 'm8-redteam',
  description: 'M8: independent Red Team — seed-corpus ingestion + coverage-aware selection + multi-turn sequencing + mutation interface + fake/cassette provider (hosted boundary behind explicit auth). Dispatches ONLY through the M4 Gateway (no creds, no evidence). No hosted-model/network call in tests. TDD + reviewer + security.',
  phases: [
    { title: 'Tests', detail: 'RED: seed replay, coverage selection, multi-turn, mutation, providers, gateway-only' },
    { title: 'Implement', detail: 'GREEN: agents/red_team/*' },
    { title: 'Review', detail: 'reviewer ∥ security' },
  ],
}

const REPO = '/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine'
const SPEC = `
REPO (main repo): ${REPO}   BRANCH: ticket/m8-redteam (off swarm/mvp-live-gate; has M2/M4/M5/M6a/M9 + M11 corpus
+ packaged schemas). venv at ${REPO}/.venv — activate for EVERY command:
  \`cd "${REPO}" && . .venv/bin/activate && <cmd>\`. Python 3.12; Postgres 16 UP. DO NOT git commit/push.
Gates: \`ruff check .\`, \`ruff format --check .\`, \`python -m pytest -q\`.

WHAT M8 DELIVERS — the INDEPENDENT RED TEAM (untrusted generator). ARCHITECTURE §3/§8/§16, F2/F7; PRD-14/17.
Deps P10 (contracts: attack_attempt.json), M4 (gateway/allowlist/credentials/recorder), M5 (adapter), P3 skill.
**NO hosted-model call, NO network in ANY test.** The offline path is seed-replay + a deterministic fake/cassette
provider; the HOSTED mutation path (OpenRouter/Together) sits behind an explicit-authorization + preflight gate
and is NEVER invoked in tests. Read src/agentforge/policy/gateway.py (PolicyGateway.execute — the RT's SOLE exit),
policy/{allowlist,credentials,recorder}.py, target/fake_adapter.py (P9), agents/judge/judge.py (M9),
observability/{coverage_view.sql,tracing.py} (M6a coverage), src/agentforge/evals/ (the seed corpus + validator),
contracts/v1/attack_attempt.json, and .env.example (HEADSHOT_RED_TEAM_PROVIDER / HEADSHOT_RED_TEAM_MODEL /
OPENROUTER_API_KEY / TOGETHER_API_KEY) before writing.

FILE SCOPE (impl): src/agentforge/agents/red_team/ (NEW): __init__.py, red_team.py (the agent),
  providers.py (provider protocol + fake/cassette + hosted boundary + provider/model validation),
  selection.py (coverage-aware case selection), mutation.py (mutation interface), seed_replay.py (seed
  ingestion -> AttackAttempt). Touch NOTHING else (not policy/target/observability/agents-judge/storage/
  evals/config/secrets/contracts). If a runtime provider SDK is needed, keep it BEHIND a lazy import inside the
  hosted provider only (never imported at package import; never called in tests).
FILE SCOPE (tests, Test Agent owns): tests/test_red_team.py, tests/test_red_team_providers.py,
  tests/test_seed_replay.py.

DESIGN (build to this):
seed_replay.py — ingest AttackCase seeds (from evals/seeds via the validator's loader or a read of the JSON)
  and map each to a schema-valid attack_attempt (contracts/v1/attack_attempt.json): case_ref, input_sequence
  (the multi-turn ordered turns), category. The RT emits ONLY an AttackAttempt — it produces NO credential, NO
  content_hash, NO verdict, NO trusted signal (evidence is the Recorder's/Judge's job, not the RT's). Seed
  replay is the fastest first live slice AND the offline e2e generator.
red_team.py — RedTeam agent. run(...) selects cases (coverage-aware), sequences multi-turn attempts, and
  dispatches EACH ONLY through PolicyGateway.execute(attack_attempt, run_policy, target_id=...) — the gateway is
  the SOLE path to any target; the RT holds NO adapter, NO credential, NO outbound path. The gateway (M4)
  enforces budget/rate/timeout/abort; the RT NEVER enforces or owns those caps and NEVER bypasses the gate. A
  gateway AbortError (budget/rate/timeout) propagates as a stop — the RT does not overrun it.
selection.py — coverage-aware selection: given the M6a coverage signal (the coverage_metric view / a supplied
  coverage snapshot), pick cases toward the LEAST-covered category first, so a partial success mutates toward
  the coverage gap. Deterministic given a fixed coverage snapshot (no randomness that breaks tests; vary by a
  seeded/injected order if needed).
mutation.py — a mutation INTERFACE: given a partial-success attempt, produce N variant AttackAttempts aimed at
  the least-covered category, preserving lineage (which seed a variant descends from). The DETERMINISTIC
  fake/cassette provider generates variants offline (no model); the HOSTED provider is the boundary for real
  generation (behind auth, never called in tests).
providers.py — a RedTeamProvider protocol (generate(...) -> variants). Implementations:
  * FakeProvider / CassetteProvider — deterministic, OFFLINE, no network (a cassette is recorded/replayed
    fixture responses); used for the offline slice + all tests. Handles a REFUSAL / EMPTY response by
    retry/switch (a refusal or empty generation is retried or switched to another cassette/strategy, NOT a
    silent stall).
  * HostedProvider — the OpenRouter/Together boundary. It is guarded by a PROVIDER/MODEL VALIDATION preflight:
    HEADSHOT_RED_TEAM_PROVIDER must be a supported provider AND HEADSHOT_RED_TEAM_MODEL must be non-empty AND a
    credential reference present; if HEADSHOT_RED_TEAM_MODEL is UNSET the hosted path FAILS preflight (a typed
    error) while fake/cassette/seed modes remain fully usable. The hosted provider requires EXPLICIT
    authorization to run and dispatches its generated attempts through the SAME gateway (budget/rate/abort). Its
    SDK import is lazy and it is NEVER invoked in a test — assert no network/provider SDK call occurs.

ACCEPTANCE (each test pins an edge/error; NO hosted-model/network call anywhere):
  (a) seed replay maps a multi-turn seed to a schema-valid attack_attempt (contracts validate it) carrying the
  ordered turns; the RT output has NO credential/content_hash/verdict/trusted-signal. (b) the RT dispatches ONLY
  via the gateway — a test asserts there is no path from the RT to a target/adapter that bypasses
  PolicyGateway.execute, and the RT holds no credential. (c) coverage-aware selection picks the least-covered
  category first; a partial spawns N variants toward that category (lineage preserved). (d) multi-turn (not
  single-prompt) sequences are dispatched in order. (e) a provider REFUSAL / EMPTY response is retried/switched,
  never a silent stall; (f) the gateway's budget/rate/timeout cap trips an ABORT that the RT respects (it does
  not overrun) — reuse the M4 gateway with an injected clock/accounting so it is deterministic; (g) hosted
  provider/model VALIDATION: HEADSHOT_RED_TEAM_MODEL unset -> hosted preflight typed-fails while fake/cassette/
  seed still work; a supported provider + non-empty model + credential ref -> hosted preflight ok BUT still
  requires explicit authorization (not auto-run); (h) assert NO network/socket and NO hosted-provider SDK call
  in any test (patch to raise if called). The Red Team NEVER produces Judge evidence and NEVER holds a credential.

CONSTRAINTS: NO hosted-model call, NO network, NO PHI in tests — fake/cassette + P9 fake + local Postgres only.
HEADSHOT_RED_TEAM_MODEL is the canonical model setting (do NOT add an alias, do NOT invent a model id). The RT
imports contracts/policy(gateway)/evals — NOT fastapi; any provider SDK is lazy inside the hosted provider only.
`

phase('Tests')
const TEST_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  test_files: { type: 'array', items: { type: 'string' } }, acs_covered: { type: 'array', items: { type: 'string' } },
  red_confirmed: { type: 'boolean' }, red_evidence: { type: 'string' }, no_network_proof: { type: 'string' }, notes: { type: 'string' } },
  required: ['test_files', 'red_confirmed', 'red_evidence', 'no_network_proof'] }
const testResult = await agent(
  `You are the TEST AGENT for M8. Write failing (RED) tests ONLY (tests/test_red_team.py,
tests/test_red_team_providers.py, tests/test_seed_replay.py) — no src. Cover EVERY AC incl. gateway-only dispatch,
RT-holds-no-creds/produces-no-evidence, seed->attack_attempt schema validity + multi-turn order, coverage-aware
selection toward least-covered, mutation variants + lineage, refusal/empty retry-switch, gateway budget/rate/
timeout abort respected, hosted provider/model validation (model unset -> hosted fails, fake/cassette still work),
and 'authorization required to run hosted'. Prove NO hosted-model/network/SDK call (patch to raise on use).
Dispatch through the REAL M4 gateway with the P9 fake + injected clock/accounting (deterministic). Run
\`. .venv/bin/activate && python -m pytest tests/test_red_team.py tests/test_red_team_providers.py
tests/test_seed_replay.py -q\` and CONFIRM RED (agentforge.agents.red_team.* import errors). ruff-clean. Do NOT
edit src or other tests. Return the structured result. ${SPEC}`,
  { label: 'test:m8', phase: 'Tests', schema: TEST_SCHEMA })

phase('Implement')
const IMPL_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  impl_files: { type: 'array', items: { type: 'string' } }, tests_untouched: { type: 'boolean' }, ruff_clean: { type: 'boolean' },
  pytest_summary: { type: 'string' }, green_confirmed: { type: 'boolean' }, gateway_only_mechanism: { type: 'string' }, design_notes: { type: 'string' } },
  required: ['impl_files', 'tests_untouched', 'ruff_clean', 'pytest_summary', 'green_confirmed', 'gateway_only_mechanism'] }
const implResult = await agent(
  `You are the IMPLEMENTATION AGENT for M8. Make the frozen RED tests GREEN by creating ONLY files under
src/agentforge/agents/red_team/. Do NOT edit tests. Build to the DESIGN: seed-replay -> schema-valid
attack_attempt; dispatch ONLY through PolicyGateway.execute (RT holds no creds, produces no evidence);
coverage-aware selection; multi-turn; mutation interface + lineage; fake/cassette provider (offline, refusal/
empty retry-switch); hosted provider behind provider/model-validation preflight + explicit authorization (SDK
lazy, never called in tests). The gateway (M4) owns budget/rate/timeout/abort — the RT respects, never owns them.
${SPEC}
Run the FULL suite \`. .venv/bin/activate && python -m pytest -q\` — all green (incl. pre-existing suites). ruff
check + format clean. \`git status --porcelain tests/\` shows no impl changes. In gateway_only_mechanism, describe
exactly how the RT can only reach a target through PolicyGateway.execute and holds no credential/evidence. Return
the structured result with the exact pytest summary line.`,
  { label: 'impl:m8', phase: 'Implement', schema: IMPL_SCHEMA })

phase('Review')
const REVIEW_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  verdict: { type: 'string', enum: ['approve', 'changes_requested'] },
  findings: { type: 'array', items: { type: 'object', additionalProperties: false, properties: {
    severity: { type: 'string', enum: ['critical', 'important', 'minor'] }, location: { type: 'string' }, problem: { type: 'string' }, fix: { type: 'string' } },
    required: ['severity', 'location', 'problem', 'fix'] } }, summary: { type: 'string' } }, required: ['verdict', 'findings', 'summary'] }
const [review, security] = await parallel([
  () => agent(
    `Independent CODE REVIEWER for M8 in ${REPO} (git --no-pager diff; read agents/red_team/* + the three test
files). Verify: seed replay yields schema-valid multi-turn attack_attempts; dispatch is ONLY via
PolicyGateway.execute; coverage-aware selection targets the least-covered category; mutation preserves lineage;
refusal/empty is retried/switched; the gateway abort is respected; hosted provider/model validation is correct
(model unset -> fail); tests are not tautologies. Run the suite. Report real issues only. ${SPEC}`,
    { label: 'review:m8', phase: 'Review', schema: REVIEW_SCHEMA }),
  () => agent(
    `Independent SECURITY REVIEWER for M8 (the UNTRUSTED generator boundary, F2). Adversarially audit in ${REPO}:
  - Does the Red Team hold ANY credential, adapter, or outbound path of its own, or can it reach a target
    WITHOUT PolicyGateway.execute? (must be NO — prove the only target path is the gateway.)
  - Does the RT ever produce Judge evidence (content_hash / AttemptResult / Verdict / a trusted signal)? (must be NO)
  - Can the RT overrun or bypass the gateway's budget/rate/timeout/abort? (must be NO — the gateway owns them.)
  - Is a hosted-model / provider SDK / network call made in ANY test or reachable without explicit authorization?
    (must be NO — model-unset fails preflight; SDK lazy; assert no call.) Does HEADSHOT_RED_TEAM_MODEL stay the
    canonical setting (no alias, no invented model id)?
  - Is any raw secret/credential inlined or logged? Any real PHI (fixtures must be synthetic)?
Report concrete bypass vectors with severity + fix. Do NOT print .env.local. ${SPEC}`,
    { label: 'security:m8', phase: 'Review', schema: REVIEW_SCHEMA }),
])

return { test: testResult, impl: implResult, review, security }
