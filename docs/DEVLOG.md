# Development log

Append-only project record. Newest entries appear at the bottom.

## [2026-07-20] Repository and architecture foundation   ·   type: milestone
- What: Scaffolded the repository, operating rules, planning set, diagrams, threat model, and binding architecture.
- Why: Establish a requirements-traceable platform design before implementation.
- Result: Commits `ed690f1` through `057d4dc`; `PLAN.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, and `docs/planning/*`.
- Stage: Architecture Defense.

## [2026-07-20] Configure mechanisms; build graded control plane   ·   type: decision
- What: Selected OSS wrappers for scanners/infrastructure and custom implementation for coverage-driven orchestration, independent judging, documentation, and regression admission.
- Why: Existing tools provide mechanisms but not the platform's authorization, provenance, coverage, or independent-verdict guarantees.
- Alternatives: Commercial red-team platforms, a single attack-and-judge agent, and custom implementations of every scanner were evaluated and rejected.
- Result: Commits `2557e4b` through `8488bfe`; ADR-0001 and `docs/planning/DECISIONS.md` D1–D18.
- Stage: Architecture Defense.

## [2026-07-20] Core, contracts, and CI spine   ·   type: milestone
- What: Added the Python package, deterministic fake adapter, versioned contracts, typed errors, both-sided tests, GitHub CI, Gitleaks, and dev-workflow skills.
- Why: Create deterministic boundaries and gates before agents depended on them.
- Result: Commits `6ac39c0` through `a2273cc`; `src/agentforge`, `src/agentforge/contracts/v1`, and `.github/workflows/ci.yml`.
- Stage: P1–P11 foundation.

## [2026-07-21] Runtime, storage, and trusted execution foundation   ·   type: milestone
- What: Landed local runtime/readiness, env-isolated configuration, redacted secrets, Alembic/Postgres storage, per-agent roles, Policy Gateway, and append-only Execution Recorder.
- Why: Make authorization, cap enforcement, evidence integrity, and deployment readiness executable rather than architectural claims.
- Result: Commits `8148e5b` through `16c4267`, including reviewed swarm-ledger commits; migrations `0001`–`0002` and M1a/M2/M4 tests.
- Stage: MVP secure vertical slice.

## [2026-07-21] Observability and independent Judge   ·   type: milestone
- What: Added provider-neutral telemetry and the deterministic, fail-closed independent Judge.
- Why: Separate hostile attack generation from verdict authority and preserve oracle precedence.
- Result: Commits `d625774` through `f518daf`; `src/agentforge/observability` and `src/agentforge/agents/judge`.
- Stage: MVP secure vertical slice.

## [2026-07-21] Corpus, live adapter, Red Team, and offline proof   ·   type: milestone
- What: Authored and validated the nine-case corpus, packaged schemas, hardened the OpenEMR adapter preflight, added seed replay/mutation, and exercised the recorder-to-Judge chain offline.
- Why: Prove the attack/evidence/verdict path without claiming unauthorized target traffic.
- Result: Commits `7bc19f9` through `960ce2c`; `evals/`, M5/M8, and `tests/test_offline_e2e.py`.
- Stage: MVP secure vertical slice.

## [2026-07-21] Target-agnostic control plane and product surfaces   ·   type: milestone
- What: Integrated the campaign coordinator, target domain, durable `SKIP LOCKED` queue, Clerk authentication foundation, and React Operator Console.
- Why: Join independent components behind persisted exact-scope authorization and authenticated human workflows.
- Result: Commits `8edfc31` through `2b91d63`, merging PRs #7–#11; M11, queue, auth, and console test suites.
- Stage: M1d integration.

## [2026-07-21] Authenticated console and Railway runtime baseline   ·   type: milestone
- What: Integrated same-origin Web/API bearer auth, revision `0005`, multi-stage runtime packaging, and Railway service definitions.
- Why: Establish the deployable base consumed by the final MVP Runner/results integration.
- Result: Commit `9bf50e5`; draft PR #12 baseline.
- Stage: M1d integration.

## [2026-07-21] Authoritative Runner, results, Coverage, and security tools   ·   type: milestone
- What: Composed the private durable Runner, trusted target catalog, scoped credential boundary, synthetic cassette profile, revision `0006` result/tool repositories, authoritative Findings/Coverage, and bounded scanner integrations.
- Why: Deliver the presentation-critical two-person request → queue → Runner → nine cases → evidence/verdict/findings/Coverage sequence while keeping live traffic authorization-gated.
- Result: Current PR #12 working tree; `migrations/versions/0006_authoritative_results.py`, `src/agentforge/runner.py`, `src/agentforge/security_tools`, and `docs/evidence/ato/SECURITY_TOOL_EVIDENCE.md`. Local gates: 852 passed/3 skipped, 67 console tests, 3 Playwright tests, container clean/upgrade migrations, runtime/readiness smoke, Semgrep/pip-audit/ZAP/Promptfoo evidence.
- Stage: MVP release candidate; commit, CI, Railway and human Clerk/live authorization evidence pending.
