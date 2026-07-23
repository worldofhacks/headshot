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

## [2026-07-22] Final integration audit and authoritative four-agent offline slice   ·   type: milestone
- What: Audited all 72 PRD/optional/user/lead requirements; added verified-signal Orchestration, the typed Red Team proposal handoff, confirmed-only draft Documentation, fail-closed regression disposition, append-only revision `0008`, API projection updates, and current integration/migration evidence.
- Why: Close the highest-risk runtime gaps without fabricating deployed or human-gated evidence, while preserving exact-corpus authorization, independent Judge authority, synthetic-only fixtures, content-addressed lineage, and draft-only critical findings.
- Result: `codex/final-integration-audit` working tree. The authoritative local path is PostgreSQL snapshot → Orchestrator → Red Team → Policy Gateway → adapter → Recorder → PostgreSQL reread/hash verification → Judge → Documentation → regression disposition. Fresh gates: 955 Python tests, 71 console tests, 4 Playwright tests, 15 packaged contracts, clean `0003→0008` and `0008→0007→0008` container migrations, runtime/readiness smokes, and zero Semgrep/pip-audit/npm-audit/gitleaks findings. Final image: `sha256:4af41a54884a8cf918334e5a781c3e2aa510946048d82b9dfe934d4c9dbaf634`.
- Evidence: `docs/requirements/REQUIREMENTS_MATRIX.csv`, `docs/evidence/baseline/2026-07-22-final-integration.md`, `docs/integration/INTEGRATION_PACKET.md`, and `docs/integration/migration-notes/0008-documentation-regression.md`.
- Remaining: Judge calibration/drift, deterministic regression execution/target-version replay, performance/load baselines, current dual-CI proof after commit, and a distinct-human-approved bounded staging campaign. Passive health checks do not authorize `/chat`.
- Stage: Final integration candidate; no live campaign, publication, remediation, or regression promotion performed.

## [2026-07-23] Two-role authorization and four-agent runtime observability   ·   type: security correction
- What: Reduced Clerk Organization roles to Operator and Approver, removed the self-approval path,
  added database/runtime enforcement, and traced Orchestrator, Red Team, independent Judge, and
  Documentation executions through the durable ledger and console.
- Why: Human identity must never bypass two-person campaign authorization, and the Final platform
  must show real agent order, state, lineage, latency, and measured cost rather than inferred nodes.
- Result: Revisions `0009`-`0012`, role-matrix tests, four-agent Runner integration tests, Birdseye,
  agent operations, Judge calibration primitives, and regression replay primitives are present on
  `codex/final-integration-audit`.
- Remaining: The branch is not a Final release while canonical matrix rows remain partial, missing,
  or human-blocked, including novel/mutated turn-by-turn Red Team execution, automatic
  target-version regression runs, deployed calibration evidence, performance evidence, dual-CI
  proof, and a distinct-Approver-authorized live campaign.
- Stage: Integration branch; no merge, deployment, live campaign, publication, or remediation
  authorized by this entry.
