# Red-team gap-closure swarm

This bundle turns
[`docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-24.md`](../../security/RED_TEAMING_COVERAGE_REVIEW_2026-07-24.md)
into implementation-ready, parallel agent work.

It is deliberately outside `.tdd-swarm/prompts/`. The final-submission swarm has an
active, count-sensitive 82-prompt contract and user-owned changes. Do not copy these
prompts into that namespace until the active swarm is complete or deliberately paused.

## Preconditions

1. Read `AGENTS.md`, `CLAUDE.md`, the canonical PRD, this README, and the coverage review.
2. Choose and record one clean `<RED_TEAM_GAP_BASE_SHA>` after the active final-submission
   work has been integrated or explicitly set aside.
3. Preserve all user changes. Never reset, overwrite, or absorb unrelated work.
4. Serialize migrations in wave order: WP-02, WP-10, WP-04, WP-11, WP-16A, WP-18A,
   WP-15, then WP-19. Reserve one revision only after rebasing onto the sole current head,
   replace its `<MIGRATION_REV>` placeholder, and land it before allocating the next. WP-02 also
   replaces the obsolete hard-coded `0013` readiness assertion with the stronger invariant
   that the database is at the sole packaged head and that the graph remains descended
   from `0013`.
5. Run no provider call, target request, ZAP active scan, OAST callback, Clerk/Railway
   mutation, spend, publication, remediation, push, or main merge from WP-01 through WP-20.
   Those packages produce implementation prechecks only; none can establish that a
   capability is operational, demonstrated, regression-protected, or closed.
6. WP-21A is the zero-call authorization lock. WP-21B–D are the only parallel live
   execution prompts, WP-21E performs authorized live regression, and WP-21 reconciles
   their immutable evidence. Every live executor still makes zero external calls unless
   every named authorization and deployment prerequisite is present and valid.

## Live-only evidence law

Any dynamic target or platform behavior labeled operational, demonstrated,
regression-protected, or closed requires an authorized run of the exact deployed Railway
release through production code paths and genuine pinned providers, tools, processes,
browsers, scanners, collectors, and network boundaries. A target-behavior claim additionally
requires the exact owner-authorized deployed OpenEMR live test-environment URL.

The deployed target environment must be isolated from production patient data and contain
only seeded synthetic non-PHI patient records plus provisioned test principals on the
authorized surfaces. Those are live records in the live application, not fixture adapters.
Real PHI and production patient records remain prohibited.

Mocks, fakes, doubles, cassettes, checked-in response fixtures, in-process receivers,
loopback/fake-target harnesses, simulated artifacts, and local unit or integration tests are
engineering prechecks only. They may find defects but cannot advance a coverage stage,
support an operational label, validate a regression, or close a finding. A missing live
authorization, deployed dependency, test principal, seeded record, or observation point is
`BLOCKED`, never substituted with local evidence.

Static analysis, dependency audit, and secret scanning are release/supply-chain controls,
not target behavior. They require genuine fresh GitHub and GitLab jobs and attestations for
the exact deployed SHA. Their approved state is `VERIFIED_RELEASE_CONTROL`; it can support
a release-control criterion but can never establish an operational target capability or
LLM/Web behavioral coverage.

## Concurrency model

The root orchestrator consumes one of four agent slots. Launch at most three worker agents
at once.

| Wave | Parallel work packages | Dependency |
|---|---|---|
| 0 | WP-01 physical dispatch gate; WP-07 public shell; WP-08 ownership authorization | Clean base |
| 1 | WP-02 runtime DB roles; WP-09 evidence status; WP-13 broker foundation | Wave 0 integrated |
| 2 | WP-03 pinned destination; WP-10 evidence coverage states; WP-13A Garak | Wave 1 integrated |
| 3 | WP-04 delivery ambiguity; WP-06 platform readiness; WP-13B PyRIT | Wave 2 integrated |
| 4 | WP-05 queue recovery; WP-11 trusted observations; WP-13C Giskard | Wave 3 integrated |
| 5 | WP-12 target/platform surfaces; WP-13D Promptfoo; WP-16D governed process egress | Wave 4 integrated |
| 6 | WP-14 LLM/agentic corpus; WP-16A capture/editor/replay/diff | Wave 5 integrated |
| 7 | WP-13E proposed-tool-bundle integration; WP-16B fuzz/decoder/sequencer; WP-18A private OAST | Wave 6 integrated |
| 8 | WP-15 authorized mutation/review; WP-16C custom checks/search/organizer; WP-17 API/auth/ZAP | Wave 7 integrated |
| 9 | WP-13F static/CI security tools; WP-18B browser/WebSocket/SSE; WP-19 regression executor | Wave 8 integrated |
| 10 | WP-18C OAST deployment boundary; WP-19A security reporting | Wave 9 integrated |
| 11 | WP-19B contract stewardship | Wave 10 integrated |
| 12 | WP-20A runtime; WP-20B backend API; WP-20C console/report integration | Wave 11 integrated |
| 13 | WP-20 end-to-end composition and verification | Wave 12 integrated |
| 14 | WP-21A live authorization and deployment preflight | WP-20 integrated; zero external calls |
| 15 | WP-21B live platform controls; WP-21C live LLM/toolchain; WP-21D live Web/Burp workflows | WP-21A approved; parallel only when its isolated budgets and concurrency policy permit |
| 16 | WP-21E live right-reason regression and resilience | WP-21B–D evidence produced or honestly blocked |
| 17 | WP-21 evidence reconciliation and independent review | WP-21A–E complete or honestly blocked |
| 18 | WP-22 final independent audit | Consume approved WP-21 evidence and every blocker |

Within a wave, file ownership is intentionally disjoint. Do not broaden a package's write
scope. If a necessary change is outside scope, return `NEEDS_CONTEXT` with the exact path
and reason; the orchestrator assigns it to WP-20 or changes the wave plan explicitly.

## Finding-to-package map

| Review finding | Primary packages |
|---|---|
| RT-01 honest demonstrated coverage | WP-09, WP-10, WP-20; live proof WP-21C/D/E |
| RT-02 decisive trusted adjudication | WP-11; live proof WP-21C/D/E |
| RT-03 complete LLM/Agentic taxonomy | WP-12, WP-14; live proof WP-21C |
| RT-04 authorized mutation | WP-15; live proof WP-21C |
| RT-05 existing-tool depth | WP-13, WP-13A–F, WP-16D, WP-17; live proof WP-21B/C/D |
| RT-06 Burp workflows and honest parity | WP-16A–D, WP-17, WP-18A–C, WP-19A; live proof WP-21D |
| RT-07 real target surfaces | WP-12; live proof WP-21C/D |
| RT-08 continuous regression | WP-19; live proof WP-21E |
| RT-09 per-physical-request abort gate | WP-01; live proof WP-21B |
| RT-10 runtime DB isolation | WP-02; live proof WP-21B |
| RT-11 DNS rebinding | WP-03; live proof WP-21B |
| RT-12 lease recovery | WP-05; live proof WP-21B/E |
| RT-13 ambiguous retries | WP-04; live proof WP-21B/E |
| RT-14 readiness/public routes/ownership/status | WP-06–09; live proof WP-21B |
| Contract/package compatibility | WP-19B |
| Cross-cutting integration and proof | WP-20–22 |

## Burp capability routing

| Burp capability | Work package and honest boundary |
|---|---|
| Dashboard, Target, scope, site map | WP-12, WP-17, WP-20; live proof WP-21D |
| Browser and browser traffic history | WP-18B through WP-16D governed egress and WP-16A capture; live proof WP-21D |
| Proxy, Logger, Inspector, intercept/forward/drop | WP-16A governed analogue; raw MITM, response edit, CA/invisible proxy unsupported |
| Repeater and request sequences | WP-16A governed structured replay; live proof WP-21D; arbitrary raw-message replay unsupported |
| Intruder positions/modes/resource caps/extraction/minimization | WP-16B; live proof WP-21D |
| Scanner, crawl, OpenAPI/Postman/GraphQL | WP-17; live proof WP-21D under separate active/live authorization |
| Authentication, sessions, BOLA/BFLA/role matrix | WP-17; live provisioned-principal proof WP-21D |
| Sequencer token analysis | WP-16B; fresh live samples WP-21D; conversation ordering is not Sequencer |
| Decoder and byte/word/structured Comparer | WP-16B and WP-16A |
| Collaborator/OAST | WP-18A receiver plus WP-18C owner-gated deployment; live callback proof WP-21D; HTTP(S)-only and blocked by default |
| WebSocket and SSE | WP-18B; live proof WP-21D |
| DOM Invader, Clickbandit, Infiltrator-style observations | WP-18B; live proof WP-21D; runtime instrumentation blocked without an owner contract |
| Organizer, Search, BChecks-like checks | WP-16C safe declarative subset |
| Executive and technical reporting | WP-19A |
| BApp/Montoya arbitrary runtime extensions | Explicitly unsupported; never relabel WP-16C as equivalent |

## Existing-tool depth routing

| Existing tool | Depth package | Required live validation |
|---|---|---|
| Garak 0.15.1 | WP-13A allowlisted multi-family profile and native lineage | WP-21C genuine pinned process and accepted live records |
| PyRIT 0.14.0 | WP-13B bounded multi-turn attacks and converter chains | WP-21C genuine pinned process and live target/provider turns |
| Giskard 1.0.0b3 | WP-13C owned-target/RAG scenarios with truthful zero-result state | WP-21C genuine owned-target/RAG run and accepted live records |
| Promptfoo 0.121.19 | WP-13D red-team plugins, strategies, assertions, and multi-turn cases | WP-21C genuine pinned process and accepted live records |
| Shared LLM-tool execution | WP-13 broker separation, WP-16D process egress, WP-13E proposed bundles, WP-15 review | WP-21C deployed process/broker/physical-ledger parity |
| ZAP 2.17.0 | WP-17 authenticated/API/AJAX/passive and separately authorized active profiles | WP-21D deployed pinned process against authorized live target |
| Semgrep 1.170.0 | WP-13F framework-aware and taint profiles | WP-21B fresh exact-SHA GitHub/GitLab `VERIFIED_RELEASE_CONTROL`; never target-behavior coverage |
| pip-audit, npm audit, Gitleaks | WP-13F signed/hash-bound CI artifact ingestion | WP-21B fresh exact-SHA GitHub/GitLab `VERIFIED_RELEASE_CONTROL`; never target-behavior coverage |

## Prompt index

**Runtime trust boundary**

- [WP-01 physical dispatch gate](WP-01-PHYSICAL-DISPATCH-GATE.md)
- [WP-02 runtime DB roles](WP-02-RUNTIME-DB-ROLES.md)
- [WP-03 pinned destination](WP-03-PINNED-DESTINATION.md)
- [WP-04 delivery ambiguity](WP-04-DELIVERY-AMBIGUITY.md)
- [WP-05 lease recovery](WP-05-LEASE-RECOVERY.md)
- [WP-06 platform readiness](WP-06-PLATFORM-READINESS.md)
- [WP-07 public shell allowlist](WP-07-PUBLIC-SHELL-ALLOWLIST.md)
- [WP-08 ownership authorization](WP-08-OWNERSHIP-AUTHORIZATION.md)
- [WP-09 evidence status](WP-09-AUTHORITATIVE-EVIDENCE-STATUS.md)

**Role overlays**

- [Test Agent](ROLE-TEST-AGENT.md)
- [Implementer](ROLE-IMPLEMENTER.md)
- [Code/Test Reviewer](ROLE-CODE-REVIEWER.md)
- [Security Reviewer](ROLE-SECURITY-REVIEWER.md)
- [Ground-truth Reviewer](ROLE-GROUND-TRUTH-REVIEWER.md)
- [Applicability Reviewer](ROLE-APPLICABILITY-REVIEWER.md)
- [Evidence Reviewer](ROLE-EVIDENCE-REVIEWER.md)
- [Live Evidence Executor](ROLE-LIVE-EVIDENCE-EXECUTOR.md)

**LLM efficacy and existing tools**

- [WP-10 evidence coverage states](WP-10-EVIDENCE-COVERAGE-STATES.md)
- [WP-11 trusted observations](WP-11-TRUSTED-OBSERVATIONS.md)
- [WP-12 real target surfaces](WP-12-REAL-TARGET-SURFACES.md)
- [WP-13 broker foundation](WP-13-TOOL-BROKER.md)
- [WP-13A Garak](WP-13A-GARAK-DEPTH.md)
- [WP-13B PyRIT](WP-13B-PYRIT-DEPTH.md)
- [WP-13C Giskard](WP-13C-GISKARD-DEPTH.md)
- [WP-13D Promptfoo](WP-13D-PROMPTFOO-DEPTH.md)
- [WP-13E toolchain integration](WP-13E-TOOLCHAIN-INTEGRATION.md)
- [WP-13F static/CI security tools](WP-13F-STATIC-CI-TOOLS.md)
- [WP-14 full-spectrum corpus](WP-14-FULL-SPECTRUM-CORPUS.md)
- [WP-15 authorized mutation](WP-15-AUTHORIZED-MUTATION.md)

**Burp-style workflows and regression**

- [WP-16A request workbench](WP-16A-REQUEST-WORKBENCH.md)
- [WP-16B fuzz/Decoder/Sequencer](WP-16B-FUZZ-DECODER-SEQUENCER.md)
- [WP-16C custom checks/Search/Organizer](WP-16C-CUSTOM-CHECKS-SEARCH.md)
- [WP-16D governed process egress](WP-16D-GOVERNED-PROCESS-EGRESS.md)
- [WP-17 API/auth/ZAP](WP-17-API-AUTH-ZAP.md)
- [WP-18A private OAST](WP-18A-PRIVATE-OAST.md)
- [WP-18B browser/streaming](WP-18B-BROWSER-STREAMING.md)
- [WP-18C OAST deployment boundary](WP-18C-OAST-DEPLOYMENT-BOUNDARY.md)
- [WP-19 continuous regression](WP-19-CONTINUOUS-REGRESSION.md)
- [WP-19A security reporting](WP-19A-SECURITY-REPORTING.md)
- [WP-19B contract stewardship](WP-19B-CONTRACT-STEWARDSHIP.md)

**Integration and evidence**

- [WP-20A runtime integration](WP-20A-RUNTIME-INTEGRATION.md)
- [WP-20B backend API integration](WP-20B-BACKEND-API-INTEGRATION.md)
- [WP-20C console/report integration](WP-20C-CONSOLE-REPORT-INTEGRATION.md)
- [WP-20 end-to-end integration](WP-20-END-TO-END-INTEGRATION.md)
- [WP-21A live preflight](WP-21A-LIVE-PREFLIGHT.md)
- [WP-21B live platform controls](WP-21B-LIVE-PLATFORM-CONTROLS.md)
- [WP-21C live LLM/toolchain](WP-21C-LIVE-LLM-TOOLCHAIN.md)
- [WP-21D live Web/Burp workflows](WP-21D-LIVE-WEB-BURP.md)
- [WP-21E live regression and resilience](WP-21E-LIVE-REGRESSION.md)
- [WP-21 authorized evidence reconciliation](WP-21-LIVE-EVIDENCE-RECONCILIATION.md)
- [WP-22 final independent audit](WP-22-FINAL-INDEPENDENT-AUDIT.md)

## Required role sequence for every code package

For every code package from WP-01 through WP-20, including lettered subpackages:

1. Launch an independent Test Agent using `ROLE-TEST-AGENT.md` plus the work package.
2. Have an independent Test Reviewer confirm clean, criterion-tagged RED and freeze the
   test file hashes. A Test Reviewer uses `ROLE-CODE-REVIEWER.md` with `phase=test`.
3. Launch the Implementer using `ROLE-IMPLEMENTER.md`. Frozen tests are read-only.
4. Launch Code and Security reviewers in parallel using their respective role prompts.
5. Critical/Important findings go back to the Test Agent for a regression test, then to an
   independent Test Reviewer to re-review and re-freeze the complete test hash set, and
   only then to the Implementer. Reviewers never repair their own findings.
6. Integrate only when focused gates, `bash scripts/check.sh`, `git diff --check`, code
   review, and security review are green.

WP-11 additionally requires `ROLE-GROUND-TRUTH-REVIEWER.md` before a Judge identity can be
eligible. WP-14 requires both Ground-truth review for human labels and
`ROLE-APPLICABILITY-REVIEWER.md` for every proposed N/A record. WP-21B–E use
`ROLE-LIVE-EVIDENCE-EXECUTOR.md`; each executor must be independent of its launcher,
approver, Evidence Reviewer, Security Reviewer, Judge, and publisher. WP-21 uses independent
Evidence and Security reviewers. WP-22 is read-only except for its final report.

## Common variables

- `<WORKTREE>`: absolute worktree path.
- `<BRANCH>`: the branch named by the package.
- `<RED_TEAM_GAP_BASE_SHA>`: immutable base for the current wave.
- `<DIFF_BASE>`: normally `<RED_TEAM_GAP_BASE_SHA>`.
- `<PACKAGE_PATH>`: absolute or repo-relative work-package path.
- `<FROZEN_TEST_HASHES>`: reviewer-approved hashes from the Test report.
- `<REVIEW_SHA>`: immutable implementation commit reviewed by both parallel reviewers.
- `<REVIEW_BRANCH>`: unique report-only branch for one reviewer; never the package branch.
- `<MIGRATION_REV>`: orchestrator-reserved Alembic revision for that wave.
- `<AUTHORIZATION_ARTIFACT>`: a persisted, exact-scope authorization; never synthesize it.
- `<LIVE_PREFLIGHT_MANIFEST>`: the approved, immutable WP-21A manifest; never edit it from
  an execution lane.

Every agent must run `pwd` before its first write and verify it equals `<WORKTREE>`. Every
shell call must set that worktree explicitly. A mismatch returns `BLOCKED(worktree mismatch)`
without writing.

## Exact launch messages

Substitute variables; do not paraphrase away constraints.

**Test Agent**

> Worktree `<WORKTREE>`; branch `<BRANCH>`; base `<RED_TEAM_GAP_BASE_SHA>`; migration
> `<MIGRATION_REV>` if applicable. Read
> `docs/planning/red-team-gap-swarm/ROLE-TEST-AGENT.md` and `<PACKAGE_PATH>` completely
> and follow both as one prompt. Use `<DIFF_BASE>`. No writes outside the package's test
> scope and declared report.

**Test Reviewer**

> Worktree `<WORKTREE>`; branch `<BRANCH>`. Read
> `docs/planning/red-team-gap-swarm/ROLE-CODE-REVIEWER.md` with `phase=test`,
> `<PACKAGE_PATH>`, and the Test report. Verify intended RED and freeze exact test hashes.
> Write and commit only the declared test-review report on the sequential package branch;
> return its commit and SHA-256.

**Implementer**

> Worktree `<WORKTREE>`; branch `<BRANCH>`; base `<RED_TEAM_GAP_BASE_SHA>`; migration
> `<MIGRATION_REV>` if applicable. Read
> `docs/planning/red-team-gap-swarm/ROLE-IMPLEMENTER.md`, `<PACKAGE_PATH>`, the approved
> Test report, and `<FROZEN_TEST_HASHES>` completely and follow them as one prompt. Tests
> are frozen and read-only.

**Code Reviewer**

> Detached review worktree `<WORKTREE>`; unique report branch `<REVIEW_BRANCH>` at
> `<REVIEW_SHA>`. Read
> `docs/planning/red-team-gap-swarm/ROLE-CODE-REVIEWER.md` with `phase=code`,
> `<PACKAGE_PATH>`, all reports, and `<DIFF_BASE>..<REVIEW_SHA>`. Write and commit only the
> code-review report; return its commit and SHA-256.

**Security Reviewer**

> Detached review worktree `<WORKTREE>`; different unique report branch `<REVIEW_BRANCH>`
> at `<REVIEW_SHA>`. Read
> `docs/planning/red-team-gap-swarm/ROLE-SECURITY-REVIEWER.md`, `<PACKAGE_PATH>`, all
> reports, and `<DIFF_BASE>..<REVIEW_SHA>`. Write and commit only the security-review
> report; return its commit and SHA-256.

**Ground-truth Reviewer (WP-11/WP-14)**

> Detached review worktree `<WORKTREE>`; unique report branch `<REVIEW_BRANCH>` at
> `<REVIEW_SHA>`. Read
> `docs/planning/red-team-gap-swarm/ROLE-GROUND-TRUTH-REVIEWER.md`, the assigned WP, the frozen
> candidate manifest, and the existing human label/review artifacts. Validate only; never
> create or change a label. Write and commit only the declared review report.

**Applicability Reviewer (WP-14)**

> Detached review worktree `<WORKTREE>`; unique report branch `<REVIEW_BRANCH>` at
> `<REVIEW_SHA>`. Read
> `docs/planning/red-team-gap-swarm/ROLE-APPLICABILITY-REVIEWER.md`, WP-14, every proposed
> N/A record, and its existing human approval. Validate only; never create an approval.
> Write and commit only the declared review report.

**Evidence Reviewer (WP-21)**

> Detached review worktree `<WORKTREE>`; unique report branch `<REVIEW_BRANCH>` at
> `<REVIEW_SHA>`. Read `docs/planning/red-team-gap-swarm/ROLE-EVIDENCE-REVIEWER.md`, WP-21,
> every WP-21A–E prompt, every authorization/review record, and the produced live artifacts.
> Make no external call.
> Write and commit only the declared evidence-review report.

**Live Evidence Executor (WP-21B–E)**

> Deployed release `<REVIEW_SHA>`; immutable preflight `<LIVE_PREFLIGHT_MANIFEST>`;
> authorization `<AUTHORIZATION_ARTIFACT>`. Read
> `docs/planning/red-team-gap-swarm/ROLE-LIVE-EVIDENCE-EXECUTOR.md` and `<PACKAGE_PATH>`
> completely and follow both as one prompt. Execute only the manifest's exact lane through
> the deployed production code path. Seeded synthetic non-PHI live records only; no fixture,
> mock, cassette, fake-target, or local-harness substitution.

## Status contract

Code-work agents write their full report to the path declared by their role and return:

`DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)`

followed by commit identifiers, one-line gate status, and at most three concise concerns.
Ground-truth, Applicability, and Evidence Reviewers instead use the explicit
`APPROVED | REJECTED | BLOCKED` contract in their role prompt.

For WP-01–20, `DONE` means implementation and non-evidentiary engineering prechecks are
complete. It never means the capability is live, operational, demonstrated, or closed.
Live executors return `LIVE_EVIDENCE_PRODUCED | PARTIAL_LIVE_EVIDENCE | BLOCKED(reason)`;
only independently approved evidence may advance authoritative coverage.

## Closure standard

“Mapped” is not “covered.” WP-22 may close a behavioral gap only when the exact deployed
release and owner-authorized deployed target produced approved WP-21 live evidence through
production code paths, the Judge outcome is decisive, and a fresh authorized live
right-reason regression passed. Deterministic and local tests prove implementation only.
An honestly `INDETERMINATE` outcome remains a visible non-closing blocker. An absent
external authorization or live dependency is a legitimate `BLOCKED`, never permission to
use a mock, fixture, cassette, simulated artifact, or fake target as evidence.
