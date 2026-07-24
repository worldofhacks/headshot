# Final-submission execution manifest (final review repair)

[locked-decision] Canonical requirements remain `Week_3_AgentForge.pdf`; this is not a replacement PRD/roadmap.

## Evidence boundary

- Base `23490ea`: 1001 Python passed/3 skipped, 75 console, 4 browser, dual CI green.
- Run `aceddc495808427992efbd2b73b3598d`: 9 HTTP 200, 9 evidence, 9 `INDETERMINATE`, $0.09 outbound.
- Judge baseline 60% agreement/33.3% false negatives/60% abstention is failed.
- [locked-decision] None proves calibrated safe/unsafe outcomes, finding, current-SHA four-agent live trace, production isolation, performance, or report.

## Closure ownership

| requirement family | owner(s) |
|---|---|
| mechanical swarm gates | T-F00 |
| sanitized export / final stale-doc matrix reconciliation | T-F01a / T-F01b |
| package-authority root contracts | T-F02 |
| Judge code / authorized calibration evidence | T-F03a / T-F03b |
| Red Team controls / authorized provider eval | T-F04a / T-F04b |
| versioned HostedRoleConfiguration domain/settings, release+full-input idempotency, append-only persistence/migration, public atomic staging | T-F04c |
| read-only authorization preflight, drift invalidation, secret-free Birdseye projection | T-F04g |
| shared OpenRouter credential/transport/identity, atomic worst-case reservation, reconciliation, caps/abort | T-F04f |
| operational smoke schemas/registry classification, content-addressed fixture, no-network manifest/review verifier | T-F04h |
| hosted Orchestrator/Documentation adapters, target-free composition, create-only atomic dual-manifest publication | T-F04d |
| authorized smoke execution plus distinct immutable Evidence/Security review records | T-F04e |
| durable trace / additive campaign-grant+review preflight / authorized current-SHA campaign | T-F05a / T-F05c / T-F05b |
| replay executor / authorized replay evidence | T-F06a / T-F06b |
| deterministic benchmark / separately authorized stress | T-F07a / T-F07b |
| measured cost from immutable hashes | T-F08 |
| ATO / failure drills+postmortem | T-F09a / T-F09b |
| release / genuine reports / demo-social-package | T-F10a / T-F10b / T-F10c |
| target readiness, measured threat defenses, OWASP breadth | T-F11 |
| ADR/architecture AI-use/rates/pagination | T-F12 |
| current-SHA published-contract-only integration | T-F13 |
| security-tool runtime / typed failure contracts | T-F14a / T-F14b |
| devlog/project story | T-F15 |

## Invariants

- No production code without reviewed failing deterministic tests; sampled behavior uses graded eval artifacts.
- Oracle confirmation cannot be downgraded; failed/absent calibration cannot yield LLM-only safe/likely.
- No network/spend/live traffic without the exact named authorization artifact; invalid preflight sends zero calls.
- Four hosted roles use pairwise-distinct authorization-selected OpenRouter model IDs and role-scoped sealed credential references; Judge and Red Team also have distinct prompts/rubrics and actual upstream endpoint identities.
- The public T-F04c staging command parses once, derives a schema-versioned full-four-role input hash and idempotency identity from domain+release SHA+input hash with actor audit-only, commits all four versions or none, returns the original set for same release/input, conflicts on same release/changed input, leaves records inactive, and emits only the set hash; T-F04g loads it read-only.
- Requested and returned model/provider/endpoint identities, physical retries, tokens, measured cost, trace/configuration/policy hashes, and schema status are exact evidence; identity drift or missing accounting fails closed without fallback.
- Before every physical attempt, one shared ledger atomically reserves worst-case input/output/reasoning tokens and USD from authorization-bound maxima, catalog price vector, price hash and `max_price`; the last exactly affordable attempt may dispatch, retries reserve again, concurrent roles cannot oversubscribe, and reconciliation replaces the reservation only with exact returned usage/cost.
- Catalog price drift, reasoning growth beyond reservation, identity drift, or missing accounting is terminal; missing usage/cost retains the full reservation as partial evidence and never creates spend capacity.
- The four smoke schemas are repository operational contracts: they are explicitly in `OPERATIONAL_SCHEMAS`, excluded from `SUCCESS_SCHEMAS`, and covered by generic root/package/wheel conformance.
- T-F04d publishes result/evidence smoke manifests only as an identical durable create-only pair beneath fixed roots using no-follow/exclusive same-directory staging, fsync, no-replace commit and recovery; pre-existing paths, symlinks, reused IDs, crashes, partial/unequal outputs, or missing commit state cannot become review inputs.
- T-F05c reads `campaign.json` itself and derives the canonical smoke-manifest and unequal Evidence/Security review hashes from that grant. Before T-F05b actions it mechanically composes exact target/host/surface/allowlist, corpus/synthetic-only, current deploy/release, provider-role configuration/policy, caps/rate/concurrency/timeout/USD/abort, expiry/principal, SMART lease, existing Policy Gateway, and T-F04h review checks; any mismatch is exit 4 with zero actions.
- No PHI/secrets/sessions/raw hostile evidence in artifacts; staging/test is never called production.
- Package contracts remain authoritative; root contracts are generated parity publications.
- Swarm never merges main, publishes critical findings, remediates, load-tests or posts socially autonomously.

## Deadline triage

- **P0 deterministic code:** T-F04c staging → T-F04g preflight/projection → T-F04f reserved transport → T-F03a/T-F04a roles → T-F04h contracts/verifier → T-F04d create-only composition → T-F05a lineage → T-F05c live-grant preflight. These scopes authorize no calls and hard-code no model IDs. T-F04h/T-F04d/T-F05c proceed with injected zero-network inputs after code dependencies even if external authorization is absent.
- **P1 human/external evidence:** T-F03b/T-F04b may remain zero-call `BLOCKED` without blocking deterministic code. T-F04e requires a create-only committed manifest pair plus distinct reviews; T-F05b cannot start until the exact T-F05c command accepts immutable `campaign.json` and all current target/deploy/corpus/configuration/smoke/review/lease/cap inputs.
- **P2 downstream packaging:** T-F12/T-F13 and every live/release/cost claim consume the landed four-role runtime/smoke hashes; otherwise the corresponding claims remain incomplete.

[locked-decision] P0 deterministic proof is prioritized; P1 human/external evidence and P2 packaging are reported blocked/incomplete if not safely achieved by noon. Full completion is not promised.

## Open owner gates

- [open-question] Authorize or replace four exact pairwise-distinct OpenRouter model IDs; the readiness report's allocation is only a proposal.
- [open-question] Provision four role-scoped sealed credential references and an expected upstream endpoint identity per role, with Judge materially independent from Red Team.
- [open-question] Approve exact provider data policy/ZDR disposition, catalog price hash/vector, `max_price`, maximum input/output/reasoning tokens, expiry, synthetic fixture hashes, and per-role/global call/token/USD/rate/time/retry/concurrency caps for T-F04e.
- [open-question] Assign distinct Evidence and Security reviewers whose immutable identities differ from the executor and one another.
- [open-question] Retain separate T-F03b Judge-calibration and T-F04b Red-Team-evaluation approvals; T-F04e does not broaden or replace either.
- [open-question] Supply immutable `campaign.json` with the exact T-F05c target/allowlist, corpus/synthetic, deploy/release, provider-role configuration/policies, smoke/review hashes, caps, expiry/principals, and SMART lease bindings; smoke/provider approval alone is never live-target authority.
