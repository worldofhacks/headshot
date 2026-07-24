# Independent TDD re-review — OpenRouter four-role scope

**Disposition: CHANGES_REQUIRED**

Planning review only. No network, provider, credential, spend, target, deployment, or git action was performed.

## Closure audit

| Prior finding | Re-review result |
|---|---|
| C1 executable smoke path | **Closed.** T-F04d owns the exact execute/verify/verify-reviews CLI, four ordered dispatches, shared cap/abort state, target-adapter prohibition, typed manifest, and injected-transport reachability test. |
| C2 versioned authority binding | **Partially closed; Critical remains.** The record, migration, hashing, preflight, projection, and consumer rules are specified, but no reachable staging/persistence command is owned. |
| I1 independent Evidence/Security approval | **Closed.** T-F04e has separate create-only Evidence and Security prompts/records and verify-reviews enforces distinct identities and hashes. |
| I2 Judge adapter/independence | **Closed.** T-F03a owns strict Verdict adaptation, post-parse deterministic precedence, calibration gating, metadata, and every listed Red-Team collision dimension. |
| I3 hashed fixture/chain semantics | **Closed.** T-F04d owns the typed, authorization-bound fixture and positive/negative role-chain semantics. |
| I4 half-day split | **Not closed.** Transport was split out, but T-F04c and T-F04d remain multi-boundary tickets too large for the stated limit. |
| M1 exact T-F05b gate | **Closed.** The ticket and prompts name the exact offline command, both review records, unequal hashes, identities, and provenance comparisons before outbound work. |
| M2 overstated PASS | **Closed.** The amendment now says repaired/pending independent re-review. |

## Critical

### C1 — No owned command can create the persisted four-role configuration set

**Evidence:** T-F04c requires HostedRoleConfiguration to be derived from canonical settings, stored append-only, and selected by configuration-set SHA-256 (tickets/T-F04c.md:26-34). Its only named command is preflight_openrouter_roles.py with --check-only, whose acceptance criterion explicitly loads an already persisted set (tickets/T-F04c.md:33). The prompt likewise implements only configuration persistence and check-only preflight, but names no staging/publish invocation (.tdd-swarm/prompts/T-F04c-implement.md:1-4). Current external configuration surfaces cannot supply the full record: AgentConfigurationInput carries only provider/model/execution_mode/rationale (src/agentforge/api/router.py:171-175), and PostgresApiBackend forwards only those fields to configure_agent (src/agentforge/api/postgres.py:1394-1403). Neither API file is in T-F04c scope (tickets/T-F04c.md:8-17).

**Impact:** All downstream paths require a persisted configuration-set hash, but the plan defines no production or operator-reachable operation that can create that set. Tests can seed records by calling store internals and still pass while the exact smoke command remains unusable outside tests. Ad-hoc startup or preflight persistence would also violate the locked rule that check-only preflight is side-effect free and runtime consumers may not independently reinterpret environment authority.

**Repair:** Give one ticket an exact zero-network staging command and frozen reachability test. For example, add a create-only stage subcommand that parses the four canonical settings once, validates the complete set, persists all four versions atomically, returns only the configuration-set SHA-256, and refuses mutation/reuse conflicts. Alternatively expand the authenticated configuration API, which requires explicit scopes for api/router.py, api/postgres.py, request schemas/tests, and exact activation evidence. In either design, check-only preflight must remain read-only, staging must not activate or resolve secrets, and a test must invoke the public command/API then load the same set through preflight and T-F04d composition.

## Important

### I1 — T-F04c and T-F04d are still not half-day-sized

**Evidence:** T-F04c spans settings, runtime domain types, control-plane persistence, storage models, a migration, Birdseye projection, a CLI, and environment documentation in one ticket (tickets/T-F04c.md:8-17), with unit, migration, store-integrity, projection, drift, and preflight work (tickets/T-F04c.md:29-40). T-F04d spans composition, two hosted role adapters, three CLI modes, four package schemas, four root publications, a content-addressed fixture, review verification, and full integration/E2E behavior (tickets/T-F04d.md:8-24,36-48). The repaired self-check still treats them as bounded code tickets (.tdd-swarm/reports/openrouter-scope-amendment.md:140-143).

**Impact:** Each ticket crosses several failure and review boundaries. A single three-loop implementation/review budget can produce a superficially green slice that omits migration/API reachability, schema publication, reviewer-record integrity, or role composition. This does not satisfy the requested at-most-half-day sizing.

**Repair:** Split T-F04c into at least (a) configuration domain/settings plus atomic staging/persistence/migration and (b) read-only preflight/projection/activation-drift checks. Split T-F04d into at least (a) smoke schemas/fixture/hash/offline verification and (b) Orchestrator/Documentation adapters plus executable composition. Preserve dependency order configuration persistence -> preflight -> transport/roles -> contracts/fixture -> executable composition -> lineage. Give every split its own test scope and five-role TDD prompts.

### I2 — USD/token caps do not explicitly reserve worst-case spend before dispatch

**Evidence:** T-F04f requires exact measured accounting and says limits are charged atomically before the next dispatch (tickets/T-F04f.md:28-30), but it never requires a pre-dispatch reservation using authorized max input/output/reasoning tokens and price bounds. Its strict request criterion names routing/data policy but not authorization-bound max_price or equivalent price ceiling (tickets/T-F04f.md:27). The test prompt covers accounting/cap races but does not name a final-call projected-cost overshoot case (.tdd-swarm/prompts/T-F04f-test.md:1-4).

**Impact:** An implementation may dispatch while measured spend is below the cap and discover afterward that the response crossed the authorized USD/token ceiling. Stopping before the following call preserves accounting but does not preserve the hard cap.

**Repair:** Require an atomic pre-dispatch reservation for one physical attempt using authorization-bound maximum input/output/reasoning tokens and catalog price/max_price, followed by reconciliation to exact returned usage/cost. Refuse when the reservation would exceed any role/global cap; retain the reservation as measured/estimated partial evidence when usage is missing. Add boundary tests for the last affordable call, a retry, price drift, reasoning-token growth, and concurrent roles.

## Minor

### M1 — Contract enumeration ownership is implicit

**Evidence:** T-F04d adds four package contract schemas (tickets/T-F04d.md:15-18), while the current registry enumerates all success boundaries in a fixed SUCCESS_SCHEMAS tuple (src/agentforge/contracts/registry.py:41-62). Neither registry.py nor generic contract-conformance tests are scoped by T-F04d.

**Repair:** State whether smoke authorization/fixture/manifest/review are deliberately outside SUCCESS_SCHEMAS. If they are repository contracts, scope registry enumeration and generic wheel/conformance coverage; if operational-only, document that classification and keep explicit T-F04d validation tests authoritative.

### M2 — Deadline step incorrectly conditions deterministic T-F04d on external authorization

**Evidence:** TICKETS.md:62 says T-F04d runs beside authorized T-F03b/T-F04b only when their artifacts exist, but T-F04d is deterministic no-network code and does not depend on those evidence tickets (tickets/T-F04d.md:5-6,44-48).

**Repair:** State that T-F04d proceeds after its code dependencies regardless of T-F03b/T-F04b authority; only the parallel evidence tickets block at zero calls.

## Verified safety properties

The repaired plan now explicitly covers four distinct non-default OpenRouter models; role-scoped sealed references; Judge/Red-Team prompt, model-family, credential, expected and actual upstream independence; strict structured output plus repository contracts; exact returned identity; no fallback drift; physical call/retry/token/USD lineage; shared abort; target_scope:none synthetic smoke; zero-call preflight; deterministic oracle/policy authority; no live target in smoke; separate review records; and an exact T-F05b offline prerequisite. Wave dependencies resolve and the declared overlapping file scopes are serialized.

**Final: CHANGES_REQUIRED**

