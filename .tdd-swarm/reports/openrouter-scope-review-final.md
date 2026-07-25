# Final independent TDD re-review — OpenRouter four-role amendment

**Disposition: CHANGES_REQUIRED**

Planning review only. No application/test code, credential, authorization, network/provider/target call, spend, deployment, or git state was changed.

## Required finding closure

| finding | result |
|---|---|
| C1 — reachable atomic staging | **Closed.** T-F04c owns the public zero-network staging CLI, one-pass four-role parsing, four-or-zero transaction, staged-only state, canonical set hash, idempotent retry/conflict behavior, migration references, and frozen public-reachability tests. T-F04g and T-F04d consume the same public set hash rather than seeding store internals. |
| I1 — half-day splits/scopes/dependencies | **Closed.** Configuration staging/persistence is separated from read-only preflight/projection (T-F04c → T-F04g); smoke contracts/fixture/offline verification are separated from adapters/composition (T-F04h → T-F04d). Each has a unique test scope and five TDD prompts. Dependencies serialize every declared shared source boundary. |
| I2 — atomic worst-case token/USD reservation | **Closed.** T-F04f reserves per-role/global calls, concurrency, maximum input/output/reasoning tokens, and worst-case USD before every physical attempt under one shared atomic ledger, then reconciles exact usage. Last-affordable, retry, missing-usage, price-drift, reasoning-growth, reconstruction, and concurrency cases are required in tests and reviews. |
| M1 — registry/conformance ownership | **Closed.** T-F04h explicitly owns `registry.py`, `OPERATIONAL_SCHEMAS`, `SUCCESS_SCHEMAS` exclusion, root/package/wheel parity, lookup, and generic conformance. |
| M2 — deterministic deadline wording | **Closed.** T-F04h/T-F04d depend only on landed deterministic code and proceed with injected no-network transports even if T-F03b/T-F04b remain authorization-blocked. |

The plan also preserves pairwise-distinct authorization-selected model and sealed-reference identities; Judge/Red-Team prompt, rubric/criteria, family, expected endpoint, and actual endpoint independence; strict repository output contracts; exact returned identity; no fallback; target-free synthetic smoke; separate executor/Evidence/Security principals; bounded physical-call accounting; and fail-closed authorization/preflight behavior through T-F04e.

## Critical

### C1 — T-F05b no longer mechanically enforces the exact live-target authorization, and its review hashes are not bound to `campaign.json`

**Evidence:** The amended T-F05b AC-1 names only the smoke `reviews` verifier and replaces the earlier target authorization checks (`tickets/T-F05b.md:20-24`). The exact verifier invocation accepts the manifest, two review records, caller-supplied expected hashes, release SHA, and configuration-set SHA, but it does **not** accept `docs/evidence/authorizations/campaign.json` (`tickets/T-F05b.md:21`; `.tdd-swarm/prompts/T-F05b-execute.md:2-4`). Therefore it can prove that the supplied artifacts agree with each other, but cannot prove that the expected review hashes or smoke provenance came from the immutable campaign grant. The same amended AC also omits mechanical verification of the live target/surface/host/allowlist, corpus and synthetic-fixture hashes, SMART lease generation/expiry, launcher/distinct approver, credential binding, and budget/rate/abort caps before outbound work. AC-3 only says a later breach aborts (`tickets/T-F05b.md:23`); it is not a pre-dispatch authorization contract. This contradicts the manifest claim that no live traffic occurs without exact authorization (`.tdd-swarm/final-submission-manifest.md:43,50`) and the still-open owner gate in `TICKETS.md:84`.

**Impact:** An executor could pass the named smoke-review command with hashes copied from somewhere other than the approved campaign grant, or proceed without a ticket-verifiable exact target/lease/synthetic-data authorization. Provider spending approval and reviewed target-free smoke would then be capable of being mistaken for live-target authority.

**Exact repair:** Restore the original live-campaign preflight as a separate acceptance criterion and prompt step: exact release, target/surface/host/allowlist, corpus and synthetic-fixture hashes, provider/policy/configuration hashes, credential binding, SMART lease generation/expiry, launcher and distinct approver, and aggregate/per-role call/token/USD/rate/time/retry/concurrency/abort caps; any mismatch must exit 4 with zero secret/provider/target actions. Add a deterministic code/test owner before T-F05b for the new smoke-review binding (new small ticket, or an explicitly scoped existing deterministic ticket). Its public preflight/verifier must read `campaign.json` itself and compare the authorization-bound manifest hash, unequal Evidence/Security review hashes, release/configuration/fixture and provider-policy provenance—do not accept those values only as free CLI substitutions. Make T-F05b depend on that landed verifier and invoke it exactly before any outbound action. Preserve the existing Policy Gateway checks; the new smoke gate is additive, not a replacement.

## Important

### I1 — The smoke manifest is called immutable but its producer has no create-only/atomic write contract

**Evidence:** T-F04e calls the manifest immutable before the two create-only reviews (`tickets/T-F04e.md:27-29`), and downstream T-F05b trusts review hashes over it. But the execution prompt merely writes `evals/results/openrouter-smoke/<RUN_ID>/manifest.json` and copies it to `docs/evidence/openrouter-smoke/<RUN_ID>/manifest.json`; unlike the review prompts, it does not refuse existing paths or require atomic/no-follow creation (`.tdd-swarm/prompts/T-F04e-execute.md:2-4`). T-F04d/T-F04h own the executable/verifier code, yet neither ticket requires create-only manifest output or a negative overwrite/symlink test (`tickets/T-F04d.md:28-38`; `tickets/T-F04h.md:38-45`).

**Impact:** A reused run ID can overwrite the evidence object that independent review and the live-campaign prerequisite are supposed to make immutable. Hash mismatch may detect some later tampering, but the plan does not prevent replacement, partial copy, or path redirection at creation time.

**Exact repair:** Assign the behavior to the code owner of the execute CLI (T-F04d) and add reviewed RED tests: both result/evidence paths must be absent regular files beneath fixed roots; creation uses atomic create-only/no-follow semantics; an existing file, symlink, path escape, partial dual-write, or reused run ID fails without overwrite; the two published manifest bytes and canonical SHA-256 must be identical. Amend T-F04e AC/prompt to require those exact semantics before reviews start, and add the cases to T-F04d Security Review (T-F04h verifier may additionally reject unsafe/noncanonical paths, but offline validation alone is not a substitute for safe creation).

## Minor

### M1 — T-F04c does not define the idempotency identity named by AC-4

The public command exposes `--release-sha` and `--actor-ref`, while AC-4 refers to “the same idempotency identity” without defining whether that is the release, actor, tuple, set hash, or a separate request key (`tickets/T-F04c.md:31-32`). Define the exact canonical idempotency key/domain in the CLI contract and frozen tests; do not overload the actor identity in a way that prevents legitimate later staged versions.

## Structural checks

- Parsed all 32 `T-F*` ticket frontmatters: zero missing dependencies and every dependency points to an earlier wave.
- `TICKETS.md` wave table matches all 32 ticket frontmatters.
- Zero same-wave exact file/test-scope collisions were found.
- All 49 expected prompts exist for T-F03a through T-F05b, including five-role TDD sets for T-F04c/d/f/g/h and separate Execute/Evidence/Security prompts for T-F04e.
- No readiness-report proposed model ID is hard-coded in the reviewed tickets, prompts, index, or manifest.
- The planned public stage → preflight → execute → offline manifest/review command chain is present.

**Final: CHANGES_REQUIRED — Critical 1, Important 1, Minor 1.**
