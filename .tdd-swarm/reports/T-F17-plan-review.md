# T-F17 hosted runtime/provenance plan review

Verdict: `REVIEW_CHANGES_REQUIRED`

The plan correctly locks the four requested OpenRouter models, package-owned/versioned prompt
content, a leading `system` role, independent Judge precedence, Runner-only provider credentials,
append-only physical-call observations, configured-versus-observed UI semantics, backend-gated
prompt text, dual-remote deployment, and separate live-campaign approval. Those decisions should be
preserved.

The following Important findings must be repaired before T-F17 RED dispatch.

## Findings

### F17-PR-1 — The proposed hosted Red Team cannot safely reach the existing Policy Gateway

`docs/planning/agent-runtime-provenance.md:94-97,145-150` and
`tickets/T-F17d.md:37-43` require hosted mutation followed by one trusted evaluator. The current
gateway path deliberately rejects every proposal that is not byte-for-byte the authorized corpus
seed (`src/agentforge/campaign/coordinator.py:378-394`). T-F17d owns only `runner.py`, a new
composition module, and a migration note (`tickets/T-F17d.md:8-13`); it does not own the coordinator,
gateway, mutation-policy contract, or contract registry. An implementation would either abort every
genuine hosted mutation or bypass the exact-corpus check by presenting mutated content as the seed.

Repair: make T-F17d depend on the final T-F16 gateway/scan contracts, and define a versioned,
authorization-hashed mutation envelope with parent seed hash, generation-policy hash, bounded
turn/string sizes, category/class/OWASP invariants, physical maximum, and exact permitted
transformations. Extend file/test scopes to the owning coordinator/gateway/contract files (or add a
predecessor ticket). Add negative tests for seed substitution, metadata drift, oversized/unbounded
sequences, and attempts to smuggle host/method/credential changes.

### F17-PR-2 — T-F17d has an undeclared cross-plan dependency and conflicting Runner ownership

The final-target remediation changes `runner.py` in T-F16e and T-F16f and changes the gateway seam in
T-F16b. T-F17d also owns `runner.py` but depends only on T-F17c. Wave numbers are not dependencies,
and this T-F17 branch does not contain the T-F16 tickets. Parallel execution can therefore produce
two incompatible composition roots or a merge that silently restores the old single-surface path.

Repair: declare the exact T-F16 prerequisite (at minimum the accepted T-F16f composition contract)
for T-F17d, establish one integration base/owner for `runner.py`, and add a combined test proving the
hosted runtime uses the final two-target, per-surface Policy Gateway path. T-F17a-c may remain
parallel because their scopes are disjoint.

### F17-PR-3 — The hosted Orchestrator is ceremonial rather than requirement-complete

The current hosted runtime receives one already-selected `authorized_case` and can only echo that
case (`src/agentforge/agents/hosted_runtime.py:146-171`). T-F17d preserves that one-case contract
(`tickets/T-F17d.md:37-39`). It never receives the PRD-required coverage gaps, open findings,
regressions, remaining authorized candidates, low-signal/cost state, or authority to choose/stop the
next bounded action. Calling this the production Orchestrator would misrepresent a hosted advisory
step as actual orchestration.

Repair: define a bounded, secret-free orchestration snapshot and authorized candidate set, require
the hosted Orchestrator to select/halt only within it, verify the selection deterministically, and
persist the signal/decision hashes. Add no-priority, stale-snapshot, unauthorized-selection,
cost-without-signal, and regression-trigger cases. If the deterministic Orchestrator remains
authoritative, label the hosted call as advisory in storage/UI instead of claiming it ran the
Orchestrator role.

### F17-PR-4 — Physical provider events have no implementable logical-execution correlation

T-F17b requires each physical attempt to bind to a logical `agent_execution`
(`tickets/T-F17b.md:30-38`). Today `HostedFourRoleRuntime` invokes the transport internally and only
receives successful lineage after the call (`src/agentforge/agents/hosted_runtime.py:300-351`);
there is no before-call lifecycle hook or logical execution id in the transport invocation. The
T-F17c criteria do not add that context, while T-F17d cannot edit `hosted_runtime.py`. Retry/error
events therefore cannot be atomically and durably attributed as planned.

Repair: add an explicit Runner-created invocation context before reservation/network I/O containing
organization, campaign, attempt, logical execution id, role, parent logical execution id, and
physical sequence. Pass it through the runtime/transport/event sink, enforce composite
organization/execution FKs and unique `(logical_execution_id, physical_sequence)`, and specify
idempotent reconciliation when either event or logical terminalization fails. Update T-F17c/d scopes
and tests accordingly.

### F17-PR-5 — The capability heartbeat can prove the wrong configuration/release

The plan keys hosted readiness only by database time and environment
(`docs/planning/agent-runtime-provenance.md:154-157`; `tickets/T-F17e.md:33-39`). A fresh heartbeat
for configuration A can therefore admit Web preflight for configuration B, an older prompt bundle,
another organization, or another image. Runner rejection later is safe for target I/O but the Web
readiness claim is false. The existing status table is only `(environment, component_id)` and its
availability constraint does not contain `unavailable` or `degraded`
(`migrations/versions/0007_runtime_telemetry.py:110-127`). T-F17e also cannot change `runner.py` or a
migration (`tickets/T-F17e.md:8-18`), so AC-1's verified/degraded publication is not reachable within
scope.

Repair: make capability evidence content-addressed to organization, exact configuration-set hash,
release/image digest, prompt-registry hash, credential-reference hashes (never values), environment,
and Runner instance/generation. Web preflight must match all of those to the campaign binding. Add
the necessary additive migration and Runner composition scopes, ensure startup failure overwrites
or supersedes prior operational capability immediately, and test wrong-org/config/release/prompt/
generation plus rollback overlap.

### F17-PR-6 — “Unavailable, never zero” is not closed across existing cost consumers

The new event contract is truthful, but existing logical executions default `measured_cost` to zero
(`src/agentforge/storage/models.py:1492-1499`) and Costs/Birdseye aggregate that field with
`coalesce`/`or 0` (`src/agentforge/api/postgres.py:1045-1072`;
`src/agentforge/api/birdseye.py:202-213`). T-F17f corrects only the Agents view and does not own
Birdseye. Failed/timeout hosted calls with unknown billing would still display as measured zero
elsewhere, contradicting the plan's global truth claim.

Repair: define one canonical measurement-state contract for logical and physical cost, prevent
unknown hosted cost from entering zero-valued aggregates, and make T-F18j (or an expanded T-F17
ticket) an explicit pre-deployment consumer migration for Costs/Birdseye/campaign totals. Add
partial-usage, timeout-after-send, mixed known/unknown, and no-double-count reconciliation tests.

### F17-PR-7 — The fixed provider cap cannot execute the required 100-case hosted baseline

The locked code cap is 56 physical provider calls
(`src/agentforge/agents/hosted.py:22-27`). A 100-case run needs at least 300 hosted calls
(Orchestrator + Red Team + Judge per case), before conditional Documentation and retries. The plan
does not state that the 100-case baseline is deterministic-only, shard it into separately authorized
campaigns, or safely revise the limit. As written, a “full hosted” baseline must abort before one
fifth of the corpus completes.

Repair: record one explicit requirement-level decision. Either (a) authorize a bounded 100-case
hosted profile with derived calls/cost/time and no hidden retries, or (b) label the 100-case baseline
deterministic and add a separately authorized statistically meaningful hosted sample. Tests and
deployment evidence must reject any UI/report claiming 100 hosted cases when the provider ledger
does not reconcile.

### F17-PR-8 — Prompt retrieval identity is under-specified for version and organization safety

T-F17f describes a “dedicated role endpoint” but also requires wrong-organization and prompt-hash
mismatch refusal (`tickets/T-F17f.md:47-52`). A role-only path cannot identify which staged or
historical prompt version/hash the user is viewing, nor prove that the requested content is
referenced by that organization's configuration/event.

Repair: define a content-addressed endpoint keyed by role plus prompt version/hash (and, preferably,
configuration-set hash), require that identity to be referenced by the authenticated
organization's staged configuration or provider event, compare exact package bytes/hash before
return, use generic authorization/not-found failure, and keep `Cache-Control: no-store`. Add
same-role multi-version, unreferenced hash, cross-org, stale UI selection, and package/config
mismatch tests.

## Required plan repair summary

1. Preserve the exact model lock:
   `anthropic/claude-opus-4.8`, `qwen/qwen3.5-397b-a17b`,
   `google/gemini-2.5-pro`, `openai/gpt-5.4`.
2. Add the T-F16 integration dependency and a single owner for the final Runner/gateway seam.
3. Specify authorized mutation and real Orchestrator decision contracts.
4. Add pre-call logical context and transactional/idempotent physical-event correlation.
5. Replace environment-only readiness with content-addressed capability evidence.
6. Close unknown-cost semantics across all consumers before production promotion.
7. Resolve the 56-call versus 100-case contradiction explicitly.
8. Make prompt retrieval content-addressed and organization-referenced.

After those repairs, rerun independent plan review before any RED test dispatch.
