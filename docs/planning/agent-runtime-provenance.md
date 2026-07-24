# P0 hosted agent runtime and provenance remediation

Status: planning only
Base: `1ac3ee02be7855b638dd1fa43bb0612a3db5f025`
Posture: production-grade

The base above is the planning/audit seed, not T-F17d's implementation base. T-F17d may start RED
only after the accepted T-F16f final two-target composition commit is mechanically recorded, and
its GREEN branch must be cut from that commit plus accepted T-F17a-c. T-F17d is then the sole
post-T-F16 owner of `runner.py` and the Policy Gateway mutation seam; T-F16e/f and T-F17d must never
run or merge in parallel. T-F17e is the next serialized `runner.py` owner.

## Outcome

[locked-decision] Production campaigns with a `HostedRunBinding` will execute the real
`HostedFourRoleRuntime` in the private Runner with these exact OpenRouter model assignments:

| Role | Requested model |
|---|---|
| Orchestrator | `anthropic/claude-opus-4.8` |
| Red Team | `qwen/qwen3.5-397b-a17b` |
| Judge | `google/gemini-2.5-pro` |
| Documentation / Reporter | `openai/gpt-5.4` |

[locked-decision] The Web service will not construct an OpenRouter client, resolve a provider
credential, or execute an agent. It will derive hosted-runtime availability from a fresh,
Runner-owned, secret-free, content-addressed capability observation in PostgreSQL that exactly
matches the campaign's organization, configuration, release, image, deployed revision, prompt
registry, credential-reference set, environment, and Runner generation. It exposes only
authenticated, permission-checked projections.

[locked-decision] A configured assignment and an observed execution are different facts. The
console will never label a requested or staged model as the model that ran. A provider-confirmed
model, upstream provider, request id, token usage, and measured cost appear only when an immutable
provider-call event proves them. Missing evidence renders as `not observed`, never as zero or an
inferred value.

## Current gap at the base commit

The repository already contains strong but disconnected pieces:

- `HOSTED_ROLE_MODELS` freezes the four requested model ids.
- `HostedConfigurationSet` binds role model, upstream, prompt hash, policy hash, prices, and limits.
- `OpenRouterTransport` disables fallback and rejects returned model/provider mismatch.
- `HostedFourRoleRuntime` preserves Judge independence and deterministic precedence.
- `HostedRunBinding` binds configuration, generation policy, limits, and session generation into
  campaign authorization.
- `agent_executions` records logical role activity, while the Agents page displays assignments and
  aggregate activity.

The production path is still incomplete:

1. `DurableCampaignRunner` constructs the deterministic Orchestrator, seed-replay Red Team,
   deterministic Judge path, and deterministic Documentation Agent. It never constructs
   `HostedFourRoleRuntime`.
2. `HostedFourRoleRuntime._invoke()` sends only a `user` message. The configured
   `prompt_sha256` is not resolved to exact content and does not protect a system message.
3. There are no versioned system-prompt resources in the wheel.
4. Provider response lineage exists only in a transient `OpenRouterResult`; it is not durable.
5. `agent_executions.provider/model` come from the configured assignment before execution, not
   from the provider response. The UI presents those fields as the engine that ran.
6. Web passes `hosted_runtime_available=False` and hard-codes `runner_available=True`; these are
   process-local claims rather than a fresh Runner observation.
7. The Agents API and UI expose neither prompt content/version nor provider-confirmed execution
   lineage.

## Required architecture

```text
versioned prompt resources ──hash/role/version──┐
staged HostedConfigurationSet ──exact hash─────┤
authorized HostedRunBinding ──caps/policy──────┤
Runner-only secret resolver ──OpenRouter key───┤
                                                v
                                   HostedFourRoleRuntime
                  authorized snapshot/candidates -> Orchestrator select/halt
                                                -> Red Team mutation envelope
                                                -> per-surface Policy Gateway
                                                -> Judge -> Documentation
                                                      |
                   +----------------------------------+------------------+
                   |                                                     |
 provider_call_invocations/events                            agent_executions
 reserved + terminal physical lineage                    logical role lifecycle
                   |                                                     |
                   +---------------- PostgreSQL -------------------------+
                                             |
                              authenticated Web read models
                                             |
                         configured assignment != observed execution
```

### Prompt authority

[locked-decision] The four prompts are immutable UTF-8 package resources under
`agentforge.agents.prompts`. Their raw bytes, including trailing newline, are the hash authority;
there is no whitespace normalization, environment override, browser authoring, or database prompt
body. A registry returns `(role, version, sha256, content)` and rejects missing, duplicate,
role-mismatched, altered, oversized, non-UTF-8, or secret-shaped prompt resources.

[locked-decision] Each role prompt must encode its trust boundary:

- Orchestrator may select or halt only within the supplied authorized candidate set and fresh
  coverage/cost/regression snapshot; it cannot widen target, corpus, surface, caps, approval,
  publication, or remediation authority.
- Red Team treats retrieved/target content as hostile, mutates only authorized work, never judges,
  approves, publishes, or opens a target connection.
- Judge is independent of attack generation, treats evidence as hostile, preserves deterministic
  oracle/canary precedence, never marks a confirmed exploit safe, and abstains fail-closed.
- Documentation produces a draft from the verified verdict/evidence contract, never publishes or
  remediates, never invents reproduction evidence, and excludes secrets and PHI.

[locked-decision] Before any provider call, the runtime resolves the prompt by role, verifies that
its raw-byte hash exactly equals the role configuration's `prompt_sha256`, and sends exactly two
messages: one leading `system` message containing that prompt and one `user` message containing the
canonical structured input. The transport rejects zero, multiple, misplaced, or caller-supplied
system messages before network I/O.

### Durable provider-call lineage

[locked-decision] Logical activity remains in `agent_executions`. Before reservation or network
I/O, the Runner transactionally creates the logical execution and an immutable
`ProviderInvocationContextV1`/`provider_call_invocation` containing organization, campaign, campaign
attempt, logical execution id, parent logical execution id, role, physical sequence, idempotency
key, and all bound configuration/prompt/policy hashes. The transport receives that context; it
cannot invent or repair identity after a response. Composite organization/execution foreign keys
and unique `(organization_id, logical_execution_id, physical_sequence)` prevent cross-org or
duplicate attribution.

[locked-decision] A new append-only `provider_call_events` relation records exactly one terminal
fact per committed physical invocation:

- organization, campaign, logical agent execution, attempt sequence, and role;
- requested model and configured upstream;
- provider-confirmed returned model, upstream provider, and request id when present;
- prompt version/hash, configuration-set hash, role-configuration hash, and generation-policy hash;
- input, output, and reasoning tokens when provider usage is valid;
- measured cost only when the provider reports it, with an explicit measurement state;
- physical status, sanitized typed error code, start/finish timestamps, and duration.

[locked-decision] Failed calls never manufacture a provider identity, token count, or zero cost.
Transient retry attempts remain individually visible. The store writes the terminal provider event
and logical terminalization in one transaction. Replaying the same canonical terminalization is
idempotent; changed facts conflict. A crash after send with no durable response is reconciled as
`outcome_unknown` and is never retried. Recovery can terminalize a committed invocation but cannot
create an unreserved physical sequence. Raw provider bodies, messages, prompt text, credentials,
target sessions, hostile evidence, and exception strings are never stored. Database grants permit
only the private Runner to insert and authenticated Web/Runner roles to read;
UPDATE/DELETE/TRUNCATE are rejected.

### Canonical cost measurement

[locked-decision] Logical and physical cost use one closed measurement contract:
`measured`, `partial`, `not_observed`, or `invalid`; a numeric value is permitted only for
`measured` or the known subtotal of `partial`. Unknown is SQL `NULL`, never `0`. Existing unproven
logical zeros are migrated to `not_observed`, not treated as free calls. Provider events are the
only hosted currency-cost aggregate source; logical summaries reference their source event ids and
cannot be added again.

[locked-decision] Every Costs, Birdseye, campaign-total, report, and Agents projection returns
`known_sum`, `measured_count`, and `unknown_count`. Mixed evidence renders a partial known subtotal
plus the unknown count; it never presents a complete total. T-F18j, based on accepted T-F17b/c,
owns the shared Costs/Birdseye/campaign consumer migration and must include
`src/agentforge/api/birdseye.py`. T-F17e production promotion mechanically depends on the accepted
T-F18j commit. Partial usage, timeout-after-send, mixed known/unknown, and no-double-count tests are
deployment blockers.

### Hosted Runner path

[locked-decision] A campaign without `scope.hosted_run` preserves the deterministic execution path.
A campaign with `scope.hosted_run` must take the hosted path or fail before provider/target I/O;
there is no deterministic fallback.

[locked-decision] Hosted preflight must:

1. load the exact staged configuration set, final T-F16f scan plan, parent/eight-child decisions,
   and per-surface gateway policies by organization and bound hashes;
2. validate configuration content, fixed role models, limits, generation policy, and prompt hashes;
3. verify all four Runner-only credential references are distinct and resolvable without exposing
   values;
4. verify current campaign authorization, target/session binding, caps, queue lease, and synthetic
   data controls already required by the Runner;
5. construct one shared OpenRouter usage ledger and concurrency-one transport;
6. verify the exact bounded provider-call formula and reserve its token/cost/time maximum; and
7. refuse with a typed, sanitized blocker before any provider or target call if any fact differs.

#### Coverage-driven Orchestrator

[locked-decision] The deterministic coordinator creates an immutable, secret-free
`OrchestrationSnapshotV1` and authorized candidate set before each selection. The content-addressed
snapshot binds organization/campaign/scan-plan revision, remaining candidate ids and parent seed
hashes, boundary/invariant/regression and OWASP gaps, open finding severities, regression history,
recent signal, known/unknown cost state, remaining provider/target/token/time caps, and expiry.
The hosted Orchestrator returns exactly `select(candidate_id, reason_codes)` or
`halt(reason_code)`. Runner rejects stale snapshots, a candidate not in the set, exhausted caps,
and changed hashes before later I/O; it persists the snapshot, candidate-set, decision, and
signal-state hashes. Selection drives the next case, so the role is operational, not advisory.
No-priority, stale-snapshot, unauthorized-selection, cost-without-signal, and regression-trigger
tests are mandatory.

#### Authorized mutation envelope

[locked-decision] The Red Team never submits an unbound replacement case. It returns a versioned
`HostedMutationEnvelopeV1` that binds organization/campaign, selected candidate, parent seed bytes
hash, orchestration snapshot/decision, generation policy, target/surface/version/policy, method/path
template, credential-reference, category/class/OWASP mappings, mutation ordinal, generated byte
length, turn/string limits, and reserved physical maximum. The mutation-policy hash enumerates the
only mutable JSON pointers and permits exactly: bounded replacement of a declared mutable string;
bounded prefix/suffix insertion at that string; or substitution of a named token from a closed
value set. It cannot add/delete object fields or change host, method, path/query, headers,
credentials, session/patient binding, target, surface, policy, or fixture.

[locked-decision] The final T-F16 Policy Gateway validates the original parent against the exact
authorized corpus seed, validates the envelope and derivation against the versioned mutation
policy, and only then evaluates the derived request. The runtime's one typed
`trusted_target_evaluator(envelope)` delegates through the final per-surface Policy Gateway,
persists/re-reads evidence, runs deterministic oracles, and returns evidence plus deterministic
verdict from that same dispatch. Seed substitution, metadata drift, oversized/unbounded sequences,
undeclared transforms, and host/method/path/query/header/credential changes fail before target I/O.

#### Exact 100-case hosted profile

[locked-decision] The Week 3 100-case baseline is an explicitly authorized hosted profile, not a
deterministic run relabeled as hosted. It fixes `N=100`, provider retries `R=0`, and at most one
Documentation call per case. Preflight reserves the hard physical maximum
`P_max = N × (Orchestrator + Red Team + Judge + Documentation_max) × (1 + R) = 400`.
Actual provider calls must reconcile to `P_actual = 300 + F`, where `F` is the number of cases
whose verified verdict requires Documentation (`0 <= F <= 100`). The platform ceiling is 400 for
this profile; the old 56-call ceiling cannot admit it. A provider failure makes that case/run
partial and is not hidden by retry.

[locked-decision] A report or UI may claim `hosted_100_case_complete` only when the ledger proves
100 terminal Orchestrator, 100 Red Team, and 100 Judge calls; Documentation count equals eligible
verdicts; every call belongs to one of the 100 authorized cases; `physical_count = 300 + F`; there
are no retries or unmatched invocations; and all 100 cases have terminal target/verdict records.
Any halt, cap exhaustion, provider unknown outcome, or missing reconciliation is explicitly
partial and cannot satisfy the requirement.

### Web and UI boundary

[locked-decision] T-F17e adds a dedicated append-only capability contract rather than overloading
the environment-only component table. On every Runner startup, a new instance/generation
immediately supersedes prior operational evidence and publishes `verifying`; failure publishes
`unavailable` or `degraded`. `operational` is allowed only after prompt/configuration verification
and Runner-only credential-reference resolution. Every observation binds organization, exact
configuration-set hash, release id, image digest, deployed revision, prompt-registry hash, hashes
of credential references (never values), environment, Runner instance/generation, database time,
status, and bounded reason.

[locked-decision] Web hosted preflight derives the expected identity from the campaign binding and
requires an exact fresh operational match on every field. Wrong organization, configuration,
release, image, revision, prompt registry, credential-reference set, environment, instance, or
generation blocks launch. A static flag or another configuration's heartbeat proves nothing.
Rollout overlap and rollback require a new explicitly selected generation; superseded generations
cannot admit work.

[locked-decision] `GET /api/v1/agents` and `GET /api/v1/agent-activity` remain available to
`org:console:read` and return only secret-free configured and observed metadata. Exact prompt text
is returned only by
`GET /api/v1/agent-prompts/{role}/{version}/{sha256}?configuration_set_sha256=...`, requiring
backend-verified `org:config:manage`. The authenticated organization must reference that exact
role/version/hash/configuration identity in its staged configuration or immutable provider event.
The endpoint re-hashes exact package bytes before return, uses a generic authorization/not-found
failure for unauthorized, unreferenced, cross-org, or mismatched identities, and sets
`Cache-Control: no-store`. A role-only or browser-selected identity is never authoritative. Other
Headshot users see prompt version/hash plus an explicit restricted state. Prompt text is rendered
as escaped text, never HTML.

The Agents screen must show:

- configured assignment: provider, requested model, mode, activation state, version, config hash;
- observed execution: returned model, upstream provider, provider request id, status/error,
  input/output/reasoning tokens, measured/unavailable cost, timestamps, and lineage hashes;
- system prompt: version, SHA-256, verified/mismatch state, and exact text when authorized;
- explicit `not observed`, `unavailable`, or `restricted` states rather than inferred readiness.

## Tickets and waves

| wave | ticket | concern | dependencies |
|---:|---|---|---|
| 26 | T-F17a | versioned four-role prompt registry and wheel packaging | T-F00 |
| 26 | T-F17b | append-only provider-call lineage contract and persistence | T-F00 |
| 27 | T-F17c | hash-bound system messages and physical-call observations | T-F17a, T-F17b |
| 28 | T-F17d | coverage-driven runtime, authorized mutation, final gateway/Runner composition | T-F17c, accepted T-F16f |
| 29 | T-F18j | canonical unknown-cost consumer migration | T-F17b, T-F17c, accepted T-F18i |
| 30 | T-F17e | content-addressed Runner capability, Web truth, deployment controls | T-F17d, accepted T-F18j |
| 31 | T-F17f | Agents API/UI configured-versus-observed provenance and content-addressed prompts | T-F17b, T-F17c, T-F17e |

T-F17a and T-F17b have disjoint production/test scopes and may use two workers in parallel.
T-F17a-c can land independently of T-F16. T-F17d starts only from the accepted T-F16f integration
commit and becomes the sole shared `runner.py`/gateway owner. T-F18j starts only after T-F17b/c,
owns the shared cost consumers, and must be accepted before T-F17e. T-F17e is the next sole
`runner.py` owner. T-F17f follows capability acceptance.

## TDD and review gates

Every ticket follows this uncompressed sequence:

1. Test Agent writes criterion-tagged deterministic RED tests only in declared test scopes.
2. Independent Test Reviewer verifies the tests fail for the missing behavior, resist a lazy
   implementation, cover negative/authorization/error cases, and freezes them.
3. Implementation Agent may edit only production/doc scopes and may not edit frozen tests.
4. Coordinator re-runs `.tdd-swarm/run-local-gates.sh <ticket> <DIFF_BASE>`.
5. Independent Code Reviewer verifies every criterion and reachability from the real entrypoint.
6. Independent Security Reviewer checks authorization, prompt/credential leakage, provider spoofing,
   fail-open fallback, unsafe rendering, and migration/grant correctness.
7. Critical/Important findings return to the implementer and repeat both reviews; three-loop maximum.

Wave gates additionally require full Python and console suites, formatting/lint/typecheck/build,
contract compatibility, migration upgrade/downgrade on a disposable baseline copy, package/wheel
verification, architecture-drift review, dependency and secret scans, and no coverage reduction.
Sampled LLM quality is an eval artifact, not a mocked deterministic unit-test claim.

## Deployment gate and rollback

No production provider or target traffic is part of the deterministic tickets. Promotion requires:

1. owner-approved PR; equal commit on GitHub and GitLab; both CI systems green;
2. one reviewed image digest for Web and Runner;
3. additive migration validation and backup evidence;
4. exact staged configuration, prompt, release, image, deployed-revision, credential-reference,
   organization, environment, and Runner-generation hashes matching the campaign;
5. Runner-only OpenRouter credential bindings with no values in Web;
6. Runner deployment first and a fresh exact-match hosted-runtime capability observation;
7. Web deployment from the same image and authenticated Agents/preflight smoke;
8. a separately authorized, two-person-approved, synthetic-only bounded campaign;
9. accepted T-F18j proof that Costs, Birdseye, campaign totals, and Agents preserve unknown/partial
   cost without zero coercion or double counting;
10. one observed successful provider event for every invoked role, exact returned model/upstream
    match, intact invocation lineage, and one final T-F16 per-surface Policy Gateway target path;
    missing measured usage/cost remains unknown and Documentation may be correctly skipped; and
11. no critical finding publication or remediation without its separate human approval gate.

Rollback stops new hosted admissions, lets the hard-abort path terminate active work, deploys the
previous reviewed image to Runner and Web, and retains the additive lineage tables as evidence. A
superseded or nonmatching capability makes Web fail closed. Production schema downgrade is not an emergency
rollback mechanism; downgrade is verified only on an isolated copy and performed later under a
separate reviewed maintenance change if required.

## Traceability

| Requirement | Closure |
|---|---|
| Week 3 distinct agents, models, and trust levels | T-F17a, T-F17c, T-F17d |
| Judge independence and consistent criteria | T-F17a, T-F17c, T-F17d |
| What each agent is doing and in what order | T-F17b, T-F17d, T-F17f |
| Cost tracking at agent level and honest aggregates | T-F17b, T-F17c, T-F18j, T-F17f |
| Versioned contracts, migration notes, lineage | T-F17b, T-F17c |
| External API auth/rate/error behavior | T-F17c, T-F17d, T-F17e |
| Coverage-driven orchestration and authorized mutation | T-F17d |
| Exact hosted 100-case provider budget/reconciliation | T-F17c, T-F17d |
| AI-use disclosure and residual risk | T-F17a, T-F17e |
| User requirement: actual OpenRouter model and prompt in Agents | T-F17f |

## Explicit non-goals

- No per-role browser activation; hosted configuration remains atomic.
- No model/provider fallback or alias.
- No Web access to provider credentials.
- No weakening of Policy Gateway, two-person approval, synthetic-only, budget/rate, Judge
  precedence, draft-only publication, or target allowlist controls.
- No claim that a configured model ran until provider-call evidence exists.
- No provider call, live target call, deployment, main merge, or critical publication in this
  planning branch.

## Open owner gates

- [open-question] Confirm that full system-prompt text should remain restricted to
  `org:config:manage` while prompt version/hash stays visible to `org:console:read`. The plan uses
  this least-privilege default.
- [open-question] Supply the production deployment authority, separately authorized campaign scope,
  distinct launcher/Approver identities, and Runner-only sealed provider bindings. Their absence
  blocks operational evidence but not deterministic implementation.
