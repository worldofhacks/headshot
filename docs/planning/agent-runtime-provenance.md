# P0 hosted agent runtime and provenance remediation

Status: planning only
Base: `1ac3ee02be7855b638dd1fa43bb0612a3db5f025`
Posture: production-grade

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
Runner-owned, secret-free capability heartbeat in PostgreSQL and expose only authenticated,
permission-checked projections. This is how Web participates in the production composition
without violating the Runner-only credential boundary.

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
                        Orchestrator -> Red Team -> trusted evaluator
                                                -> Judge -> Documentation
                                                      |
                   +----------------------------------+------------------+
                   |                                                     |
          provider_call_events                                  agent_executions
    observed response/error lineage                         logical role lifecycle
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

- Orchestrator may prioritize only the supplied authorized case/snapshot and cannot widen target,
  corpus, surface, caps, approval, publication, or remediation authority.
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

[locked-decision] Logical activity remains in `agent_executions`. A new append-only
`provider_call_events` relation records one terminal fact per physical OpenRouter attempt:

- organization, campaign, logical agent execution, attempt sequence, and role;
- requested model and configured upstream;
- provider-confirmed returned model, upstream provider, and request id when present;
- prompt version/hash, configuration-set hash, role-configuration hash, and generation-policy hash;
- input, output, and reasoning tokens when provider usage is valid;
- measured cost only when the provider reports it, with an explicit measurement state;
- physical status, sanitized typed error code, start/finish timestamps, and duration.

[locked-decision] Failed calls never manufacture a provider identity, token count, or zero cost.
Transient retry attempts remain individually visible. Raw provider bodies, messages, prompt text,
credentials, target sessions, hostile evidence, and exception strings are never stored in this
table. Database grants permit only the private Runner to insert and authenticated Web/Runner roles
to read; UPDATE/DELETE/TRUNCATE are rejected.

### Hosted Runner path

[locked-decision] A campaign without `scope.hosted_run` preserves the deterministic execution path.
A campaign with `scope.hosted_run` must take the hosted path or fail before provider/target I/O;
there is no deterministic fallback.

[locked-decision] Hosted preflight must:

1. load the exact staged configuration set by organization and bound hash;
2. validate configuration content, fixed role models, limits, generation policy, and prompt hashes;
3. verify all four Runner-only credential references are distinct and resolvable without exposing
   values;
4. verify current campaign authorization, target/session binding, caps, queue lease, and synthetic
   data controls already required by the Runner;
5. construct one shared OpenRouter usage ledger and concurrency-one transport; and
6. refuse with a typed, sanitized blocker before any provider or target call if any fact differs.

[locked-decision] The runtime's target seam becomes one typed
`trusted_target_evaluator(attack_attempt)` call. It delegates to the existing Policy Gateway,
evidence persistence/re-read, and deterministic oracle path and returns verified target evidence
plus the deterministic verdict as one value. This prevents independent target-dispatch and
deterministic-Judge callbacks from observing different evidence and proves exactly one target
dispatch path. The interface change receives a migration note and contract tests.

### Web and UI boundary

[locked-decision] The Runner emits a fresh `hosted-four-role-runtime` component heartbeat only after
prompt/configuration verification and Runner-only credential-reference resolution succeed. Web
uses the database timestamp and environment to derive availability; a stale/missing heartbeat
degrades preflight and blocks a hosted launch. No boolean environment flag can assert composition.

[locked-decision] `GET /api/v1/agents` and `GET /api/v1/agent-activity` remain available to
`org:console:read` and return only secret-free configured and observed metadata. Exact prompt text
is returned by a dedicated role prompt endpoint requiring backend-verified
`org:config:manage`; other Headshot users see prompt version/hash plus an explicit restricted state.
Prompt text is rendered as escaped text, never HTML.

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
| 28 | T-F17d | authorization-bound HostedFourRoleRuntime Runner composition | T-F17c |
| 29 | T-F17e | Runner capability heartbeat, Web truth, and deployment controls | T-F17d |
| 30 | T-F17f | Agents API/UI configured-versus-observed provenance and prompt view | T-F17b, T-F17c, T-F17e |

T-F17a and T-F17b have disjoint production/test scopes and may use two workers in parallel.
Every later ticket is serialized because it consumes or renders the preceding contract.

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
4. exact staged configuration and prompt hashes matching that image;
5. Runner-only OpenRouter credential bindings with no values in Web;
6. Runner deployment first and a fresh hosted-runtime capability heartbeat;
7. Web deployment from the same image and authenticated Agents/preflight smoke;
8. a separately authorized, two-person-approved, synthetic-only bounded campaign;
9. one observed successful provider event for every invoked role, exact returned
   model/upstream match, measured usage/cost, intact parent lineage, and one Policy Gateway target
   path; Documentation may be correctly skipped when no finding exists; and
10. no critical finding publication or remediation without its separate human approval gate.

Rollback stops new hosted admissions, lets the hard-abort path terminate active work, deploys the
previous reviewed image to Runner and Web, and retains the additive lineage table as evidence. A
stale Runner heartbeat makes Web fail closed. Production schema downgrade is not an emergency
rollback mechanism; downgrade is verified only on an isolated copy and performed later under a
separate reviewed maintenance change if required.

## Traceability

| Requirement | Closure |
|---|---|
| Week 3 distinct agents, models, and trust levels | T-F17a, T-F17c, T-F17d |
| Judge independence and consistent criteria | T-F17a, T-F17c, T-F17d |
| What each agent is doing and in what order | T-F17b, T-F17d, T-F17f |
| Cost tracking at agent level | T-F17b, T-F17c, T-F17f |
| Versioned contracts, migration notes, lineage | T-F17b, T-F17c |
| External API auth/rate/error behavior | T-F17c, T-F17d, T-F17e |
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
