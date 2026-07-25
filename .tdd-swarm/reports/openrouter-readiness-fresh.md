# Fresh OpenRouter implementation/readiness audit

**Decision: BLOCKED.**

The deterministic OpenRouter implementation is ready to begin only after T-F00 is integrated and
review-passed. On the audited integration branch, T-F00 is not landed and every implementation and
focused test path for T-F04c, T-F04g, T-F04f, T-F03a, T-F04a, T-F04h, T-F04d, and T-F05a is absent.
No paid inference, target request, credential resolution, deployment, Railway mutation, or secret
inspection was performed.

- Audit time: 2026-07-24T15:21:55Z
- Branch/HEAD: `swarm/final-submission-gap-closure` at `66e670fee8c6c66a5236c7d932a0c4a2e9f74b87`
- Audit mode: repository read-only, local/Railway variable presence-only, and unauthenticated public
  OpenRouter catalog/documentation reads
- Deliberately excluded: inference endpoints, key/credit APIs, target URLs, target sessions, databases,
  Clerk, deployment, and raw environment/Railway values

## Immediate findings

1. **T-F00 is the first mechanical blocker.** T-F04c depends on T-F00. The integration branch contains
   only the reviewed plan; it does not contain the accepted gate implementation.
2. **The current runtime is deterministic, not four-role hosted.** `AgentAssignment` carries only
   provider/model/mode/state/version/hash. Hosted Orchestrator and Judge configurations are rejected,
   and only Red Team/Documentation can be staged.
3. **The only current hosted call seam is incomplete.** Red Team's `HostedProvider` validates a minimal
   provider/model/reference triple, builds an ambient SDK client, and its real call method raises
   `NotImplementedError`. There is no shared OpenRouter transport, accounting ledger, Judge provider,
   hosted Orchestrator adapter, hosted Documentation adapter, or four-role composition.
4. **Migration 0011 is insufficient for hosted authority/evidence.** `agent_executions` lacks the
   configuration-set hash/FK, configuration hash, exact returned model, selected upstream identity,
   reasoning tokens, reservation/reconciliation, provider request ID, release SHA, and the policy,
   catalog, data-policy, prompt, rubric, criteria, and fixture hashes required by the reviewed tickets.
5. **A funded account or one available key is not a runnable configuration.** Local configuration has
   a legacy OpenRouter key/base URL, but no four distinct sealed role references. Neither Railway
   Runner environment has the OpenRouter/four-role settings. No provider authorization artifact exists.
6. **The reviewed four-role runtime assignment remains mandatory.** Using the strongest available
   Codex model for development workers is fine. It does not relax deployed runtime separation:
   Orchestrator, Red Team, Judge, and Documentation model IDs and credential references remain pairwise
   distinct, and Judge versus Red Team must additionally differ in family, prompts/rubric-or-criteria,
   expected upstream, and actual upstream.

## Current implementation map

| Boundary | Current state | First owning ticket |
|---|---|---|
| Canonical hosted settings/domain | `Settings` contains only deployment environment; no hosted role type | T-F04c |
| Persisted role assignment | Minimal `agent_configuration_versions`; one role at a time | T-F04c |
| Four-role set/staging CLI | Missing | T-F04c |
| Read-only authority preflight/projection | Missing | T-F04g |
| Secret resolution | A reusable `Secret` and opaque `secretref://` resolver exist for Runner, but no provider-role enforcement | T-F04f |
| OpenRouter request/response transport | Missing; legacy Red Team call is `NotImplemented` | T-F04f |
| Atomic provider accounting/abort | Missing | T-F04f |
| Hosted Judge adaptation/calibration | Deterministic Judge only; hosted provider module missing | T-F03a |
| Hosted Red Team search runtime | Offline provider/selection/mutation only; `provider_runtime.py` missing | T-F04a |
| Operational smoke schemas/fixture/verifier | Missing; registry has only `SUCCESS_SCHEMAS` | T-F04h |
| Four-role target-free composition | Missing | T-F04d |
| Durable complete four-role lineage | Partial agent-execution rows only | T-F05a |

The exact ticket dependency chain remains sound:

```text
T-F00
  -> T-F04c
    -> T-F04g
      -> T-F04f
        -> T-F03a + T-F04a
          -> T-F04h
            -> T-F04d
              -> T-F05a
```

T-F03b, T-F04b, and T-F04e are later operational evidence runs. Their absence must not block the
deterministic code tickets, but it must keep provider calls at zero.

## Presence-only configuration

No value was printed, retained, or written to this report.

| Surface | Present state |
|---|---|
| Local effective configuration | OpenRouter key and base URL set; Red Team provider set but model empty; Judge provider/model set; Documentation provider missing and model empty; Orchestrator provider missing and model set |
| Local four role-scoped credential references | All four missing |
| Local generic sealed-reference binding map | Missing |
| Railway Staging Runner | OpenRouter key/base URL, all four role provider/model selectors, and all four role credential references missing; generic sealed-reference binding map set |
| Railway production Runner | Same provider state as Staging: all OpenRouter/four-role entries missing; generic sealed-reference binding map set |
| Railway Web, both environments | OpenRouter key and all four provider credential references missing, which is the correct service boundary |

The target credential/session surface was deliberately not inspected. Target authority is separate
from provider authority and cannot unblock this chain.

Also absent:

- `.tdd-swarm/judge-calibration-policy.json`
- `.tdd-swarm/red-team-eval-policy.json`
- `docs/evidence/authorizations/judge-calibration.json`
- `docs/evidence/authorizations/red-team-eval.json`
- `docs/evidence/authorizations/openrouter-four-role-smoke.json`
- `evals/fixtures/openrouter-four-role-smoke-v1.json`

## Runtime independence versus development model choice

The same high-capability Codex model may be used by separate development workers. Separation there is
enforced by worktree/context, frozen tests, role-specific write scopes, and independent reviews.

The deployed evaluation runtime has a different threat model. A compromised or steered attack generator
must not evaluate its own output. Therefore:

- four requested model IDs and four sealed credential-reference IDs stay pairwise distinct;
- Judge and Red Team requested model, returned model, model family, prompt, rubric-or-criteria,
  expected upstream tag/provider, and returned upstream provider must not collide;
- no alias such as `auto`, `latest`, `~vendor/model`, multi-model `models`, or provider fallback is allowed;
- deterministic oracle/canary evidence still outranks hosted Judge text;
- a collision or unverifiable identity yields `INDETERMINATE|ERROR`, never a safe result.

The user's “same highest model” preference can therefore govern development workers, but not these four
deployed roles without changing the reviewed requirements and invalidating Judge independence.

## Public catalog verification

The public unauthenticated catalog was checked at audit time. The previously reviewed candidate IDs remain
listed, unexpired, and advertise `response_format`/`structured_outputs`:

| Role candidate | Exact current ID | Catalog input/output per 1M tokens | Relevant point-in-time facts |
|---|---|---:|---|
| Orchestrator | `anthropic/claude-opus-4.8` | $5 / $25 | 1M context, 128K max completion, reasoning |
| Red Team | `qwen/qwen3.5-397b-a17b` | $0.39 / $2.34 | 262,144 context, 65,536 max completion, reasoning |
| Judge | `google/gemini-2.5-pro` | $1.25 / $10 | 1,048,576 context, 65,536 max completion, reasoning; higher price tier begins at 200K prompt tokens |
| Documentation | `openai/gpt-5.4` | $2.50 / $15 | 1.05M context, 128K max completion, reasoning; higher price tier begins at 272K prompt tokens |

These remain candidates, not runtime defaults or authorization. Catalog order does not define “best,” and
newer entries do not automatically supersede a calibrated role. A model change requires a new catalog
snapshot, configuration-set hash, authorization, and Judge/Red-Team evaluation.

Official public sources:

- [model catalog](https://openrouter.ai/api/v1/models)
- [per-model endpoint records](https://openrouter.ai/docs/guides/overview/models)
- [provider selection](https://openrouter.ai/docs/guides/routing/provider-selection)
- [strict structured outputs](https://openrouter.ai/docs/guides/features/structured-outputs)
- [router metadata](https://openrouter.ai/docs/guides/features/router-metadata)
- [usage accounting](https://openrouter.ai/docs/cookbook/administration/usage-accounting)
- [zero data retention](https://openrouter.ai/docs/guides/features/zdr)

## Exact first implementation interfaces

### 1. T-F04c: immutable configuration authority

Add framework-neutral immutable types to `config.py`/`agents/runtime.py`:

```python
@dataclass(frozen=True, slots=True)
class TokenPriceVector:
    input_usd_per_token: Decimal
    output_usd_per_token: Decimal
    reasoning_usd_per_token: Decimal


@dataclass(frozen=True, slots=True)
class HostedLimits:
    max_calls: int
    max_retries: int
    max_input_tokens: int
    max_output_tokens: int  # visible completion, excluding reasoning
    max_reasoning_tokens: int
    max_usd: Decimal
    max_wall_clock_seconds: int
    max_requests_per_second: Decimal
    max_concurrency: int


@dataclass(frozen=True, slots=True)
class HostedRoleConfiguration:
    role: AgentRole
    provider: Literal["openrouter"]
    requested_model: str
    expected_returned_model: str
    credential_reference_id: str
    base_url: str
    expected_upstream_provider: str
    expected_upstream_endpoint_tag: str
    output_schema_id: str
    prompt_sha256: str
    rubric_sha256: str
    criteria_sha256: str
    policy_sha256: str
    catalog_sha256: str
    data_policy_sha256: str
    catalog_prices: TokenPriceVector
    max_price_usd_per_million: Mapping[str, Decimal]
    role_limits: HostedLimits
    global_limits: HostedLimits
    role_configuration_sha256: str


@dataclass(frozen=True, slots=True)
class HostedConfigurationSet:
    release_sha: str
    full_four_role_input_sha256: str
    configuration_set_sha256: str
    roles: tuple[HostedRoleConfiguration, ...]
    activation_state: Literal["staged_pending_authorization"]
```

Required pure interfaces:

```python
parse_hosted_role_settings(environ: Mapping[str, str]) -> HostedConfigurationSetInput
validate_hosted_configuration_set(value: HostedConfigurationSetInput) -> None
canonical_hosted_configuration_bytes(value: HostedConfigurationSetInput) -> bytes
stage_hosted_configuration_set(
    store: HostedConfigurationStore,
    *,
    release_sha: str,
    actor_ref: str,
    value: HostedConfigurationSetInput,
) -> str
```

The parser reads all canonical settings exactly once. Missing, blank, unknown, duplicated, alias-shaped,
raw-secret-shaped, float-priced, or unsupported values exit 4 without defaults. Use `Decimal` from the
original strings and encode units in field names. The canonical input is schema-versioned, sorted by role,
and excludes actor/session/audit metadata.

Lock the settings names in the frozen test before implementation. Preserve existing
`HEADSHOT_<ROLE>_MODEL`; add explicit provider, expected-returned model, sealed reference, endpoint tag,
schema/hash, price, `max_price`, and limit fields per role, plus one explicit global-cap namespace. Do not
read `OPENROUTER_API_KEY` as authority.

### 2. Migration 0014: authority and integrity

`0014_hosted_role_configuration.py` must revise `0013` and introduce:

- `hosted_configuration_sets`: organization scope, set hash, release SHA, full-input hash, idempotency
  hash, staged state, audit actor, creation time; unique release identity and append-only trigger.
- `hosted_role_configuration_versions`: organization/set/role key, immutable role version/hash, exact
  provider/model/reference/upstream/schema/hashes, typed price vectors and typed role/global caps; exactly
  four roles are inserted by the one transaction.
- nullable hosted-authority columns plus composite FKs on `agent_configuration_versions` and
  `agent_executions`; a hosted row must have both role-version and set authority, while a deterministic row
  must not forge them.
- append-only triggers and least-privilege grants. The staging workload identity may insert/select the new
  configuration records but may not update/delete, activate, resolve secrets, or write executions.

Organization scope must be part of every lookup/FK/preflight even though the content hash may be identical
between organizations. The current public CLI has no organization argument, so the workload DB identity or
a separately validated setting must bind exactly one organization; do not infer it from actor text.

The transaction inserts four role versions and one set, or none. Same release/full-input returns the
original set. Same release/different input conflicts. A new release may create a new set. The CLI:

```text
python scripts/stage_openrouter_role_configurations.py \
  --release-sha <RELEASE_SHA> --actor-ref <ACTOR_REF> --hash-only
```

prints only the set hash on success and never resolves a secret, constructs a provider, activates a set, or
contacts a target.

### 3. T-F04g: read-only approved projection

Expose:

```python
preflight_hosted_authority(
    persisted_set: HostedConfigurationSet,
    authorization: Mapping[str, Any],
    fixture_sha256: str,
) -> ApprovedHostedConfigurationSet

project_hosted_authority(
    approved: ApprovedHostedConfigurationSet,
) -> Mapping[str, Any]
```

The approved wrapper, not a boolean, is the only input T-F04f accepts. It binds organization, release/set,
all role version/configuration/model/reference/upstream/schema/hash/price/`max_price` fields, fixture,
per-role/global caps, expiry, approver, and `target_scope:none`. Projection contains reference IDs and hashes
only. It performs no settings reparse, mutation, activation, secret resolution, transport construction, or
target construction.

### 4. T-F04f: one transport and one shared ledger

Use existing `httpx` through an injected narrow transport rather than adding an ambient OpenAI SDK client
(the ticket does not own dependency changes):

```python
class ProviderCredentialResolver(Protocol):
    def resolve_for_role(self, role: AgentRole, reference_id: str) -> Secret: ...


class OpenRouterWireTransport(Protocol):
    def post(
        self, *, url: str, headers: Mapping[str, str], json: Mapping[str, Any], timeout_seconds: int
    ) -> Mapping[str, Any]: ...


class ReservationLedger(Protocol):
    def reserve(self, estimate: AttemptEstimate) -> Reservation: ...
    def reconcile(self, reservation: Reservation, usage: ActualUsage) -> Reconciliation: ...
    def retain_unknown(self, reservation: Reservation, reason: str) -> None: ...
    def abort(self, reason: str) -> None: ...


class OpenRouterRoleClient:
    def complete(self, request: RoleRequest) -> OpenRouterResult: ...
```

The credential resolver receives one approved role record and may resolve only its exact reference. The raw
value becomes a `Secret`, is revealed only while constructing the Authorization header, and is never placed
in a dataclass, exception, log, manifest, or projection. Four distinct OpenRouter keys may be funded by the
same account; account funding does not justify one shared key.

The base URL validator must allow only the bound HTTPS OpenRouter origin and exact API path, with no
userinfo, query, fragment, redirect, or alternate host. HTTP redirects are disabled.

Every request must contain one exact `model`, no `models`/auto/latest alias, a repository-loaded strict JSON
schema, and:

```json
{
  "provider": {
    "only": ["<exact-full-endpoint-tag>"],
    "allow_fallbacks": false,
    "require_parameters": true,
    "data_collection": "deny",
    "zdr": true,
    "max_price": {
      "prompt": "<authorized USD per million>",
      "completion": "<authorized USD per million>"
    }
  },
  "response_format": {
    "type": "json_schema",
    "json_schema": {
      "name": "<repository schema id>",
      "strict": true,
      "schema": {}
    }
  }
}
```

Also send `X-OpenRouter-Metadata: enabled`. Do not enable cache replay, tools, plugins, web search, response
healing, or context compression for the smoke. Any unapproved material router-pipeline stage is terminal.
Validate parsed JSON again with the packaged repository contract; provider strict output is not a trust
boundary.

Record:

- exact requested model and top-level returned model;
- authorization-pinned endpoint tag, returned provider name/model, router strategy, selected endpoint
  count, OpenRouter attempt count, request/generation ID, and service tier;
- input, visible output, and reasoning tokens;
- `usage.cost` measured charge and cost provenance;
- configuration-set/role/prompt/rubric/criteria/policy/catalog/data-policy/schema hashes.

The current router-metadata schema returns selected provider/model but does not promise the exact full
endpoint tag. Do not label the request's pinned tag as a provider-returned value. Frozen tests must use the
honest fields `authorized_endpoint_tag`, `request_only_endpoint_tag`, and `returned_provider_name`. If the
acceptance criteria continue to require a provider-returned full endpoint tag, implementation is blocked
until OpenRouter exposes one. Pinning with `provider.only` plus `allow_fallbacks:false` is still mandatory.

Require router strategy `direct`, exactly one selected candidate, and router attempt `1`. A cache replay
omits router metadata and therefore fails closed. This also prevents hidden router retries from being
misrepresented as one application physical attempt.

### 5. Atomic reservation, reconciliation, retry, and abort

Normalize catalog prices as `Decimal` USD/token. Normalize request `max_price` separately as USD/million;
never compare numbers with different units. Define visible output as
`completion_tokens - completion_tokens_details.reasoning_tokens` when OpenRouter reports reasoning as part
of completion. Reject negative or contradictory accounting.

Before each application-to-OpenRouter HTTP attempt, under one shared role/global lock:

```text
reserved_tokens =
    max_input_tokens + max_visible_output_tokens + max_reasoning_tokens

reserved_usd =
    max_input_tokens * input_usd_per_token
  + max_visible_output_tokens * output_usd_per_token
  + max_reasoning_tokens * reasoning_usd_per_token
  + any explicitly authorized fixed/request charge
```

Use the maximum applicable catalog tier for the authorized token maxima. A threshold-crossing request may
not use the lower tier. Reserve call, retry, token, USD, rate, concurrency, and wall-clock capacity
atomically. The last exactly affordable attempt passes; one unit over refuses before credential resolution
or transport.

After a complete response, reconcile to exact returned token fields and `usage.cost`, release only unused
capacity, and retain both estimate and actual. Missing usage/cost, a timeout after send, malformed response,
identity/schema drift, price overrun, reasoning growth, 402, or unverifiable provider metadata is terminal:
retain the full reservation (and any exact partial accounting), set shared abort, and allow no later role.

Only explicitly retryable timeout/429/503 classes may retry, with `Retry-After` bounded by remaining
wall-clock. Every retry obtains a new full reservation and uses the same model/endpoint/reference. Refusal,
schema failure, identity drift, 402, and accounting failure do not switch model/provider and should not be
retried. A failure provably before any bytes are dispatched may release concurrency and the unused attempt
reservation; a possibly processed request may not.

Client reconstruction must receive the same ledger object and abort state. T-F04f is process-local by
scope; T-F05a persists the resulting reservation/reconciliation/terminal lineage. It must not claim
crash-durable provider budgeting before that persistence exists.

## Capability/price snapshot required before any smoke

Create one owner-reviewed, canonical JSON snapshot per role immediately before authorization. It must
contain:

- schema version, retrieval timestamp, public source URLs, exact requested model ID and canonical slug;
- exact endpoint tag, provider display name, endpoint model ID, status, context/max prompt/max completion;
- endpoint-level supported parameters including `response_format` and `structured_outputs`;
- complete endpoint pricing, fixed/request fees, cache/media/search prices, and all threshold overrides;
- normalized input/output/reasoning USD-per-token vector and the derivation rule;
- exact request `max_price` USD-per-million object;
- required routing/data controls (`only`, no fallback, require parameters, `data_collection:deny`, `zdr:true`);
- repository schema/prompt/rubric/criteria/policy/data-policy hashes;
- canonical snapshot SHA-256.

The public endpoint catalog does not expose a definitive per-endpoint ZDR flag. ZDR/data-collection policy
therefore needs its own owner-reviewed snapshot/hash, and the request must still enforce both filters. A
configuration with no endpoint surviving those filters must fail before or at routing with no fallback;
it is not permission to relax privacy.

T-F04c persists the authorization-selected snapshot/hash. T-F04g compares the persisted set to the
authorization and fixture. T-F04f accepts only that approved wrapper and a freshly supplied
capability/price snapshot with the same canonical hash. No layer independently reinterprets ambient
environment values.

## Ordered actions

1. **Finish and integrate T-F00.** Require frozen tests, coordinator gate rerun, and zero unresolved
   Critical/Important Code or Security findings. Until then T-F04c remains blocked by contract.
2. **Freeze T-F04c tests**, including organization binding, exact settings names/units, raw-secret and
   alias rejection, four-or-zero staging, migration/FKs/RBAC, and hash-only stdout.
3. **Implement and review T-F04c**, then run its public stage command only against injected/local test
   storage. Do not stage a real role set yet; prompt/policy/catalog hashes are not available.
4. **Implement T-F04g** as a read-only stage-to-preflight path returning the typed approved wrapper.
5. **Implement T-F04f** with injected `httpx` transport, role-only resolver, exact routing/metadata, Decimal
   reservation/reconciliation, and persistent shared abort state.
6. **Implement T-F03a and T-F04a in parallel** after T-F04f. Keep deterministic oracle precedence and
   Judge/Red-Team collision checks before and after dispatch.
7. **Implement T-F04h, then T-F04d, then T-F05a** to publish operational schemas/fixture/verifier, compose
   exactly four target-free dispatches, and persist full immutable lineage.
8. **Provision four role-scoped OpenRouter keys/references on Staging Runner only**, after code/security
   review. Keep them absent from Web. Do not use the local generic key as evidence of separation.
9. **Select four exact runtime models/endpoints and capture capability/price/data-policy snapshots.** The
   four reviewed IDs remain available candidates, but selection is not automatic and “highest” is not an
   auditable criterion.
10. **Create bounded, expiring T-F03b/T-F04b authorization artifacts**, run zero-call preflight, then perform
    only those target-free evaluations. Failed calibration/evaluation blocks activation.
11. **Create the separate target-free four-role smoke authorization** with exact set/fixture/snapshot/caps
    and distinct reviewers. Only then may T-F04e make four bounded provider calls.
12. **Keep target work separate.** Provider funding, provider smoke, or any target session does not
    authorize target traffic, a campaign, replay, stress test, publication, or remediation.

**Final: BLOCKED — first unblock is accepted T-F00 integration; no paid or target call is currently
permitted.**
