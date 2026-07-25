# OpenRouter readiness and model allocation

**Disposition:** **BLOCKED / zero paid inference calls authorized.**

**Catalog retrieval:** 2026-07-24T13:18:19Z from the public OpenRouter
[`GET /api/v1/models`](https://openrouter.ai/api/v1/models) endpoint, without an API key.
Pricing and capability data below are a point-in-time snapshot and must be revalidated in the
zero-call preflight immediately before any authorized run.

## Executive finding

The repository is not ready to spend against OpenRouter yet:

- The current effective local configuration has no OpenRouter credential or model setting.
- T-F03a/T-F04a are still backlog tickets and their required policy/runtime artifacts do not
  exist.
- T-F03b/T-F04b owner authorization artifacts do not exist, so both operational workflows must
  exit blocked with zero provider calls.
- The only hosted boundary is the Red Team `HostedProvider`; its real client call is explicitly
  `NotImplemented`, and its OpenAI client construction does not currently wire the OpenRouter
  base URL, API key reference, timeout, retries, structured-output contract, or accounting.
- The runtime catalog permits hosted advisory mode only for Red Team and Documentation, keeps
  such choices staged, and explicitly rejects hosted Orchestrator and Judge assignments. This is
  safe but means the proposed four-role allocation cannot be selected by the current runtime.
- Judge calibration currently invokes only the deterministic `oracle-precedence` evaluator with
  hard-coded offline provider identities. There is no Judge provider module.

The deterministic runtime remains the safe active baseline. Any hosted Judge must be advisory and
calibrated; deterministic oracle/canary confirmation must continue to override contradictory model
text, and an uncalibrated or failed Judge must never produce a safe/likely disposition.

## Proposed exact allocation

These are recommendations for the owner-authorized evaluation, not runtime defaults that have
already been enabled.

| Role | Exact OpenRouter model ID | Family / vendor | Context / max output | Catalog capabilities used | Catalog price per 1M tokens |
|---|---|---|---:|---|---:|
| Orchestrator | [`anthropic/claude-opus-4.8`](https://openrouter.ai/anthropic/claude-opus-4.8) | Claude / Anthropic | 1,000,000 / 128,000 | reasoning, structured outputs, tools | $5 input / $25 output |
| Red Team | [`qwen/qwen3.5-397b-a17b`](https://openrouter.ai/qwen/qwen3.5-397b-a17b) | Qwen / Qwen | 262,144 / 65,536 | structured outputs, tools, seed, temperature, reasoning | $0.39 input / $2.34 output |
| Judge | [`google/gemini-2.5-pro`](https://openrouter.ai/google/gemini-2.5-pro) | Gemini / Google | 1,048,576 / 65,536 | structured outputs, tools, seed, reasoning | $1.25 input / $10 output |
| Documentation | [`openai/gpt-5.4`](https://openrouter.ai/openai/gpt-5.4) | GPT / OpenAI | 1,050,000 / 128,000 | structured outputs, tools, seed, reasoning | $2.50 input / $15 output |

All four IDs were present in the catalog with `expiration_date: null` and
`per_request_limits: null` at retrieval time. `null` is not a throughput or availability
guarantee.

### Why this allocation

- It uses four distinct model families and four distinct underlying vendors.
- The Judge is materially independent from the Red Team: Gemini versus Qwen, with separate
  prompts, rubric/criteria hashes, execution identity, and proposed role-scoped credentials.
- `google/gemini-2.5-pro` is selected instead of a preview Judge model to reduce model-identity
  churn. It is still only a candidate until the exact T-F03a thresholds pass.
- Qwen is a large hosted open-weight-family candidate for offensive generation. Its measured
  refusal, canonical novelty, and deterministic reproduction rates—not its reputation—must decide
  whether it passes T-F04b.
- Claude Opus matches the repository's low-volume, high-reasoning Orchestrator decision.
- GPT-5.4 matches the repository's schema-gated Documentation decision and is vendor-disjoint from
  the proposed Judge.

### Non-negotiable independence details

OpenRouter would remain a shared gateway and therefore a correlated availability/security
dependency. Model-family separation alone is insufficient. Before evaluation:

1. Use distinct, role-scoped OpenRouter API keys or sealed credential references for Red Team and
   Judge; never share the current single `OPENROUTER_API_KEY` binding between them.
2. Hash and persist the requested model ID, returned model ID, actual upstream provider/endpoint,
   prompt, rubric/criteria, policy, and ground-truth version.
3. For calibration, disable model fallbacks and pin the upstream provider endpoint after a
   zero-call endpoint check. A fallback changes evaluator identity and must invalidate calibration.
4. Keep deterministic oracle/canary precedence outside the model. Model agreement cannot downgrade
   `EXPLOIT_CONFIRMED`.
5. Fail closed on provider/model identity collision, timeout, refusal, malformed output, schema
   failure, or drift.

## Current repository mapping

| Role | Current env/config surface | Proposed value mapping | Current readiness |
|---|---|---|---|
| Red Team | `HEADSHOT_RED_TEAM_PROVIDER`, `HEADSHOT_RED_TEAM_MODEL`, `OPENROUTER_API_KEY`, `OPENROUTER_BASE_URL`, timeout, retries | provider `openrouter`; model `qwen/qwen3.5-397b-a17b` | Partial preflight only; real call/runtime/policy absent |
| Judge | `HEADSHOT_JUDGE_PROVIDER`, `HEADSHOT_JUDGE_MODEL`, `ANTHROPIC_API_KEY`, timeout | model key can hold `google/gemini-2.5-pro`, but provider/credential surface is direct-Anthropic-shaped | No hosted Judge provider; runtime rejects hosted Judge |
| Documentation | `HEADSHOT_DOCUMENTATION_MODEL`, `OPENAI_API_KEY` | model key can hold `openai/gpt-5.4` | No provider/base URL/credential-ref/timeout/retry runtime |
| Orchestrator | `HEADSHOT_ORCHESTRATOR_MODEL` | model key can hold `anthropic/claude-opus-4.8` | No provider/base URL/credential-ref/timeout/retry runtime; hosted mode rejected |

The persisted `agent_configuration_versions` table can store per-role provider/model assignments,
but persistence is not execution. Current hosted assignments are staged and do not drive the
role implementations.

### Missing code/config for genuine per-agent selection

The following must land under the ticketed TDD/review workflow before paid evaluation:

- Complete T-F03a: a Judge provider boundary, injected transport, typed provider failures,
  schema-validated output, identity collision checks, landed calibration policy, and a CLI that
  supports zero-call preflight plus authorized bounded evaluation.
- Complete T-F04a: `provider_runtime.py`, novelty/minimization controls, exact candidate/token/USD/
  wall-clock counters, landed Red Team eval policy, and a real OpenRouter transport.
- Replace the current `HostedProvider._generate_via_client()` `NotImplementedError` with the
  authorized, accounting-aware implementation. Construct the client with the configured
  OpenRouter base URL and resolved role-scoped secret, never ambient defaults.
- Add provider selection for Judge, Documentation, and Orchestrator. The existing model-only keys
  are insufficient.
- Add separate sealed credential-reference keys per role. A single
  `OPENROUTER_API_KEY` cannot demonstrate Judge/Red Team credential separation.
- Add per-role base URL, request timeout, bounded retries, inference concurrency/rate, max input
  tokens, max output tokens, max calls, and USD cap configuration. Target request rate is not an
  inference-provider rate limit.
- Extend `validate_agent_configuration` activation policy. Hosted Orchestrator/Judge support must
  remain staged until their role-specific authorization/calibration gates pass; do not simply add
  them to `_HOSTED_ELIGIBLE`.
- Connect the active/staged persisted assignment to actual execution and record
  `configuration_sha256`, token usage, measured cost, endpoint identity, trace ID, and typed errors
  in `agent_executions`.
- Extend the presence-only preflight from Red Team-only status to all four roles, including
  distinct credential references, model-catalog existence, structured-output endpoint support,
  timeouts/retries, and authorization artifact validity. It must never print model values or
  secrets in its ordinary status output.
- Require OpenRouter routing controls:
  `provider.require_parameters: true`, no cross-model fallback, endpoint pinning for calibrated
  Judge runs, and an owner-approved data policy (`zdr: true` if a compatible endpoint exists).
- Parse and validate strict JSON Schema output, then validate again against repository contracts.
  Structured output is a transport aid, not a trust boundary.

Suggested new configuration names are intentionally not prescribed here; they require an owner/
implementation decision. Whatever names are selected must preserve existing
`HEADSHOT_<ROLE>_MODEL` keys as canonical model selectors and represent credentials only by sealed
references.

## Presence-only inspection

`Settings.from_env()` was run locally and only set/empty/missing state was printed. No value was
read into this report or exposed in command output.

| Effective local key | State |
|---|---|
| `OPENROUTER_API_KEY` | missing |
| `OPENROUTER_BASE_URL` | missing |
| `HEADSHOT_RED_TEAM_PROVIDER` | missing |
| `HEADSHOT_RED_TEAM_MODEL` | missing |
| `HEADSHOT_JUDGE_PROVIDER` | missing |
| `HEADSHOT_JUDGE_MODEL` | missing |
| `HEADSHOT_DOCUMENTATION_MODEL` | missing |
| `HEADSHOT_ORCHESTRATOR_MODEL` | missing |
| `ANTHROPIC_API_KEY` | missing |
| `OPENAI_API_KEY` | missing |
| Red Team timeout / retries | missing / missing |
| Judge timeout | missing |

`.env.example` documents non-secret examples/defaults, but those are not effective runtime
configuration. Railway variables were not inspected or changed.

Required operational artifacts are also missing:

- `.tdd-swarm/judge-calibration-policy.json`
- `.tdd-swarm/red-team-eval-policy.json`
- `docs/evidence/authorizations/judge-calibration.json`
- `docs/evidence/authorizations/red-team-eval.json`

Therefore T-F03b and T-F04b remain correctly blocked with zero calls.

## Proposed bounded two-hour evaluation envelope

**Owner decision required:** the repository contains no owner-approved dollar cap. The following is
a proposal only and must not be treated as authorization.

### Global hard limits

- Proposed wall-clock ceiling: **2 hours**
- Proposed inference-call ceiling: **56 calls total, including retries**
- Proposed owner spend cap: **USD $5.00 total**
- Estimated cost at the token ceilings below: **about USD $1.56**
- Concurrency: **1**
- Launch rate: at most **0.5 inference requests/second**
- Retries: at most **1 retry per logical sample**, counted inside the 56-call ceiling; honor
  `Retry-After`, otherwise exponential backoff
- Stop immediately at the first of: 2 hours, 56 calls, measured cost reaching the owner-authorized
  cap, per-key credit exhaustion, 402, repeated 429, identity drift, schema failure rate breach,
  missing usage/cost fields, or operator abort
- No target traffic for Judge calibration. Red Team provider evaluation should use
  `target_scope: none` unless the separate owner artifact explicitly authorizes staging.

### Call and token allocation

| Workload | Calls | Max input/call | Max output/call | Estimated max at catalog rates | Proposed sub-cap |
|---|---:|---:|---:|---:|---:|
| Orchestrator smoke/trace | 4 | 12,000 | 2,000 | $0.44 | $0.75 |
| Red Team T-F04b eval | 18 | 8,000 | 2,000 | $0.14 | $0.50 |
| Judge T-F03b calibration: 15 labels × 2 controlled passes | 30 | 10,000 | 1,000 | $0.68 | $1.25 |
| Documentation smoke/trace | 4 | 12,000 | 3,000 | $0.30 | $0.50 |
| **Total** | **56** | **540,000 aggregate** | **86,000 aggregate** | **$1.56** | **$3.00 allocated; $5.00 global hard cap** |

The difference between the $3.00 workload sub-caps and proposed $5.00 global cap is safety margin,
not permission to expand calls or tokens. Reasoning tokens, retries, endpoint price changes, and
provider-specific accounting can consume it. No individual proposed request crosses the current
long-context pricing override thresholds (Gemini above 200k prompt tokens; GPT-5.4 at/above 272k),
but the code must price the actual response, never rely on this estimate.

Each T-F03b/T-F04b authorization must independently state its exact model/provider identity, policy
and threshold hashes, call cap, USD cap, expiry, approver, and target scope. The global proposal does
not substitute for either named authorization.

## OpenRouter caveats and required preflight checks

- OpenRouter publishes no single paid-model RPM guarantee. Limits vary by model/upstream provider;
  429s can originate from OpenRouter or upstream. Additional keys do not increase global capacity.
  Check the role key with `GET /api/v1/key` during authorized zero-call preflight, without logging
  the response fields that could identify the key.
- Catalog `supported_parameters` is model-level aggregation. Structured-output support is
  endpoint-specific and can change. Send `response_format.type=json_schema`, strict schemas where
  supported, and `provider.require_parameters=true`.
- Default OpenRouter routing load-balances across upstream endpoints and allows fallback. That is
  useful for availability but unsafe for calibration identity unless the returned endpoint is
  recorded and the calibration is invalidated on change. Pin the Judge endpoint and disable
  fallback during calibration.
- OpenRouter and each upstream provider are separate data processors. Use synthetic fixtures only.
  Enforce an owner-approved data policy and ZDR routing where compatible. Enabling third-party
  tools/plugins creates separate retention considerations; none are needed for this evaluation.
- Prices can change without a repository change. Snapshot and hash the relevant catalog records at
  authorization time, set OpenRouter `max_price` routing limits where compatible, and abort rather
  than silently route above the authorized price.
- `per_request_limits: null` and `expiration_date: null` are catalog metadata, not an SLA.

## Official sources

Retrieved 2026-07-24:

- [OpenRouter model catalog API](https://openrouter.ai/api/v1/models)
- [List all models and properties](https://openrouter.ai/docs/api/api-reference/models/list-all-models-and-their-properties)
- [API credit and rate limits](https://openrouter.ai/docs/api_reference/limits)
- [Structured outputs](https://openrouter.ai/docs/guides/features/structured-outputs)
- [Tool and function calling](https://openrouter.ai/docs/guides/features/tool-calling)
- [Provider routing and endpoint selection](https://openrouter.ai/docs/guides/routing/provider-selection)
- [Zero data retention](https://openrouter.ai/docs/guides/features/zdr)
- [Provider logging and retention](https://openrouter.ai/docs/guides/privacy/provider-logging)

## Go/no-go checklist

No paid inference call is allowed until all are true:

- T-F03a and T-F04a code, tests, policies, and reviews are complete.
- The exact model IDs still exist in the catalog and required endpoint capabilities pass zero-call
  checks.
- Distinct role-scoped credential references are set, bounded, expiring, and presence-only
  preflight passes.
- The owner supplies valid, unexpired T-F03b and T-F04b authorization artifacts with explicit call
  and USD caps. The proposed $5.00 cap is either explicitly accepted or replaced by the owner's
  lower cap.
- Judge and Red Team identities are distinct; Judge endpoint identity and rubric/criteria/
  ground-truth/policy hashes are pinned.
- Structured-output, timeout, retry, accounting, abort, ZDR/data-policy, and secret-redaction
  controls are mechanically verified.
- Zero-call preflight exits 0. Any missing/invalid field exits 4 before transport construction.

Until then: **NO-GO, zero paid inference calls.**
