# Provider-call lineage v1

Migration `0018_provider_call_lineage` follows the already-frozen `0016` Langfuse delivery and
`0017` hosted logical-lineage migrations.

`provider_call_invocations` is the pre-send reservation for one physical OpenRouter attempt.
`provider_call_events` is its single append-only terminal fact, identified by a lowercase
64-character content-safe identity. Planner and selecting Red Team calls may precede attempt
creation, so `campaign_attempt_id` is intentionally nullable and its event copy is checked with
null-safe identity matching.

The physical tables are authoritative for:

- actual send/retry count;
- returned model, upstream, and provider request identity when observed;
- disjoint input/output/reasoning usage;
- lossless `NUMERIC(20,12)` USD cost;
- explicit `measured`, `partial`, `not_observed`, or `invalid` cost state.

`agent_executions` remains the logical role projection. Physical completion refreshes only its
cost/event projection. The pre-send reservation itself immediately projects the physical-attempt
count, so open calls and retry gaps cannot disappear from activity or budget views. It cannot
change logical status, create output hashes, assign Judge decision authority, or bypass role-output
validation. The existing hosted lifecycle performs those operations after semantic validation and,
for Judge, deterministic reconciliation.

An invocation without an event blocks logical terminalization. Runner startup and idle heartbeats
boundedly reconstruct interrupted work from PostgreSQL. Recovery skips every run with a live
`agent_work` lease and, by default, requires the newest physical reservation to be stale beyond
the ten-minute job lease plus a one-minute grace period. It appends one deterministic
`outcome_unknown` event for an open reservation, or reuses an already-committed terminal event
when the worker crashed before logical completion. The Runner then separately invokes the normal
logical failure lifecycle. Even a physically successful event cannot approve or reconstruct a
lost semantic role result. Recovery never contacts a provider or target and is safe when multiple
Runners observe the same row.

OpenRouter request routing and response attribution use different identifiers. The request sends
an exact lowercase provider slug through `provider.only` with fallbacks disabled; router metadata
returns a display name. Hosted-configuration schema v2 binds the exact route and a closed
`completion_token_parameter` to each role configuration hash:

| Role | Model | Exact `provider.only` route | Accepted router identity | Authorized output-token parameter |
|---|---|---|---|---|
| Orchestrator | `anthropic/claude-opus-4.8` | `amazon-bedrock/eu-west-1` | `Amazon Bedrock` | `max_tokens` |
| Red Team | `qwen/qwen3.5-397b-a17b` | `atlas-cloud/fp8` | `AtlasCloud` | `max_tokens` |
| Judge | `google/gemini-2.5-pro` | `google-vertex/global` | `Google` or `Google Vertex` | `max_tokens` |
| Documentation | `openai/gpt-5.4` | `azure/eu` | `Azure` | `max_completion_tokens` |

Catalog preflight must find exactly that endpoint, confirm its ZDR membership and support for the
role's configured parameter, and content-address the result before activation. Transport emits only
that parameter name and never falls back to `max_tokens`/`max_completion_tokens` substitution.
Both configured and served identities remain persisted. Any other pairing is recorded as an invalid
physical response and cannot become a successful logical execution. This follows OpenRouter's
provider-routing and router-metadata contracts:

- <https://openrouter.ai/docs/guides/routing/provider-selection>
- <https://openrouter.ai/docs/guides/features/router-metadata>

Prompt text remains owned by the immutable hosted prompt registry. The physical invocation stores
only the registry's existing version and `prompt_sha256`; it does not introduce prompt storage.

Each durable physical reservation also has one Langfuse
`provider.openrouter.attempt` GENERATION beneath the owning role AGENT. That generation, rather than
the logical hosted-runtime child, carries the physical attempt's tokens and measured/partial cost.
The query-back verifier reconciles invocation/event identity, sequence, model/provider, request ID,
latency, error, token counts, and cost against PostgreSQL before marking delivery exported. This is
candidate behavior, not deployed or query-back evidence.

The canonical q generator component resolves the same durable `provider_context` immediately after
starting its logical Red Team execution and passes it into the shared transport. Its exact system
text comes from the immutable prompt authority; count, category, and synthetic seed data remain in
the user payload, so the recorded prompt hash attests the text actually sent. Missing or invalid
context fails before network I/O, while every send and retry uses this migration's physical ledger.

The candidate Runner now invokes q once per selected frozen seed so a hosted campaign has a real,
physical Red Team provider attempt in the ordered four-role trace. The unreviewed variant is never a
target payload: the Runner stores only its hash plus `quarantined_not_dispatched`, discards the raw
text, and sends the byte-exact SeedReplay case already bound by the campaign grant. Provider or
telemetry failure aborts before target dispatch.

This remains candidate source behavior, not deployed evidence. It also does not create the absent
generation → quarantine → human review → frozen corpus publication → fresh authorization entrypoint.
Any future use of a generated variant must cross that separate boundary; the console may claim four
hosted roles only when the exact deployed campaign and Langfuse query-back prove them.
