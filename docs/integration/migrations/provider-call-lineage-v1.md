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
returns a display name. The release accepts only these explicitly normalized pairs:
`anthropic` → `Anthropic`, `together` → `Together`, `google-vertex` (including region variants) →
`Google` or `Google Vertex`, and `openai` → `OpenAI`. Both configured and served identities remain
persisted. Any other pairing is recorded as an invalid physical response and cannot become a
successful logical execution. This follows OpenRouter's provider-routing and router-metadata
contracts:

- <https://openrouter.ai/docs/guides/routing/provider-selection>
- <https://openrouter.ai/docs/guides/features/router-metadata>

Prompt text remains owned by the immutable hosted prompt registry. The physical invocation stores
only the registry's existing version and `prompt_sha256`; it does not introduce prompt storage.

The canonical q generator component resolves the same durable `provider_context` immediately after
starting its logical Red Team execution and passes it into the shared transport. Its exact system
text comes from the immutable prompt authority; count, category, and synthetic seed data remain in
the user payload, so the recorded prompt hash attests the text actually sent. Missing or invalid
context fails before network I/O, while every send and retry uses this migration's physical ledger.

This does **not** make q live in the production Runner. The current Runner consumes only immutable,
already-reviewed campaign corpora; it has no production generation → quarantine → human review →
fresh corpus authorization entrypoint. Calling q inside authorized case selection would violate
that boundary, so this migration deliberately does not do it. Until that separate governed
candidate-generation workflow is composed, the console must not claim four live hosted roles.
