# Provider-call lineage v1

The canonical physical-provider lineage is the linear migration pair
`0018_provider_call_lineage` → `0019_recordable_provider_identity`. It extends the logical
hosted-execution ledger introduced in `0017`; it does not create another execution, prompt, or cost
authority.

## Authoritative shape

`provider_call_invocations` is the durable pre-send reservation for one physical OpenRouter
attempt. `provider_call_events` is its single append-only terminal fact, identified by a lowercase
64-character content-safe identity. Planner and selecting Red Team calls can precede attempt
creation, so `campaign_attempt_id` is intentionally nullable and its event copy is checked with
null-safe identity matching.

The physical tables are authoritative for:

- actual sends and retries;
- returned model, upstream, and provider request identity when observed;
- disjoint input, output, and reasoning usage;
- lossless `NUMERIC(20,12)` USD cost; and
- explicit `measured`, `partial`, `not_observed`, or `invalid` cost state.

`agent_executions` remains the logical role projection. A reservation immediately increments its
physical-attempt projection, and terminal events refresh its cost/event projection. Physical
lineage cannot set logical success, create a role output, grant Judge authority, or bypass
role-output validation. The hosted lifecycle still owns those decisions after semantic validation
and, for Judge, deterministic reconciliation.

The recorder and logical context are mandatory. `OpenRouterTransport` rejects a missing or invalid
recorder during construction and rejects a missing, stale, or mismatched
`ProviderLogicalContextV1` before network I/O. Every physical send, including a retry, must first
commit a reservation derived from the running logical execution. There is no no-op recorder,
unrecorded send path, or retry-only shortcut.

## Prompt and provider identity

The only prompt authority is the immutable package registry under
`src/agentforge/agents/prompts/`. The transport sends the registry resource's exact UTF-8 system
bytes, including its trailing newline, and the reservation binds their SHA-256. A prompt version is
replay metadata only: it never authorizes text and cannot substitute for an exact
role + version + SHA-256 registry resolution. The physical ledger stores no prompt body and creates
no second prompt registry.

OpenRouter request routing and response attribution use different identifiers. A request sends an
exact lowercase provider slug through `provider.only` with fallbacks disabled; router metadata
returns a display identity. The release accepts only these explicitly normalized pairs:

- `anthropic` → `Anthropic`;
- `together` → `Together`;
- `google-vertex` (including region variants) → `Google` or `Google Vertex`;
- `openai` → `OpenAI`; and
- `atlas-cloud` (including route variants) → `AtlasCloud`; and
- `chutes` → `Chutes`.

Both requested and observed identities remain durable. Revision `0019` permits a mismatched returned
model to be retained only on a non-successful logical row, so provider substitution is recordable
evidence but can never be accepted as authorized output. Unknown routing/metadata pairs are invalid
physical responses and cannot produce logical success.

The mapping follows OpenRouter's provider-routing and router-metadata contracts:

- <https://openrouter.ai/docs/guides/routing/provider-selection>
- <https://openrouter.ai/docs/guides/features/router-metadata>

## Historical rows and migration quiescence

Revision `0018` takes an exclusive lock on `agent_executions`, refuses to run while any hosted
execution is `running`, and reserves `detail.provider_lineage_state` as migration-owned metadata.
The environment must therefore be quiesced before upgrade: no old Runner, scheduler enqueue, public
launch, active lease, running hosted execution, or queued authorized work may remain.

Pre-`0018` hosted rows are explicitly marked
`provider_lineage_state=historical_not_instrumented`. They remain terminal, have no fabricated
provider event IDs, and can never claim complete measured cost. New hosted rows are
`canonical_physical`; a terminal canonical row has exactly one terminal event per physical
reservation. Deterministic rows have no provider-lineage marker and remain not applicable. The
console and API must preserve these three states rather than presenting historical absence as zero
activity.

## Crash recovery and replay prevention

Recovery performs no provider or target I/O. For one stale hosted execution it locks the campaign's
`agent_work` rows, then the logical execution and physical ledger, and rechecks lease and staleness
under those locks. In one PostgreSQL transaction it:

1. appends a deterministic `outcome_unknown` event for each open reservation, or reuses the
   already-committed terminal event;
2. projects the physical facts into a failed logical execution without reconstructing semantic
   output;
3. dead-letters queued or leased `agent_work` for that run; and
4. aborts an otherwise queued/running campaign and records the recovery audits.

Those authoritative changes commit or roll back together. A later best-effort telemetry projection
is not part of the authority transaction. Even a physically successful event cannot approve work or
reconstruct a role result lost in the crash.

The private Runner compares the database revision with the one exact packaged Alembic head before
heartbeat recovery, queue claim, and preflight. At a mismatch it stays inert: no lease, job
mutation, provider call, or target call. After a lease is reaped, preflight also rejects any run
that already has a hosted execution with
`prior_hosted_execution_requires_manual_recovery`; reclaim cannot replay the old physical call.

## Red Team composition status

The current governed Runner composes qwen as a real hosted fourth role using this context/recorder
seam. Its live schema returns a `case_ref` from the exact approved candidates, so its output cannot
mutate authorized target bytes. The 2026-07-26 staging run durably recorded 12 Red Team logical
executions and 12 Chutes physical provider calls with attempt lineage.

The separate arbitrary q generator remains a candidate-authoring component. Its required workflow is
generation → normalization/content addressing → quarantine → human review → fresh workload
authorization → dispatch. It cannot feed generation output directly to a target.
