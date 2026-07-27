# Hosted Red Team selection and candidate generation

**Reconciled:** 2026-07-26

**Runtime identity:** [`RED_TEAM_MODEL_RESOLUTION.md`](RED_TEAM_MODEL_RESOLUTION.md)

AgentForge has two deliberately separate hosted Red Team capabilities. Conflating them previously
caused documentation to claim qwen was either absent or allowed to mutate a live campaign. Neither is
true.

## Governed live selector

`HostedReplaySelector` in `src/agentforge/agents/red_team/hosted_replay.py` is the Red Team used by the
private Runner. It:

- runs `qwen/qwen3.5-397b-a17b` through the shared hosted runtime;
- receives a bounded list of exact authorized candidate identities;
- returns one schema-validated `case_ref`;
- carries immutable campaign/attempt/logical/physical provider lineage;
- cannot change the authored input sequence or target binding; and
- cannot judge, confirm, document, publish, remediate, or hold a target credential.

The Runner creates the durable attempt before this provider call. The 2026-07-26 staging run recorded
12 successful Red Team executions and 12 Chutes calls with zero lineage conflicts. Their combined
measured cost was `$0.14276145`; maximum observed latency was 65.9 seconds.

The current per-call envelope is 32,768 input / 8,192 output / 8,192 reasoning tokens and 180 seconds.
That headroom is intentional. Provider completion accounting can place thousands of tokens in output
even when the final schema is small.

## Quarantined candidate generator

`TracedHostedRedTeamProvider` in `hosted_generation.py` can generate proposed variants with shared
OpenRouter transport, prompt authority, physical-call lineage, tokens, cost, and content-addressed
provenance. It is used by target-free acceptance and candidate-authoring workflows; it is not the
Runner's live dispatch selector.

Its output is hostile/untrusted and follows:

```text
generate
  -> normalize and content-address
  -> quarantine
  -> human review
  -> immutable generation/review records
  -> new workload and manifest digest
  -> fresh exact campaign authorization
  -> governed selector and Policy Gateway
```

No generated string can flow directly to the target. This separation preserves the PRD's novel
generation capability without allowing model output to expand an already approved operation.

## Evidence and observability requirements

Both capabilities must use:

- the package-owned Red Team prompt and exact prompt SHA-256;
- the authorization-bound model, upstream, policy, configuration, price, token, call, retry, rate,
  concurrency, timeout, and spend envelopes;
- durable logical execution before physical invocation;
- one provider invocation row plus one terminal event per physical attempt;
- exact returned model/upstream/request ID and measured usage/cost;
- sanitized Langfuse projection with PostgreSQL as the authority; and
- typed terminal errors without raw prompts, responses, credentials, or PHI.

A component test is not deployment evidence. A live-role claim requires durable provider rows and
exact Langfuse query-back (or an explicit queued/failed delivery statement) for the governed campaign.

Current known reliability/observability gaps are in [`../CURRENT_STATE.md`](../CURRENT_STATE.md) and
[`../../PLAN.md`](../../PLAN.md).
