# Red Team (qwen) traced component — governed composition pending

## Current release truth

`agents/red_team/hosted_generation.py` provides a traced q-generator component, but the production
Runner does **not** compose it. The authorized campaign path currently records Red Team corpus
selection as deterministic seed replay, with no provider request, model usage, tokens, or hosted
cost. That is intentional: an authorized corpus is immutable, so generating or mutating cases
inside its dispatch loop would invalidate the approved scope.

Accordingly:

- q is not a fourth live hosted role in production;
- a deterministic Red Team execution must not be relabeled as a q provider call;
- component/unit tests are not deployment evidence; and
- Langfuse, Agents, Costs, and Traces must show q as unavailable until a real governed execution
  has been durably recorded and remotely verified.

## Component seam

`TracedHostedRedTeamProvider` routes hosted generation through the shared
`OpenRouterTransport` with `role="red_team"`. It uses the shared cost/call/token ledger, the
mandatory physical-lineage recorder, and the immutable prompt registry under
`src/agentforge/agents/prompts/`; it does not create a separate SDK client, prompt store, or
lineage shape.

The component exposes two integration styles:

- `generate_traced(...)` returns proposed variants plus the provider-returned model/request/upstream
  identity, input/output/reasoning usage, measured cost, and physical-attempt count for a
  composition root that owns the logical execution lifecycle.
- `generate(...)` uses `HostedExecutionLifecycle` to record the same logical and physical lineage
  itself.

`require_red_team_subcap(...)` verifies the configured Red Team cost ceiling before a live call.
The shared ledger still enforces the per-role and global call, token, retry, concurrency, and cost
bounds.

The output is always untrusted proposed input. It contains no target credential, evidence authority,
finding verdict, or publication/remediation authority. Model credentials resolve only inside the
private transport from a sealed reference.

## Required production workflow

Production composition must be a distinct, governed workflow:

`generation → normalization/content addressing → quarantine → human review → fresh corpus authorization → dispatch`

It must not be inserted into `SeedReplayRedTeam.propose(...)` or the current authorized case loop.
Before q can be called live, the integration owner must prove all of the following:

1. generation has a separately authorized scope, policy hash, configuration hash, synthetic seed,
   budget, rate limit, abort path, and distinct launcher/approver identities;
2. every attempt obtains its durable logical context and pre-send physical reservation before
   provider I/O;
3. the exact registry prompt bytes and SHA-256 are the system message actually sent;
4. proposed variants remain quarantined and cannot reach a target before review and a fresh,
   content-addressed corpus authorization;
5. provider/model substitution, missing accounting, invalid output, and crash recovery fail closed;
   and
6. a real deployed run produces query-verified provider identity, request ID, usage, cost, and
   logical/physical lineage in the production telemetry views.

Final model-envelope confirmation and every live campaign remain human-only gates. Until this
workflow and its deployed evidence exist, documentation must describe three hosted model roles plus
deterministic Red Team selection—not a live four-model campaign.
