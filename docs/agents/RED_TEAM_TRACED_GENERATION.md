# Red Team (qwen) as the fourth live, traced agent — wiring handoff

Goal: Red Team (qwen) lands in `agent_executions` with the **identical** trace/cost/lineage shape
as Orchestrator (opus) / Judge (gemini) / Documentation (gpt), so all four appear uniformly across
Langfuse / Costs / Traces / Agents. This note is the composition-root wiring; the component lives
in my lane (`agents/red_team/hosted_generation.py`), the wiring lives in Codex's `runner.py`.

## What's built (my lane, done + tested)

`agents/red_team/hosted_generation.py`:

- **`TracedHostedRedTeamProvider`** — routes Red Team hosted generation through the SAME
  `OpenRouterTransport` as the other roles (`role='red_team'`), so the shared `HostedUsageLedger`
  enforces the Red Team per-role **cost subcap + call/token caps** within the global kill switch —
  no divergent SDK client.
  - `generate(seed, *, count, category) -> list[dict]` — SELF-RECORDING via the
    `HostedExecutionLifecycle` seam (`start` → `invoke` → `HostedExecutionLineage` → `finish`).
    Drop-in for `mutation.mutate(..., provider=...)` (the two-stage loop's generation).
  - `generate_traced(seed, *, count, category) -> RedTeamGenerationResult` — the raw traced call;
    returns `variants` + `measured_cost_usd` + `input_tokens`/`output_tokens`/`reasoning_tokens` +
    `returned_model` + `provider_request_id` + `upstream_provider` + `physical_attempts`. Use this
    where the composition root owns its own `start/finish_agent_execution` (the runner).
- **`require_red_team_subcap(configuration, ceiling_usd=$1)`** — assert the configured red_team
  `limits.max_usd` ≤ $1 before a live run; the ledger enforces it per call.

Governance is unchanged: the Red Team is the UNTRUSTED generator — `generate*` returns PROPOSED
input only (`input_sequence` continuations), never a credential/`content_hash`/verdict, never a
target credential or a second network exit; the provider (model) credential is resolved only inside
the transport via the sealed reference. Candidates still flow review → authorization → dispatch.

## The gap in `runner.py` (Codex's lane) and the exact wiring

Today `runner.py` (~lines 810–871) records a `red_team` execution but the step is
`self.red_team.propose(...)` — a **seed-replay case-selection** whose `_finish_agent_execution`
carries **no `measured_cost` and no tokens**. So Red Team shows up as a silent seed-replay (0 cost,
no live trace) while the other three show real LLM cost/tokens. That case-selection is correctly
deterministic (the corpus-hash invariant forbids mutation inside an authorized run) — leave it.

The Red Team's **LLM work** is the two-stage **generation** phase (produce variants → normalize/
content-address → human review → fresh authorization → dispatch). Wire the traced generation there
so it records real cost/tokens. Minimal shape for the generation step:

```python
# construct once per run (composition root), from the same config/transport as the other roles:
traced = TracedHostedRedTeamProvider(
    transport=self.hosted_transport,  # the shared OpenRouterTransport
    lifecycle=...,
    role_identity=RedTeamRoleIdentity(  # only needed for the self-recording generate()
        provider=rt.provider,
        model=rt.model_id,
        upstream_provider=rt.upstream_provider,
        prompt_version=rt.prompt_version,
        prompt_sha256=rt.prompt_sha256,
        role_configuration_sha256=rt.configuration_sha256,
    ),
    configuration_sha256=configuration.configuration_sha256,
    generation_policy_sha256=authorization.generation_policy_sha256,
    call_bounds=call_bounds["red_team"],
    parent_execution_id=orchestrator_execution,
)

# in the generation step, using the runner's existing store seam:
gen_execution = self._start_agent_execution(
    run_id=run_id,
    agent_role="red_team",
    input_payload={"phase": "generation", "category": category, "count": count},
    parent_execution_id=orchestrator_execution,
    detail={"phase": "generation"},
)
try:
    result = traced.generate_traced(seed, count=count, category=category)
except Exception as exc:  # budget/provider refusals are typed
    self._fail_agent_execution_preserving_error(
        primary_error=exc,
        execution_id=gen_execution,
        status="failed",
        output_payload={"status": "failed"},
        error_code=getattr(exc, "code", "red_team_generation_failed"),
        detail={"phase": "generation"},
    )
    raise
self._finish_agent_execution(
    execution_id=gen_execution,
    status="succeeded",
    output_payload={"variant_count": len(result.variants)},
    measured_cost=float(Decimal(result.measured_cost_usd)),  # real qwen cost
    input_tokens=result.input_tokens,
    output_tokens=result.output_tokens,
    detail={
        "phase": "generation",
        "returned_model": result.returned_model,
        "provider_request_id": result.provider_request_id,
        "reasoning_tokens": result.reasoning_tokens,
        "upstream_provider": result.upstream_provider,
    },
)
# result.variants then flow into mutate()/normalize -> review -> fresh authorization -> dispatch.
```

`trace_id`, `campaign_run_id`, `attempt_id`, `parent_execution_id`, provider/model come from the
store's `start_agent_execution`; `measured_cost` + tokens come from the finish above — identical to
the other three roles, so `AgentActivityReadModel` surfaces Red Team uniformly.

Alternatively, for a composition that uses the `HostedExecutionLifecycle` abstraction directly, pass
that lifecycle to the provider and call `generate()` — it self-records the identical lineage.

Contract coordination: I did NOT touch the agent read-models or the lineage shape. Only the
`ToolScopeReadModel` block in `api/read_models.py` remains mine (unrelated). If the `agent_executions`
finish fields change, `generate_traced()` returns the raw values to map — nothing in my component
pins a divergent shape.
