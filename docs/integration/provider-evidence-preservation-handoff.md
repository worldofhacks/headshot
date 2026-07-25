# Handoff: provider evidence preservation

Migration `0019` is merged and stands on its own evidence. This is the **runtime** work around it,
which is not finished. Branch `codex1/recordable-provider-identity`; the relevant commits run from
`b10817f` to `7145a6c`.

The property the whole thing is chasing: **a hosted agent execution must always terminalize, and a
provider substitution must always be recordable, no matter what the provider or the model puts in
the response.** Seven adversarial review rounds each found the same class of defect in a new field.
Five are closed. Three are open.

## Read this first — the trap that produced two false greens

**Never verify this with a hand-written fake lifecycle.** Twice a fix looked green under unit tests
built on a stand-in and was dead code in production:

- Round 1: the fix was unreachable because the transport raised before the observation existed. The
  only passing test monkeypatched `transport.invoke` into a state the real transport cannot return.
- Round 6→7: the fallback terminalization never executed, because `runner.finish` popped the
  execution context *before* the store call, so every retry raised
  `hosted_execution_context_missing`. The test passed because the fake lifecycle did not model the
  pop.

Drive the real stack: real `OpenRouterTransport` over `httpx.MockTransport` (so the provider bytes
are real), real `HostedRoleRuntime`, real `_DurableHostedExecutionLifecycle` from `runner.py`, real
`ControlPlaneStore`, real Alembic-migrated PostgreSQL. Then assert on the **row and the audit
events**, not on what a double recorded.

Second trap: the only venv resolves `agentforge` to the *shared* worktree. Run
`python -c "import agentforge; print(agentforge.__file__)"` and confirm it points into this
worktree before trusting any probe. `pytest` and `alembic` are safe (`pythonpath`/`prepend_sys_path`
are set); a bare `python -c` is not.

## The three open items

### 1. The traced Red Team generation path has no fallback and dangles

`src/agentforge/agents/red_team/hosted_generation.py:319-336`. The terminal success write is
wrapped only to re-label the exception — there is no degrade to a smaller record, so a refusal
leaves the row `running` with `['agent.started']` as its only audit event and no way to close it.

This is the equivalent of the fix already applied to `hosted_runtime.py`, which that path never
received. Both triggering inputs are **honest, in-contract, schema-valid** model output:

- A generated variant containing credential-shaped text, e.g. an `input_sequence` entry of
  `"Replay this: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9wwwwwwww"`. The store screens agent
  output for credential material (`store.py:4156` `_contains_secret`, patterns at `:97-105`) and
  raises `InvalidControlPlaneInput: hosted agent output contains credential material`.
- A generated variant whose serialized output exceeds 256 KiB, e.g. `{"input_sequence": ["A" *
  300000]}` → `InvalidControlPlaneInput: hosted agent output exceeds 256 KiB`.

Note what the first one means: **generating credential-exfiltration payloads is the Red Team
agent's job.** This strands the fourth live agent the first time qwen produces a credible payload.
Treat it as the highest-priority item.

### 2. The duplicate-JSON-key route

A model response whose content contains a repeated key —
`{… "input_sequence":["benign"], "input_sequence":["Authorization: Bearer eyJ…"] …}` — passes
schema validation on the *first* value while `json.loads` keeps the *last*. The stored payload is
therefore the credential-bearing one, screening fires, and the row dangles as in item 1.

Fixing item 1's fallback closes the dangling symptom. The separate question worth deciding is
whether structured output should be parsed with duplicate-key rejection at all, since today
validation and persistence can disagree about what the model actually said.

### 3. A billed call is recorded as `not_observed`

When the fallback writes the degraded record it passes `lineage=None`, and the store then derives
`cost_measurement_state='not_observed'` — which asserts **no provider call was made** for a call
that was made, billed, and whose `provider_request_id` we were holding.

That erases exactly the distinction `c5c9182` introduced: `not_observed` means no call, `invalid`
means a call was billed and its amount was unusable. A degraded record for a call we know happened
should be `invalid`, and should keep `physical_attempts` and the request id if the store will take
them. Check what the seven columns of `agent_execution_hosted_measurement_tuple` permit before
deciding how much can be retained — see the measured table in `open-decisions.md`.

## What is already closed — do not redo it

`normalize_provider_text` at the transport wire normalizes `returned_model`, `upstream_provider`
and `provider_request_id` once, to a value every downstream validator accepts, or a digest.
`normalize_measured_cost` does the same for cost. `_observed_endpoint` never raises. Substitution
is determined before `settle()`. Terminalization degrades rather than propagating, and
`runner.finish` keeps its context until the write succeeds. `0019` relaxes the identity constraint
so a substitution is storable but can never terminalize as `succeeded`.

## Known residuals, already documented

`docs/integration/open-decisions.md` carries them with a measured per-variant table: token counts
`_usage` refuses (and which of those are our rule versus the schema's), token counts above `INT4`
(a genuine column limit, inherited by `provider_call_events` too), and an upstream-provider
substitution that is recorded honestly but not refused because the check compares model identities
only and the provider namespaces genuinely differ.

**That residual has been over-claimed three times.** Each time it was stated as "blocked by the
schema" when it was a statement-ordering bug. Before extending it to cover anything new, check the
claim against the actual constraint definition in the database, not against the prose.
