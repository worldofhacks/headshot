# ADR-0005 — Exactly one retryable provider failure, and the ceiling that pays for it

- **Status:** Accepted; implemented on `fix/campaign-resilience-remediation` (`f2a49cd`, `c57f630`,
  `7ebc008`). **Not deployed** — staging still runs `456d6e5` with `max_retries=0`, so the behaviour
  described here is inert in every running environment.
- **Date:** 2026-07-27
- **Deciders:** platform author
- **Applies to:** the OpenRouter transport retry seam, the Runner's per-case failure handling, and the
  platform physical-call/spend ceilings in `agentforge/agents/hosted.py`
- **Does not apply to:** target-side retries, the two-person Clerk campaign gate, oracle/canary/human
  confirm authority, the synthetic-data gate (ADR-0003), or Judge verdict semantics. A retry changes
  how many times the Judge is *asked*; it never changes what a verdict is allowed to *say*.
- **Builds on:** [ADR-0004](0004-postgresql-native-hosted-runtime.md) — exact hosted-role routing,
  physical-provider accounting, and fail-closed model/upstream binding

## Context

Run `50da57b037d44b3c93a10e4c2edf61a8` (staging, 2026-07-26) submitted the 34-case workload
`headshot-live-100-batch-01`, completed 11 cases, and dead-lettered on case 12 (`AF-M11-DX-108`).

Both of that case's target turns succeeded and its evidence was durably persisted. What failed was
formatting. Gemini (`google/gemini-2.5-pro`) returned HTTP 200 with correct identity, correct route,
correct usage and correct cost, and a body that did not satisfy the Judge's JSON Schema — provider
event status `invalid_output`. The exception chain was `HostedProviderResponseError` ←
`HostedProviderError` ← `ValidationError`. The Runner converted it to `campaign_execution_failed` and
dead-lettered the whole job. Twenty-two of thirty-four cases were never attempted.

What the run had already spent when it died: 36 provider calls, 16 target calls, 12 attempts, 11
verdicts, 865 s of wall clock, $0.60731395 in provider cost and $0.76731395 including target calls.
Per role — orchestrator 12 calls, $0.242890, mean 7,674 ms; judge 12 calls, $0.221662, mean 8,860 ms;
red_team 12 calls, $0.142761, mean 37,230 ms with one call reaching 65.9 s.

**What was lost was the run, not a security conclusion.** All 11 verdicts were `INDETERMINATE` with
reason `non_oracle_uncalibrated_indeterminate`, and the Judge's `calibration_state` was
`unavailable`. None of them establishes that the target defended anything. The incident is a
durability failure, and reading it as "22 defended cases lost" would be false.

Two independent causes produced it.

First, the deployed hosted configuration carried `max_retries=0` at both role and global scope, so the
transport's attempt loop ran exactly once.

Second — and this is the one that matters — even with a retry allocated, the retryable set could not
have contained this failure. The transport retried only failures in which *no response was observed*:
timeouts, transport errors, and HTTP 429/502/503 via `_RETRYABLE_STATUS`. Every observed response that
failed any check raised the single type `HostedProviderResponseError`, which at that point covered
schema failure, model substitution, identity failure, route violation and ledger settlement failure
alike. One handler at the retry seam could not tell "the model formatted its answer badly" apart from
"this call breached an authorized cap" — and, faced with that ambiguity, correctly refused to retry
either.

So the decision this ADR records is not "add a retry." Raising `max_retries` against the pre-change
type hierarchy would have made a cap breach, an identity failure and a substituted model retryable in
the same stroke. The decision is **which observed provider failures may ever be retried**, and the
answer has to be defensible one failure mode at a time.

## Decision

### 1. The retryable set of *observed* failures has exactly one member

`HostedStructuredOutputInvalid` is raised only at the `_structured_output` seam — that is, only after
identity, route, model-substitution and usage/cost settlement have all already passed. A retry
therefore cannot launder any of them, because by construction none of them was in question. The failed
physical attempt is recorded first, with its measured tokens, cost, request id and `invalid_output`
status, so a retry never erases a call that really happened and was really charged. The retry is a new
physical sequence under the same logical execution and the same attempt, and logical totals include
both measured calls. On exhaustion the typed cause is re-raised as-is rather than collapsing into a
generic "failed after the authorized retry", so `invalid_structured_output` stays visible to the
operator.

The membership test is what makes the set one wide. Every other observed-response failure says one of
two things: *this response did not come from the model, route or identity you authorized* — in which
case a second call is simply a second unauthorized call — or *this run has spent authority it does not
have*, in which case a second call spends more of it. A schema failure is the only observed failure
where everything the platform governs held and only the generator's formatting did not. Applying that
test today admits exactly one type. It is a test, not a quota: if a second failure mode ever satisfies
it, it may join, and the burden is to show that it does.

### 2. Duplicate JSON object keys keep their own type and are never retried

A body with a repeated object key gets `_StructuredOutputAmbiguous` and terminalizes at the wire. The
reason is not fastidiousness. A repeated key validates against the first value while `json.loads`
keeps the last, so the payload that was screened is not the payload that gets stored — a smuggling
channel running straight through an untrusted generator's own output. Retrying it would re-offer the
channel on every attempt. Ambiguity is not a formatting slip; a second attempt cannot "fix" a response
that can legitimately be read two ways.

This distinction is load-bearing rather than theoretical: an earlier, too-broad version of the retry
change made duplicate keys retryable and was caught by `test_provider_evidence_preservation`.

### 3. Only the Judge is granted the retry

The Red Team must not re-generate. A second generation is a *different attack*, and silently swapping
the attack after a formatting failure would change the workload underneath the authorization that
approved it. The Orchestrator and Documentation roles are not worth spending the authority on. The
Judge is the one role whose retry is safe in the sense that matters: the evidence it adjudicates is
already fixed and durably persisted, so a second call re-requests an adjudication of unchanged inputs
rather than producing new ones. `scripts/derive_retry_configuration.py` encodes this as
`_RETRY_ROLES = {"judge": 1}`.

### 4. A retry refused before it is sent stays campaign-fatal, and keeps attempt 1's measurements

A retry re-enters ledger reservation, so a campaign with one physical call or one unit of spend left
has attempt 2 refused at `reserve()` rather than at the provider. `HostedRetryAdmissionRefused` covers
that case. It is deliberately **not** a `HostedStructuredOutputInvalid`, even though a structured-output
failure is what prompted the retry: exhausted call, token, cost or rate authority is a governance fact
about the whole campaign, and isolating it per case would let a run continue past the end of its
authorized envelope while reporting the breach as a formatting nuisance.

It carries the first attempt's `observed_result`, so the measured tokens and cost of a call that
genuinely happened are never dropped from the logical execution row, and it retains the cap breach as
`__cause__` so the operator sees both facts. No additional send occurs, so the refusal itself consumes
nothing.

All four pre-send blockers — pacing, credential resolution, reservation and lineage — route through one
`refuse_before_send` helper, so none of them can be the one that forgets. On a first attempt there is
nothing to preserve and the error passes through unchanged.

### 5. Settlement failures split into a governed ceiling and an accounting fault

`HostedSettlementBudgetExceeded` and `HostedSettlementAccountingInvalid` replace a single funnel that
had erased the difference between them. Neither is retryable. The split exists because the two demand
different human responses: a run that legitimately reached its authorized ceiling can be raised through
the governed configuration path, while a double-settled reservation or an incoherent usage record is a
correctness fault in accounting and must never be read as "we ran out of budget."

### 6. Per-case fault isolation in the Runner — for that one type only

When the structured-output retry is exhausted, the Runner persists a contract-valid `ERROR` verdict
(reason `judge_invalid_structured_output`) against the already-observed evidence and continues to the
next case. No finding is raised and the Documentation agent does not execute. If the evidence hash
cannot be recovered, it fails closed rather than writing a verdict against evidence it cannot name.

Isolation keys on the exception *type*, not on a predicate over a status string. `CampaignAbort`,
`DispatchUnavailable`, credential, budget, route, identity, evidence-integrity, lease-loss and
unknown-outcome failures are unrelated types and still abort the run. A failure mode nobody has
classified yet is fatal by default; making something isolatable requires deliberately typing it so.

### 7. The isolated errors are counted from durable rows, not inferred

Migration `0026_campaign_outcome_breakdown` persists `decisive_verdict_count`,
`indeterminate_verdict_count` and `operational_error_count` on `campaign_run_summaries`, computed from
the durable verdict rows inside the completion transaction rather than from a process counter, with a
`CHECK` that none of them can exceed `attempt_count`.

Without this, an isolated error is indistinguishable from an adjudicated case at the summary level,
which is precisely how a resilience feature turns into a coverage lie: the run reports 34 of 34 cases
"processed" and nobody can see that some of them were never judged. Deriving the counts from committed
verdicts rather than from a variable in the Runner means a crash between the last verdict and the
summary cannot invent one.

## Alternatives rejected

**Retry every failure the transport is physically able to re-send** (equivalently: raise `max_retries`
and change nothing else, since the pre-change hierarchy funnelled all observed failures into one type).
This launders cap breaches — a retry after a budget refusal spends authority no human granted — and it
re-offers the duplicate-key smuggling channel on every attempt. It also turns a model substitution or
an identity failure into a second unauthorized call to a provider that has already demonstrated it is
not serving the staged identity, which is the exact failure ADR-0004's fail-closed binding exists to
prevent. Diagnosis suffers too: the operator ends up seeing whichever failure came last, not the one
that started it.

**Retry nothing — the status quo.** Its price is measured: 22 of 34 cases per malformed Judge body,
plus the mis-attribution. The run surfaces as `campaign_execution_failed`, so a platform-wide failure
is reported for an incident in which 11 cases' evidence was durably fine and one provider response was
badly formatted.

**Make the Judge failure non-fatal without a retry** — that is, item 6 without item 1. This is the
cheapest option and it would have salvaged the run, which is why it deserves a real answer rather than
a dismissal. It is rejected because it converts a fault that usually clears on a second attempt into a
permanent `ERROR` verdict for that case. By the time the Judge is called, the platform has already
spent the target turns, the evidence write, and the orchestrator and red-team calls that produced the
evidence — the red_team call alone averaged 37,230 ms and is the most expensive step in wall clock.
Declining to adjudicate all of that rather than paying for one more Judge call is the wrong trade at
the Judge's solved rate of $1.25 / $10 per million tokens. The two mechanisms are therefore kept
together and ordered: retry first, isolate only once the retry is exhausted.

## The ceiling raise, as arithmetic

The old ceilings were `HOSTED_MAX_PHYSICAL_CALLS = 56` per role, `HOSTED_MAX_GLOBAL_PHYSICAL_CALLS =
136`, and `HOSTED_MAX_MEASURED_USD = $10`. The global figure is 34 cases × 4 logical roles = 136 —
exactly one physical call per logical call, with no retry allocated anywhere. It could not accommodate
a retry by construction.

Granting the Judge one retry makes its worst case two physical calls per logical call:

```
34 × (orchestrator 1 + red_team 1 + judge 2 + documentation 1)
  = 34 + 34 + 68 + 34
  = 170 physical calls
```

The per-role ceiling follows from the largest single role in that sum: the Judge's 34 × 2 = 68.
Hence `HOSTED_MAX_PHYSICAL_CALLS` 56 → 68 and `HOSTED_MAX_GLOBAL_PHYSICAL_CALLS` 136 → 170.

`scripts/derive_retry_configuration.py` derives the spend worst case for `headshot-live-100-batch-01`
from the same policy bounds:

| Role | Logical calls | Retries | Physical calls | Worst-case USD |
|---|---:|---:|---:|---:|
| orchestrator | 34 | 0 | 34 | 3.829760 |
| red_team | 34 | 0 | 34 | 2.116813 |
| judge | 34 | 1 | 68 | 3.829760 |
| documentation | 34 | 0 | 34 | 1.044480 |
| **total** | **136** | | **170** | see below |

with token bounds of 4,177,920 input, 365,568 output and 417,792 reasoning.

The **call** columns above are pure arithmetic and therefore final. The **spend** column is not: it
depends on per-token prices, which are authority carried by a reviewed `HostedConfigurationSet`.

An earlier draft of this ADR quoted a worst case of `$10.820813` derived from prices solved out of
run `50da57b0`'s measured totals. That was withdrawn. Solving a price from an average conflates the
rate with the usage mix, cannot produce a rate at all for a role that never executed (Documentation
fires only on a confirmed finding, so it had none and was being priced at the Judge's rate), and
goes stale the moment a provider re-prices. `scripts/derive_retry_configuration.py` now **refuses**
to derive unless it is handed a reviewed configuration carrying every role's exact price.

`HOSTED_MAX_MEASURED_USD` moves $10 → $12 as a provisional value. Whether $12 is correct is an
**open question** until the derivation is run against the real reviewed base; the script recomputes
the global ceiling from those exact prices and refuses if the result does not fit, rather than
assuming $12 survives. The call ceilings do not depend on price and are settled. The script re-checks every role and the global
total against the ceilings and reports each way the derivation could be unsafe, so if a policy or
workload change pushes the worst case past $12 that is a visible failure rather than a silent
overspend.

Two notes on what this raise does *not* touch. The 34/33/33 partition of the frozen 100-case corpus was
sized so that each batch's Σ(target turns) ≤ 56; `tests/test_live_100_batches.py` pins its own literal
`56` for that invariant and still passes, so raising the role call ceiling does not re-open the batch
plan. Separately, the Red Team's per-call timeout was raised 60 s → 180 s in an earlier commit on
measured grounds — a live Chutes selection averaged 32.4 s and one call reached 65.9 s — with token
bounds unchanged at 32768 / 8192 / 8192. That is an adjacent measurement-driven bound, not part of the
retry grant.

## This is inert until a governed configuration allocates the retry

Retry authority comes from configuration, never from code. The transport computes

```
attempts = 1 + min(HOSTED_MAX_LOGICAL_RETRIES, role.max_retries, global.max_retries)
```

and the deployed hosted configuration has `max_retries=0` at both scopes, so `attempts` is 1 and none
of the machinery above executes. Staging runs `456d6e5`. Nothing in this ADR has been deployed.

Raising `HOSTED_MAX_*` changes what a governed configuration is *permitted to request*; it does not
request anything. Ceilings are ceilings, not grants.

`scripts/derive_retry_configuration.py` derives the governed configuration and prints it with its
content digest, and it deliberately **cannot apply it**. Staging a configuration set is an append-only
governed write that requires a Clerk principal holding `org:config:manage`, and manufacturing that
authority inside a script is exactly the shortcut this platform exists to catch. Who executes that
staged write, and when, is an **open question**.

## Validation

The decision is true when:

- exactly one observed-response failure type is caught at the retry seam, ordered ahead of the general
  `HostedProviderResponseError` handler, which continues to refuse every settlement, identity, route
  and model failure without a second send;
- a duplicate-key body is refused with no second send;
- a retry refused by exhausted authority raises the campaign-fatal type carrying attempt 1's measured
  cost, retains the cap breach as `__cause__`, and results in exactly one physical request;
- an exhausted structured-output retry persists an `ERROR` verdict with reason
  `judge_invalid_structured_output` and the run continues, while abort, dispatch, credential, budget,
  route, identity, evidence-integrity, lease-loss and unknown-outcome failures still end it;
- the `campaign_run_summaries` breakdown columns are computed from durable verdict rows and cannot
  exceed `attempt_count`;
- `scripts/derive_retry_configuration.py` reports no problems for each authorized batch.

The isolation itself is proved by `tests/test_campaign_fault_isolation_db.py`, which drives a real
four-role hosted campaign against migrated PostgreSQL using the real transport, store, lifecycle and
Runner, faking only the socket. It is mutation-verified: disabling the isolation makes it fail in
exactly the way production did. `tests/test_structured_output_retry.py` and
`tests/test_operational_error_verdict.py` cover the transport seam and the ERROR-verdict contract.

## Outstanding

Deliberately not delivered here, and not to be described as done:

- durable no-replay resume;
- the complete Langfuse physical-call/target hierarchy, its outbox, and query-back reconciliation;
- the HTTP/application-status migration separating `transport_outcome` from the HTTP status code — the
  status code currently never reaches `attempt_result` and never reaches the Judge as a typed field;
- rebuilding Judge calibration against the exact Chutes and Gemini identities. Until that lands,
  verdicts remain `non_oracle_uncalibrated_indeterminate`, so the resilience bought here protects a run
  that does not yet produce security signal — an `ERROR` verdict is not meaningfully worse than the
  `INDETERMINATE` it replaces;
- console surfacing of the new outcome breakdown.
