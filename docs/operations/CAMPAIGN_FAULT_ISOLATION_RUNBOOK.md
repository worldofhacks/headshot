# Campaign fault isolation and the structured-output retry — operator runbook

**Written:** 2026-07-27
**Applies to:** branch `fix/campaign-resilience-remediation` (`f2a49cd`, `c57f630`, `7ebc008`)

**Nothing described here is deployed.** Staging still runs `456d6e5`, whose hosted configuration has
`max_retries = 0` at both role and global scope. On that release the retry cannot fire and per-case
isolation does not exist. Read this as the procedure for the release that carries the three commits
above, and as the explanation of the failure that produced them — not as a description of current
staging behavior. Authority order and the dated-evidence rule are in
[`../DOCUMENTATION.md`](../DOCUMENTATION.md).

---

## 1. The failure this exists to prevent

Run `50da57b037d44b3c93a10e4c2edf61a8` (staging, 2026-07-26) was authorized for the 34-case workload
`headshot-live-100-batch-01`. It completed 11 cases and dead-lettered on case 12
(`AF-M11-DX-108`).

Case 12 was not a target failure. Both target turns succeeded and the evidence was durably
persisted. Gemini (`google/gemini-2.5-pro`) returned HTTP 200 with correct identity, correct route,
correct usage and correct cost — and a body that did not satisfy the Judge's JSON Schema. The
provider event recorded status `invalid_output`. The transport raised
`HostedProviderResponseError`, which at the time was also the type raised when ledger settlement
failed, so the single handler at the retry seam could not tell "the model formatted its answer
badly" apart from "this call breached an authorized cap" — and correctly refused to retry either.
The exception chain reaching the Runner was:

```
HostedProviderResponseError <- HostedProviderError <- ValidationError
```

The Runner converted that to `campaign_execution_failed` and dead-lettered the whole job. Two
independent conditions made one malformed response fatal: the deployed configuration had
`max_retries = 0`, and `openrouter.py` retried only HTTP `{429, 502, 503}`, so an HTTP 200 carrying
a bad body was never a retry candidate under any configuration.

What the run actually bought, measured:

| | |
|---|---|
| Provider calls / target calls / attempts | 36 / 16 / 12 |
| Verdicts | 11, all `INDETERMINATE` |
| Provider cost | $0.60731395 |
| Total including target calls | $0.76731395 |
| Wall clock | 865 s |
| orchestrator | 12 calls, $0.242890, avg 7,674 ms |
| judge | 12 calls, $0.221662, avg 8,860 ms |
| red_team | 12 calls, $0.142761, avg 37,230 ms (one call 65.9 s) |

Every one of the 11 verdicts carried reason `non_oracle_uncalibrated_indeterminate` with Judge
`calibration_state = unavailable`. **None of them is evidence that the target defended anything.**
The run cost $0.77 and produced no security conclusion at all.

The red_team latency in that table is also why the Red Team per-call timeout was raised from 60 s to
180 s in an earlier commit: a live Chutes selection measured 32.4 s and one call reached 65.9 s.
Token bounds are unchanged at 32768 / 8192 / 8192.

---

## 2. Three outcomes, and what each one licenses you to say

| | Adjudication happened? | Security claim | Opens a finding? |
|---|---|---|---|
| Decisive — `EXPLOIT_CONFIRMED`, `EXPLOIT_LIKELY`, `NO_EXPLOIT_OBSERVED` | yes | yes | only `EXPLOIT_CONFIRMED` |
| `INDETERMINATE` | yes | **no** | never |
| `ERROR` | **no** | **no** | never |

**A finding** exists only for `EXPLOIT_CONFIRMED`, and the Verdict schema requires such a verdict to
carry `confirmation_source ∈ {oracle, canary, human}` — a calibrated model can never be the source.
The `finding` row is written inside `record_attempt_outcome` and only for that state.

**`INDETERMINATE` means the Judge looked and could not conclude.** The evidence was adjudicated;
the adjudication was inconclusive. Reason codes tell you why — `non_oracle_uncalibrated_indeterminate`
and `calibration_unavailable` point at missing calibration authority, `uncertainty_band` at a
confidence floor, `contradictory_evidence` at the evidence itself. An operator sees `INDETERMINATE`
and asks a *calibration and oracle-coverage* question.

**`ERROR` means adjudication did not happen.** The target turns ran, the evidence is durable and
hashed, and the Judge produced nothing usable. It is written at `confidence = 0.0` with
`reason_codes = ["judge_invalid_structured_output"]` and `error_code = "invalid_structured_output"`.
An operator sees `ERROR` and asks a *provider and configuration* question. It is not a claim about
the target in either direction, and it must never be counted as a case the campaign evaluated.

Both non-decisive states are permanent for that attempt. `record_attempt_outcome` rejects any later
write whose state or confidence differs (`RecordConflictError`, "attempt verdict is immutable"), so
an `ERROR` cannot be quietly upgraded after the fact. Re-evaluating the case requires a new
authorized attempt.

---

## 3. `invalid_structured_output`, end to end

Four layers record the same event at four granularities. When you are watching a live campaign,
read them in this order.

**3.1 Provider event** — `provider_call_events`, one row per *physical* send. A schema-invalid
response writes `status = 'invalid_output'` and `error_code = 'invalid_structured_output'`, together
with the measurements that call really incurred: `input_tokens`, `output_tokens`,
`reasoning_tokens`, `measured_cost_usd`, `provider_request_id`, `duration_ms`. The row is written
*before* any retry is attempted, so the cost of a failed attempt can never vanish from the ledger.

```sql
SELECT physical_sequence, status, error_code, returned_model,
       input_tokens, output_tokens, reasoning_tokens, measured_cost_usd, duration_ms
FROM provider_call_events
WHERE organization_id = '<org>' AND campaign_run_id = '<run_id>'
  AND agent_role = 'judge' AND campaign_attempt_id = '<attempt_id>'
ORDER BY physical_sequence, event_id;
```

With one authorized retry a failed-then-recovered Judge call shows exactly two rows,
`physical_sequence` 1 and 2, the first `invalid_output` and the second `succeeded`. An exhausted
retry shows two rows both `invalid_output`.

**3.2 Agent execution** — the retry is a new *physical sequence under the same logical execution and
the same attempt*. There is one `agent_executions` row for the Judge on that case regardless of how
many physical sends it took, and its accounting includes both measured calls. This is the property
that keeps logical call budgets honest: a retry consumes physical authority, not a second logical
call.

**3.3 Verdict** — on exhaustion the transport re-raises the typed
`HostedStructuredOutputInvalid` rather than collapsing into the generic "failed after the authorized
retry", so the Runner can recognize it. `_record_operational_error_verdict` then looks up the
evidence hash already persisted for the attempt and writes:

```json
{"schema_version": "1", "campaign_run_id": "<run>", "attempt_id": "<attempt>",
 "state": "ERROR", "confidence": 0.0,
 "reason_codes": ["judge_invalid_structured_output"],
 "error_code": "invalid_structured_output"}
```

`finding_id` is forced to `None`, so no finding is opened and the Documentation agent never
executes. The Runner then continues to the next case.

This step **fails closed**. If `persisted_evidence_content_hash` returns nothing, the Runner raises
`CampaignAbort(code="attempt_evidence_unavailable")` and the run stops. An attempt with observed
live-target traffic and no durable adjudication record at all is worse than an aborted campaign.

**3.4 Campaign summary** — see §4.

**Where to look while the run is live.** The console does not yet surface any of this (§7), and the
control plane redacts the failure message on write, so the Runner log line is the only place the
sanitized exception chain is observable in production:

```
campaign job failed run_id=<run> failure_code=<code> exception_chain=<Type[code] <- Type[code] ...>
```

The chain carries exception type names plus bounded machine codes only — never provider or target
text. `DispatchUnavailable` and `CampaignAbort` additionally contribute their platform-generated
blocker code (for example `preflight_blocked:hosted_provider_binding_unavailable`), because without
it an operator sees only a class name, which is precisely what made the original failure
undiagnosable.

---

## 4. Reading the outcome counts on a campaign summary

Migration `0026` adds three columns to `campaign_run_summaries`:

| Column | Counts verdicts in state |
|---|---|
| `decisive_verdict_count` | `EXPLOIT_CONFIRMED`, `EXPLOIT_LIKELY`, `NO_EXPLOIT_OBSERVED` |
| `indeterminate_verdict_count` | `INDETERMINATE` |
| `operational_error_count` | `ERROR` |

They are computed with a `count(*) FILTER` over the durable `verdict` rows inside the same
transaction that writes the summary — not from a process-local tally. That distinction is the whole
point: a Runner restart must not be able to reset how many cases a completed run failed to
adjudicate. Two `CHECK` constraints back it up: each count is non-negative, and
`decisive + indeterminate + operational_error <= attempt_count`, so a summary can never claim more
evaluation than the attempt record supports.

Rows written before `0026` are backfilled to `0` rather than `NULL`. Those runs predate per-case
isolation and either adjudicated every case or never produced a summary, so zero operational errors
is the truthful backfill — but it also means a zero on an old row carries no information.

**These columns are not projected by any API route yet** — `/costs`, the birdseye query and the
observability rows all still select `attempt_count`, `request_count` and
`confirmed_finding_count` only. Until console surfacing lands, read them directly:

```sql
SELECT attempt_count, decisive_verdict_count, indeterminate_verdict_count,
       operational_error_count, confirmed_finding_count, measured_cost, started_at, ended_at
FROM campaign_run_summaries
WHERE organization_id = '<org>' AND run_id = '<run_id>';
```

Interpret the row as follows. `attempt_count` is how many cases were *attempted*.
`decisive + indeterminate` is how many were *adjudicated*. `decisive` alone is how many produced a
security conclusion. A gap between `attempt_count` and the sum of the three counts means attempts
exist with no verdict at all — investigate before reporting anything about the run.

---

## 5. The abort matrix

Exactly one failure type isolates to a single case.

| Condition | Type | Behavior |
|---|---|---|
| Judge response failed the role's JSON Schema, after the transport exhausted its authorized retries | `HostedStructuredOutputInvalid` | **Isolated.** `ERROR` verdict, next case. |

Everything else still stops the run. These are deliberately *different types*, not different codes
on one type, so the isolation handler cannot catch them by accident:

| Condition | Type | Runner failure code / state |
|---|---|---|
| Structured output with duplicate JSON object keys | `_StructuredOutputAmbiguous` | `campaign_execution_failed` / failed |
| Retry refused before send by exhausted call, token, cost or rate authority | `HostedRetryAdmissionRefused` | `campaign_execution_failed` / failed |
| Token or cost cap exhausted at settlement | `HostedSettlementBudgetExceeded` | `campaign_execution_failed` / failed |
| Usage record not coherent (double-settled reservation, malformed usage) | `HostedSettlementAccountingInvalid` | `campaign_execution_failed` / failed |
| Returned model differs from authorization; identity not canonical; upstream route unauthorized | `_ModelSubstituted`, `_InvalidProviderIdentity`, `_UnauthorizedProviderRoute` | `campaign_execution_failed` / failed |
| Provider credential unresolvable | `CredentialResolutionError` | `campaign_execution_failed` / failed |
| Physical outcome could not be determined | `HostedProviderError` (`outcome_unknown` event) | `campaign_execution_failed` / failed |
| Evidence integrity failed; evidence unavailable for an `ERROR` verdict; lease loss | `CampaignAbort` | `campaign_aborted` / aborted |
| Preflight or dispatch binding unavailable | `DispatchUnavailable` | `preflight_blocked` / aborted |

Three of these deserve their reasoning stated, because each looks superficially like a formatting
problem and is not.

**Duplicate keys are never retried.** `json.loads` keeps the *last* value for a repeated key while a
schema validator that already ran over the decoded document approves whatever survived that
collapse. The screened payload and the stored payload can therefore differ — a smuggling channel
through an untrusted generator's own output. That is not a formatting slip a second attempt can fix;
retrying would simply re-offer the channel. It keeps its own type and terminalizes at the wire.

**Exhausted authority is deliberately fatal, even though a schema failure is what prompted the
retry.** Pacing, credential resolution, reservation and lineage all run *before* the physical send.
If one of them refuses the second attempt, the cause is not the model's formatting — it is that the
run has reached the end of an envelope a human authorized. Isolating that would let the campaign
continue past the point its authority ran out and report each subsequent case as a formatting
nuisance, when the truthful statement is that the run lost its authorization to evaluate. Only a
human can raise a ceiling, through the governed configuration path, so the run must stop and say so.
`HostedRetryAdmissionRefused` still carries attempt 1's `observed_result`, so the tokens and cost of
a call that genuinely happened are not dropped from the logical execution, and the underlying cap
breach is retained as `__cause__` and appears in the sanitized chain.

**The retry cannot launder a governance violation.** `HostedStructuredOutputInvalid` is raised only
at the `_structured_output` seam, which is reached *after* identity, route, model-substitution and
usage/cost settlement have all already passed. A response that failed any of those never reaches the
retryable branch, so a second send can never be used to paper over a substituted model, an
unauthorized upstream or an unsettled charge.

---

## 6. Granting retry authority: `scripts/derive_retry_configuration.py`

The transport now classifies a schema failure as retryable, but **retry authority comes from a
governed configuration set, never from code**. The fix is inert until a human stages a configuration
whose Judge `max_retries` is 1. The effective count is
`1 + min(HOSTED_MAX_LOGICAL_RETRIES, role.max_retries, global.max_retries)`, with
`HOSTED_MAX_LOGICAL_RETRIES = 1` — so the role limit *and* the global limit must both be raised, and
one retry is the platform maximum.

The script derives that configuration. It makes no provider call, touches no database and needs no
credential, so it is free and safe to run at any time, including mid-campaign.

```bash
python scripts/derive_retry_configuration.py                                  # human-readable
python scripts/derive_retry_configuration.py --workload <workload-id>         # another workload
python scripts/derive_retry_configuration.py --json                           # payload for review/diffing
```

Current output for the default workload:

```
workload            headshot-live-100-batch-01 (34 cases)
generation policy   b83acb23122de9b4911032738bce136f214a34328357b457935ad821b44b0b18

role            logical  retry  physical      input    output    reason    worst $
orchestrator         34      0        34     417792     34816     34816   3.829760
red_team             34      0        34    1114112    278528    278528   2.116813
judge                34      1        68    2228224     34816     69632   3.829760
documentation        34      0        34     417792     17408     34816   1.044480
GLOBAL                               170    4177920    365568    417792  10.820813

platform ceilings   per-role 68 / global 170 / $12
```

Exit status is `0` when the derivation fits the envelope and `1` when it does not; a non-fitting
derivation prints `REFUSED` and every reason. **What to do with the output:**

1. **Read the `NOTE` line.** Per-million prices were *solved* from the measured totals of run
   `50da57b0`, not taken from a list: orchestrator $5 / $25 and judge $1.25 / $10 are exact,
   red_team $0.40 / $3 is within ~0.1%. Documentation never executed in that run — it only fires on
   a confirmed finding — so it has **no measured rate** and is priced at the Judge's rate. That is an
   assumption, flagged as `price_is_assumed`, and the documentation row must be re-derived against
   the staged configuration's real prices before anyone relies on it.
2. **Check the headroom, because there is none.** Judge worst case is 68 physical calls against a
   per-role ceiling of 68, and the global worst case is 170 against a global ceiling of 170. The
   ceilings were raised to fit this derivation exactly: `HOSTED_MAX_PHYSICAL_CALLS` 56 → 68,
   `HOSTED_MAX_GLOBAL_PHYSICAL_CALLS` 136 → 170, `HOSTED_MAX_MEASURED_USD` $10 → $12. The arithmetic
   is 34 cases × (orchestrator 1 + red_team 1 + judge 2 + documentation 1) = 34 + 34 + 68 + 34 = 170;
   the old 136 was the same arithmetic with no retry anywhere (34 × 4). A 35th case, or a retry
   granted to any second role, does not fit and the script will refuse it. Cost has room —
   $10.820813 against $12 — but call count does not.
3. **Hand the `--json` payload to a principal holding `org:config:manage`.** The script
   *cannot* apply it, and this is intentional: staging a configuration set is an append-only
   governed write requiring an authenticated Clerk principal, and inventing that authority inside a
   script is exactly the shortcut this platform exists to catch. Staging is a separate authorized
   operation; deploying the release is another; neither is performed here.
4. **Re-derive after any change to the generation policy, workload, or prices.** The output carries
   `generation_policy_sha256`, and a different policy produces different numbers and a different
   payload. That is the mechanism that stops the caps and the thing they bound from drifting apart
   silently.

Until a configuration set with Judge `max_retries = 1` is staged **and** a release carrying these
commits is deployed, a schema-invalid Judge response behaves exactly as it did on 2026-07-26.

---

## 7. "Complete with operational errors" is not "fully evaluated"

A run that finishes with `operational_error_count > 0` completed. It was **not** fully evaluated,
and no report, summary or console statement may imply otherwise.

Per-case isolation buys one thing: the other 33 cases keep the authority they were granted instead
of being discarded because one model could not format an answer. It buys nothing about the isolated
case. That case has durable evidence, a real target interaction that was really paid for, and no
adjudication. It is un-adjudicated, not safe.

When reporting a run, state coverage as `decisive_verdict_count` out of `attempt_count`, and name
the other two counts explicitly. Never fold `ERROR` into "no exploit observed", never fold it into a
failure rate for the target, and never let it disappear into a percentage. The same discipline
applies to `INDETERMINATE`: run `50da57b0` produced 11 `INDETERMINATE` verdicts with Judge
`calibration_state = unavailable`, which is a statement about the platform's calibration, not about
the Co-Pilot's defenses.

The honest sentence for a run with operational errors is of the form: *"N of 34 cases reached a
security conclusion; M were adjudicated inconclusively; K could not be adjudicated because Judge
adjudication failed."*

---

## 8. What this release does not fix

Do not assume any of the following from the presence of the commits above:

- **Durable no-replay resume.** A dead-lettered run still cannot be resumed without re-attempting
  work.
- **Complete Langfuse hierarchy.** The physical-call and target span hierarchy, the outbox, and
  query-back reconciliation are incomplete, so telemetry is not a sufficient record of a retry.
- **HTTP versus application status.** The migration separating `transport_outcome` from the HTTP
  status code has not landed. The status code currently never reaches `attempt_result` and never
  reaches the Judge as a typed field — which is why an HTTP 200 with an unusable body took this long
  to become legible.
- **Judge calibration against the deployed identities.** Calibration must be rebuilt against the
  exact Chutes and Gemini identities before any non-oracle verdict is decisive.
- **Console surfacing.** The three outcome counts and the `invalid_output` provider events are
  readable only by SQL and the Runner log.

Behavioral proof for what *is* fixed is `tests/test_campaign_fault_isolation_db.py`, which drives a
real four-role hosted campaign against migrated PostgreSQL with the real transport, store,
lifecycle and Runner loop, faking only the socket. It is mutation-verified: disabling the isolation
makes it fail exactly the way production did.
