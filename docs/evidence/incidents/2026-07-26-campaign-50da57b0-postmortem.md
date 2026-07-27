# Incident postmortem — staging campaign `50da57b037d44b3c93a10e4c2edf61a8`

- **Incident date:** 2026-07-26, window `20:58:06Z`–`21:12:32Z` (865 s wall clock)
- **Environment:** staging, release `456d6e5`
- **Workload:** `headshot-live-100-batch-01`, 34 authored cases
- **Terminal state:** `failed / campaign_execution_failed`; the job was dead-lettered
- **Remediation:** branch `fix/campaign-resilience-remediation` (`f2a49cd`, `c57f630`, `7ebc008`) —
  **unmerged and undeployed**
- **Detection latency:** open question
- **Related evidence:** [`../../CURRENT_STATE.md`](../../CURRENT_STATE.md) §"Latest governed live run",
  [`../../cost/COST_ANALYSIS.md`](../../cost/COST_ANALYSIS.md)

## Summary

A single `HTTP 200` response ended a 34-case authorized campaign at case 12. The Judge's call to
`google/gemini-2.5-pro` returned successfully, with a correct provider identity, a correct route, and
usage and cost that settled cleanly against the ledger — but with a body that failed the Judge's
strict output schema. The provider event was recorded as `invalid_output`. Because the transport
retried only on transport-level status codes, and because the deployed hosted configuration
authorized zero retries anyway, and because the Runner's only unit of fault containment was the whole
job, that one malformed body was converted into `campaign_execution_failed` and the entire batch was
dead-lettered. Eleven completed cases and `$0.76731395` of authorized spend were stranded in a
terminal run with no resume path.

Nothing was exploited, nothing was published, and no accounting was lost. The failure was
fail-closed. It was also almost entirely undiagnosable from the operator-facing surfaces: the Runner
emitted no log line beyond `Starting Container`, and the queue redacted the failure detail, so the
only artifact a human could see was the string `campaign_execution_failed`.

## Timeline

Per-case wall-clock timestamps were not retained; the sequence below is ordered by durable row
sequence, not by clock, except where a timestamp is given.

1. `20:58:06Z` — the campaign starts against the authorized live target under the reviewed
   `headshot-live-100-batch-01` manifest.
2. Cases 1–11 execute end to end. Each produces a durable attempt, a durable attempt result, and a
   durable verdict. All eleven verdicts are `INDETERMINATE`.
3. Case 12, `AF-M11-DX-108`, dispatches. Both target turns succeed and the evidence envelope is
   durably persisted before any adjudication is attempted. Nothing about the target interaction
   failed.
4. The 12th Judge execution calls `google/gemini-2.5-pro`. The provider returns `HTTP 200` with
   13,574 input, 230 output and 752 reasoning tokens at a measured `$0.0267875`. Identity, route,
   model substitution and usage/cost settlement all pass. Strict schema validation of the body does
   not.
5. The transport raises the failure through `HostedProviderResponseError` <- `HostedProviderError`
   <- `ValidationError`. No retry is attempted: the response was `HTTP 200`, and the deployed
   configuration's `max_retries` is `0` at both the role and global level.
6. The Runner has no per-case handler for this. The exception propagates out of the case loop, is
   converted to `campaign_execution_failed`, and the job is dead-lettered.
7. `21:12:32Z` — the run reaches its terminal state with 22 of 34 authored cases never dispatched.

## Impact

| Measured | Value |
|---|---:|
| Authored cases in the batch | 34 |
| Cases adjudicated | 11 |
| Cases attempted | 12 |
| Cases never dispatched | 22 |
| Durable attempts / attempt results | 12 / 12 |
| Verdicts persisted | 11, all `INDETERMINATE` |
| Provider physical calls | 36 |
| Live target calls | 16 (15 `HTTP 200`, 1 `HTTP 422`) |
| Provider-measured cost | `$0.60731395` |
| Contracted target-call accounting | `$0.16` |
| Combined recorded amount | `$0.76731395` |
| Wall clock | 865 s |

Per role, across 12 physical calls each:

| Role | Calls | Measured cost | Mean latency |
|---|---:|---:|---:|
| `orchestrator` | 12 | `$0.242890` | 7,674 ms |
| `judge` | 12 | `$0.221662` | 8,860 ms |
| `red_team` | 12 | `$0.142761` | 37,230 ms |

The Documentation agent never executed, because no verdict ever reached `EXPLOIT_CONFIRMED` — a
structural property of this platform, not a consequence of the incident, but one that matters later
because it is why the remediation has no measured Documentation price to derive from.

No finding was opened. No report was drafted. No remediation was proposed. No case was silently
marked safe. The user-visible cost of the incident is 22 unexecuted cases, `$0.76731395` of spend
that produced no completed batch, and eleven cases' worth of evidence that the platform can neither
resume from nor query-back verify: all 36 agent executions and all 16 target requests remain
`langfuse_status = queued`, and the existing verifier accepts only campaigns present in
`campaign_run_summaries`, so a failed run is rejected outright.

## Correction of record: the 11 INDETERMINATE verdicts

The eleven verdicts that did land were initially read as a positive result — eleven attacks the
target held against. **That reading is wrong and should not be repeated.**

Every one of the eleven carried reason `non_oracle_uncalibrated_indeterminate`, and the Judge's
`calibration_state` was `unavailable`. Staging had no enabled exact-identity Judge calibration for
this release, so the model's opinion had no authority and the disposition fell through to
`INDETERMINATE` by design. What those rows record is that **no deterministic oracle confirmed an
exploit**. They do not record that the target refused the attack, that the attack was well-formed,
or that the evidence was even examined by a Judge whose accuracy anyone has measured against these
identities. An uncalibrated `INDETERMINATE` is the absence of a verdict, not a safe verdict.

Reading absence of confirmation as evidence of defense is the specific failure mode this platform
exists to prevent, and it happened to us in our own incident review. The calibration record that
would be needed to give a model verdict any weight is itself superseded; see
[`../judge-calibration/RESULT_2026-07-24.md`](../judge-calibration/RESULT_2026-07-24.md), which is
bound to a Judge identity production does not run, and
[`../red-team/CAPABILITY_STATUS.md`](../red-team/CAPABILITY_STATUS.md) for the standing fact that
nothing in this repository has ever confirmed an exploit.

## Root cause

The platform had no representation for a *recoverable* provider fault. Every failure that survived
the transport was, by construction, campaign-fatal.

Concretely: a response that has passed identity verification, route verification, model-substitution
checking and usage/cost settlement, and fails only strict schema validation of its body, is a
formatting defect in one generator's output about one case. It is not a governance event. But it was
raised as `HostedProviderResponseError`, the same base type used for cap breaches and settlement
failures, and the Runner had exactly one behavior for anything that escaped the case body: convert
to `campaign_execution_failed` and dead-letter the job. The blast radius of a formatting defect was
therefore the entire authorized batch.

Three independent layers each turned this from a recoverable event into a fatal one, and **any one of
them alone was sufficient**:

1. `src/agentforge/providers/openrouter.py` retried only on `_RETRYABLE_STATUS = frozenset({429, 502,
   503})`. An `HTTP 200` with an unusable body was, by that predicate, a success that failed.
2. The deployed hosted configuration set `max_retries = 0` at role and global scope. Even a correct
   retry classification would have been refused, because retry authority comes from a governed
   configuration and never from code.
3. The Runner's fault granularity was the job. There was no per-case containment to fall back to
   once the transport gave up.

Fixing only the classification would have produced a system that classified correctly and still did
not retry. Fixing only the configuration would have authorized retries that nothing requested. All
three had to move.

## Contributing factors

### (a) Exception-type conflation made a formatting fault indistinguishable from a cap breach

`HostedProviderResponseError` was a funnel. A schema-invalid body, a token cap exhausted at
settlement, a cost cap exhausted at settlement, and a corrupt usage record all arrived at the same
handler as the same type, distinguished only by a string code that callers did not switch on. This
is why the incident could not be cheaply patched: the obvious fix — retry on
`HostedProviderResponseError` — would have retried cap breaches, spending authority a human never
granted, which is a strictly worse failure than the one being fixed. The conflation did not merely
obscure the diagnosis; it foreclosed the safe repair.

The same funnel erased a distinction that matters operationally in the other direction.
"This run reached its authorized ceiling" is a governance outcome a human can respond to by raising
the ceiling through the configuration path. "The usage record is not coherent" is a correctness fault
in accounting that must never be answered by raising a limit. Both surfaced identically. An operator
holding only the funnel type could not tell which response was appropriate, and the code could not
either — `except HostedBudgetExceeded` could not catch a settlement-time cap breach at all.

The remediation is therefore a type taxonomy rather than a retry flag, and it is deliberately narrow:
exactly one type is retryable, and it can only be raised at a seam where every governance check has
already passed.

### (b) The diagnosability gap: the database knew everything and no operator surface said anything

PostgreSQL held a complete account of the failure within seconds of it happening — 36 agent
executions with role, parent linkage, latency, tokens and measured cost; a provider event with status
`invalid_output`; 12 durable attempts; 11 durable verdicts; a settled ledger. None of it reached a
human.

The Runner emitted no log output whatsoever beyond `Starting Container`. The queue redacted the
failure detail on dead-letter. The single visible artifact of a 14-minute, `$0.77`, 36-provider-call
campaign was the opaque token `campaign_execution_failed`. That string is compatible with a
credential failure, a route rejection, an evidence-integrity abort, a lease loss, a budget breach and
a malformed model response, and it distinguishes none of them. Langfuse offered no fallback: every
row was still `queued`, and the verifier refuses failed campaigns outright, so the external
projection could not be used to reconstruct the trace either.

Diagnosis required querying the database directly and reading the provider event rows by hand. That
is an acceptable *deep* investigation path and an unacceptable *first* one. It is also the reason
this incident's true cause was not obvious for far longer than the fault itself was subtle — and the
reason the eleven `INDETERMINATE` verdicts were misread: with no failure narrative available, the
only legible artifact was a row count that looked like progress.

`7ebc008` includes the narrow correction: the Runner's sanitized exception chain now carries
`DispatchUnavailable` and `CampaignAbort` messages, which are always platform-generated blocker codes
and never provider or target text. The effect was immediate and disproportionate to the change — an
opaque `DispatchUnavailable` became `preflight_blocked:hosted_provider_binding_unavailable` on first
use. This is a partial fix. Structured Runner logging and console surfacing remain outstanding.

### Other contributing factors

- **No durable resume.** A terminal batch cannot restart from its 11 completed, durably persisted
  attempts. The full cost of any late failure is the whole run, which raises the stakes of every
  other reliability gap.
- **The transport outcome and the HTTP status code are not separable.** The status code never reaches
  `attempt_result` and never reaches the Judge as a typed field, so "the request completed" and "the
  application succeeded" are still the same fact in the data model. The run also produced one
  `HTTP 422` from the target for a message exceeding its 4,000-character limit, recorded with
  `status = succeeded` — correct about receipt, misleading about outcome.
- **Latency headroom was set below observed behavior.** The Red Team's per-call timeout was 60 s
  while a live selection measured 32.4 s and one call reached 65.9 s. This did not cause the
  incident, but the run is what exposed it.

## What went right

The failure was clean in every dimension except recoverability, and that is worth stating precisely
rather than glossing.

Case 12's evidence was durably persisted **before** adjudication was attempted, so the fault was
confined to the adjudication side of a case whose target interaction had already succeeded. The
accounting stayed coherent under failure: 36 physical calls reconcile against 36 logical executions,
per-role cost and latency remain fully attributable to eight decimal places, and no spend escaped the
ledger. The authorization envelope held; nothing was spent beyond what a human granted. No finding
was opened on an unadjudicated case, no verdict was invented to paper over the gap, and no case was
downgraded to a safe disposition — the system refused to produce a security signal it could not
justify, which is the behavior we want under fault.

The run also generated the measurement that fixed a latent, unrelated defect: the 65.9 s Red Team
call is the direct evidence that the 60 s timeout was unsafe, and the per-role token and cost split
is what later allowed the governed retry configuration to be *derived* from measured prices rather
than estimated.

## What went wrong

- One malformed body from one generator cost 22 unexecuted cases.
- The safe repair was foreclosed by the type system, so the incident could not be hot-fixed.
- The operator-facing failure signal carried no information at all.
- The incident review's first conclusion — eleven successful defenses — was wrong, and was reached
  because the only legible artifact was a count.
- Eleven cases of durable, paid-for work were stranded with no resume path and no query-back
  verification.

## Remediation

Implemented on `fix/campaign-resilience-remediation`. **Nothing below is deployed.**

**One retryable failure, raised at one seam.** `HostedStructuredOutputInvalid`
(`src/agentforge/providers/openrouter.py`) is the only provider failure that may be retried. It is
raised only at the `_structured_output` seam, after identity, route, model substitution and ledger
settlement have all passed, so a retry cannot launder any of them. The failed physical attempt stays
durably recorded with its measured tokens, cost, request id and `invalid_output` status; the retry is
a new physical sequence under the same logical execution and attempt.

**Ambiguity is never retried.** Duplicate JSON object keys raise a separate
`_StructuredOutputAmbiguous`, which is refused outright. A repeated key validates against the first
value while `json.loads` retains the last — a smuggling channel through an untrusted generator's own
output. Retrying it would simply re-offer the channel, so the distinction is between "the model
failed to produce the shape we asked for", which a second attempt can legitimately fix, and "the
response can be read two ways", which it cannot.

**Authority failures stay fatal and stay measured.** When a retry is refused *before send* by
exhausted call, token, cost or rate authority, the transport raises `HostedRetryAdmissionRefused` —
deliberately not the isolatable type, because exhausted authority is a fact about the whole campaign
and isolating it per case would let a run continue past the end of its authorized envelope, reported
as a formatting nuisance. It carries attempt 1's measurements so a call that genuinely happened is
never dropped from the logical execution, and retains the cap breach as `__cause__`. All four
pre-send blockers — pacing, credential resolution, reservation and lineage — preserve attempt-1
measurements through a single `refuse_before_send` helper.

**Settlement failures are typed.** `HostedSettlementBudgetExceeded` and
`HostedSettlementAccountingInvalid` split the funnel described above, so a governed ceiling and
accounting corruption can no longer be mistaken for one another by an operator or by a handler.

**Per-case fault isolation in the Runner.** An exhausted structured-output retry now persists a
contract-valid `ERROR` verdict with reason `judge_invalid_structured_output` against the
already-observed evidence and continues to the next case. No finding is opened and the Documentation
agent is never invoked, because `ERROR` is not a security signal. If the evidence content hash cannot
be recovered, the Runner fails closed. The isolation covers exactly one exception type:
`CampaignAbort`, `DispatchUnavailable`, credential, budget, route, identity, evidence-integrity,
lease-loss and unknown-outcome failures are unrelated types and still abort the run.

**Outcome counts are durable, not in-process.** Migration `0026` adds `decisive_verdict_count`,
`indeterminate_verdict_count` and `operational_error_count` to `campaign_run_summaries`, computed from
durable verdict rows inside the completion transaction so a restart cannot reset them, with a `CHECK`
that they can never exceed `attempt_count`. The write-only process counter is removed.

**Envelope changes.** The Red Team per-call timeout was raised 60 s -> 180 s in an earlier commit on
the strength of the 65.9 s measurement; token bounds are unchanged at 32768/8192/8192. Platform
ceilings were raised to admit one Judge retry per case: `HOSTED_MAX_PHYSICAL_CALLS` 56 -> 68 and
`HOSTED_MAX_GLOBAL_PHYSICAL_CALLS` 136 -> 170, with `HOSTED_MAX_MEASURED_USD` `$10` -> `$12`. The
global figure is arithmetic, not judgement: 34 cases x (orchestrator 1 + red_team 1 + judge 2 +
documentation 1) = 34 + 34 + 68 + 34 = 170. The old 136 was the same arithmetic with no retry anywhere
(34 x 4), and 68 is the Judge's own worst case within it.

**The configuration is derived, and cannot be applied by the fix.**
`scripts/derive_retry_configuration.py` computes the governed configuration and its worst case, and
deliberately cannot stage it: an append-only governed write requires a Clerk principal holding
`org:config:manage`, and inventing that authority in a script is the shortcut this platform exists to
catch. Worst case for `headshot-live-100-batch-01`: 170 physical calls, 4,177,920 input / 365,568
output / 417,792 reasoning tokens. The worst-case **spend** is deliberately not quoted here: prices
must come from a reviewed `HostedConfigurationSet`, and the derivation refuses without one. An
earlier draft quoted `$10.820813` from prices solved out of this incident's own measurements; that
was withdrawn, because an average conflates rate with usage mix and Documentation — which never
executed — had no measured rate at all and was being priced as the Judge.

**Proof.** `tests/test_campaign_fault_isolation_db.py` drives a real four-role hosted campaign against
migrated PostgreSQL using the real transport, store, lifecycle and Runner loop, faking only the
socket. It asserts that case 1 adjudicates, that case 2's Judge returns two schema-invalid responses
and receives a durable `ERROR` verdict with no finding and no Documentation execution, that case 3
still executes, that there is exactly one durable result per authored case, that the Judge's physical
sequences are exactly `[1, 2]` and both recorded `invalid_output`, that provider events reconcile
with requests made, and that the summary reports the operational error. The test is
mutation-verified: disabling the isolation makes it fail exactly as production did.

## Follow-ups

Open, and explicitly **not** addressed by the remediation above:

1. **Durable no-replay resume.** A terminal batch still cannot restart from its completed attempts.
   Until this exists, per-case isolation limits the damage of a formatting fault but not of any of the
   fatal classes.
2. **Complete Langfuse hierarchy and reconciliation.** Physical provider calls and target requests are
   not yet first-class child observations; the outbox and query-back reconciliation are incomplete;
   the verifier still refuses failed and aborted campaigns, which is precisely when a trace is most
   needed.
3. **HTTP/application-status migration.** `transport_outcome` must be separated from the HTTP status
   code. Today the status code never reaches `attempt_result` and never reaches the Judge as a typed
   field, which is why an `HTTP 422` from the target is labelled `succeeded`.
4. **Rebuild Judge calibration against the exact Chutes/Gemini identities.** Until this lands, every
   non-oracle verdict this platform produces is `INDETERMINATE` for the reason described above, and
   no run — successful or not — establishes anything about the target's behavior.
5. **Structured Runner logging and console surfacing.** The sanitized exception chain is a partial
   fix. An operator should not need database access to learn why a campaign ended.

## Deployment status

Staging still runs `456d6e5` with `max_retries = 0`. The remediation branch is unmerged and nothing
has been deployed, so **this incident is currently un-remediated in the deployed system**: a repeat
of the same malformed response today would dead-letter the batch in exactly the same way. Applying
the derived configuration additionally requires a Clerk principal holding `org:config:manage`, which
is a separate human action from merging the code.
