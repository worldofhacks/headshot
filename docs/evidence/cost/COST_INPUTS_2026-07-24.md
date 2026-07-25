# Cost-input evidence — 2026-07-24

## Evidence boundary

This file records read-only billing and usage inputs available before the final authorized
100-case campaign. It separates attributable Headshot amounts from shared-account totals and does
not treat budgets, credits, fixture values, or another project’s usage as spend. No credential,
key identifier, session reference, or raw provider response is retained.

## Railway

Railway CLI billing-period query for July 2026, captured on 2026-07-24:

| Scope | Resource usage cost (USD) | Attribution |
|---|---:|---|
| Headshot project | 0.8168202853840123 | Directly attributable |
| Deployed target project | 21.7638898181247 | Excluded from Headshot |
| Workspace total | 22.580830863686177 | Shared total; not copied into Headshot |

Workspace meter totals were CPU `$1.014025`, memory `$21.089065`, network egress `$0.072521`,
volume storage `$0.380350`, and backup storage `$0.024869`. Railway’s project breakdown exposes
the Headshot total but not a per-meter allocation for that project, so those workspace meter
amounts must not be presented as Headshot’s component breakdown.

The raw CLI values are retained above rather than rounding away reconciliation precision. The
figures are resource-usage charges, not a tax-inclusive invoice or labor allocation. Railway
documents that subscription minimums count toward resource usage rather than being added again to
the same consumption: <https://docs.railway.com/pricing>.

## Model providers

The configured OpenRouter key reported `$0.00` usage at the pre-run baseline and `$0.98812000` at
the later read-only check. No credential or key identifier was retained.

The security owner's measured Judge-calibration bundle at commit
`8ce852be79212d184d49c9f84c593c9495629332` reconciles `$0.75823375` of that amount:

| Calibration meter | Measured value |
|---|---:|
| Logical/physical calls | 54 / 54 |
| Successful/failed calls | 54 / 0 |
| Retries | 0 |
| Input tokens | 54,707 |
| Visible output tokens | 9,675 |
| Reasoning tokens | 59,310 |
| Provider-reported cost | $0.75823375 |
| Unresolved exposure in the capture ledger | $0.00 |

Per-call provider cost was minimum `$0.007135`, p10 `$0.008995`, median `$0.0136175`, mean
`$0.0140413657407`, p90 `$0.0193475`, p95 `$0.01980125`, and maximum `$0.02519`.
The arithmetic difference between key usage and the calibration is `$0.22988625`. It has no durable
workload-level reconciliation and remains **unattributed** until the account owner confirms that the
key was dedicated to Headshot for the entire interval or supplies its lineage. It is not silently
excluded as zero and is not included in the attributable subtotal.

The calibration's requested and returned model was `google/gemini-2.5-pro`, but its recorded route
identity and Red-Team identity differ from the release candidate's exact routes. The measurement is
valid development-spend evidence and a low-confidence Judge sensitivity proxy; it is not evidence
of the current deployed route or the missing 100-case campaign.

The attributable provider amount is currently `$0.75823375`. If the owner confirms dedicated-key
attribution, it becomes `$0.98812000`. Final campaign provider cost must come from persisted physical
request lineage, provider-reported per-call cost, and the post-run key/account export.

No Anthropic-direct, Google-direct, OpenAI-direct, or Together-direct key is configured on the
Railway Runner. The selected hosted roles route through OpenRouter, so direct-provider price lists
are rate-reference inputs, not separate charges.

The retained
[public-catalog preflight](../provider/OPENROUTER_CATALOG_PREFLIGHT_2026-07-24.md) passed for the
four exact endpoint tags on 2026-07-24. It is a credential-free, read-only rate and capability
snapshot, not an inference call, deployment assertion, campaign authorization, provider invoice,
or substitute for provider-returned route identity. Its observed exact-route prices support a
dated token-bound sensitivity only; final campaign cost still requires persisted physical-attempt
usage and billing reconciliation. Applying the artifact's configured price ceilings to the current
generation-policy bounds reserves `$1.16736`, `$0.34816`, `$3.024`, and `$0.98304` for one
Orchestrator, Red Team, Judge, and Documentation attempt respectively. Reserving 100 attempts of
every role totals `$552.256`, far above the current `$10` global kill switch. This is a capacity
finding, not predicted or incurred spend.

## Langfuse Cloud

The authenticated Langfuse Cloud query found zero staging observations before deployment and no
Headshot-marked production observations. Existing production observations belong to the separately
deployed target and are excluded. The Cloud plan/invoice amount is not exposed by the Public API;
it requires the account billing record.

Langfuse defines a billable unit as one trace, observation, or score:
<https://langfuse.com/docs/administration/billable-units>. Published Cloud tiers and included units
are documented at <https://langfuse.com/pricing>.

The July 2026 public pricing snapshot records Hobby at `$0` with 50,000 included units and Core at
`$29/month` with 100,000 included units plus `$8/100,000` additional units. Those figures support
plan sensitivity only. The repository's architectural choice names Hobby, but the actual account
plan and invoice are unavailable. A workload that exceeds the Hobby allowance is blocked on Hobby;
it must not be priced as a zero-dollar overage. Any linear proration of the published Core
additional-unit rate is a sensitivity assumption, not an invoice claim.

## CI and security tools

The repository is public and uses standard GitHub-hosted runners. GitHub documents those Actions
minutes as non-billable: <https://docs.github.com/en/billing/concepts/product-billing/github-actions>.

The checked-in security workflow uses open-source command-line editions of Gitleaks, Semgrep,
pip-audit, Promptfoo/native LLM-security tools, and OWASP ZAP. No paid scanner license or external
security-tool invoice was found. Their direct software charge is therefore `$0.00`; their observed
CI compute charge is also `$0.00` under the public-repository runner policy. Labor is a separate
development-spend input and must not be silently valued at zero.

## Platform, storage, egress, and operations

The staging database baseline before the final release deployment is 11,425,471 bytes on migration
`0013`. It is a delta origin, not a bytes-per-case measurement. Pre-run Railway CPU/memory values
are idle or point-in-time observations, not utilization distributions or capacity evidence.

The Railway workspace exposes aggregate CPU, memory, egress, volume, and backup meter totals but
does not allocate those meters to Headshot. Therefore:

- the Headshot project total can be recorded as actual spend;
- workspace meter lines cannot be copied into Headshot projections;
- database, backup, artifact, observability, and egress unit growth remains unavailable until the
  final before/after measurement; and
- target-project resource usage remains excluded from the adversarial platform.

No approved labor hours/rates, local hardware amortization, power measurement, operations/on-call
allocation, or completion-window capacity plan was supplied. These are unavailable inputs, not
zero-dollar lines. A configurable target per-request cost is a budget estimate and is not treated
as a provider invoice.

## Reconciled subtotal

| Included item | USD |
|---|---:|
| Headshot Railway usage | 0.8168202853840123 |
| Reconciled Judge calibration | 0.75823375 |
| Direct security-tool licenses and eligible public CI | 0.00 |
| **Confirmed attributable subtotal** | **1.5750540353840123** |

If the configured key is confirmed Headshot-dedicated, the reconciled provider line becomes
`$0.98812000` and the known subtotal becomes `$1.8049402853840123`. Neither subtotal includes the
unavailable Langfuse invoice, development AI subscriptions outside the key, labor, or local
hardware/power allocation.

## Inputs still supplied only by final acceptance, the security owner, or the account owner

- the security owner's final frozen 100-case whole-case bundle: per-role calls, tokens, retries,
  failures, findings, latency, provider cost, database/artifact growth, Langfuse units, and egress;
- Langfuse Cloud plan and actual billed amount, including credits, overage, tax, and billing window;
- confirmation of dedicated-key attribution and the `$0.22988625` difference;
- actual development AI-tool/API/subscription spend outside the configured key;
- the chosen labor/hardware/power accounting policy and exact amounts, including an explicit zero
  when a family is intentionally excluded;
- the final Railway invoice if credits, subscription allocation, or tax differ from resource usage;
  and
- a retained redacted exact-endpoint price snapshot plus post-run provider/PostgreSQL/Langfuse
  reconciliation.
