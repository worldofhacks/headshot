# Cost-input evidence — 2026-07-24

## Evidence boundary

This file records read-only billing and usage inputs available before the final authorized
100-case campaign. It separates attributable Headshot amounts from shared-account totals and does
not treat budgets, credits, fixture values, or another project’s usage as spend.

## Railway

Railway CLI billing-period query for July 2026, captured on 2026-07-24:

| Scope | Resource usage cost (USD) | Attribution |
|---|---:|---|
| Headshot project | 0.816820 | Directly attributable |
| Deployed target project | 21.763890 | Excluded from Headshot |
| Workspace total | 22.580831 | Shared total; not copied into Headshot |

Workspace meter totals were CPU `$1.014025`, memory `$21.089065`, network egress `$0.072521`,
volume storage `$0.380350`, and backup storage `$0.024869`. Railway’s project breakdown exposes
the Headshot total but not a per-meter allocation for that project, so those workspace meter
amounts must not be presented as Headshot’s component breakdown.

The figures above are resource-usage charges, not a tax-inclusive invoice or labor allocation.
Railway documents that subscription minimums count toward resource usage rather than being added
again to the same consumption: <https://docs.railway.com/pricing>.

## Model providers

The configured OpenRouter key reported `$0.00` usage before the final run. The account-wide usage
endpoint reported historical usage from other activity, but the API did not attribute it to
Headshot; it is therefore excluded. Final provider cost must come from the persisted physical
request lineage, provider-reported per-call cost, and the post-run key/account export.

No Anthropic-direct, Google-direct, OpenAI-direct, or Together-direct key is configured on the
Railway Runner. The selected hosted roles route through OpenRouter, so direct-provider price lists
are rate-reference inputs, not separate charges.

## Langfuse Cloud

The authenticated Langfuse Cloud query found zero staging observations before deployment and no
Headshot-marked production observations. Existing production observations belong to the separately
deployed target and are excluded. The Cloud plan/invoice amount is not exposed by the Public API;
it requires the account billing record.

Langfuse defines a billable unit as one trace, observation, or score:
<https://langfuse.com/docs/administration/billable-units>. Published Cloud tiers and included units
are documented at <https://langfuse.com/pricing>.

## CI and security tools

The repository is public and uses standard GitHub-hosted runners. GitHub documents those Actions
minutes as non-billable: <https://docs.github.com/en/billing/concepts/product-billing/github-actions>.

The checked-in security workflow uses open-source command-line editions of Gitleaks, Semgrep,
pip-audit, Promptfoo/native LLM-security tools, and OWASP ZAP. No paid scanner license or external
security-tool invoice was found. Their direct software charge is therefore `$0.00`; their observed
CI compute charge is also `$0.00` under the public-repository runner policy. Labor is a separate
development-spend input and must not be silently valued at zero.

## Inputs still supplied only by final acceptance or the account owner

- provider-reported cost, tokens, retries, and failed physical calls for the final campaign;
- Langfuse Cloud plan and billed amount;
- the chosen definition of development spend and any labor/hardware rates;
- final database, trace, artifact, and egress growth for the 100-case campaign.
