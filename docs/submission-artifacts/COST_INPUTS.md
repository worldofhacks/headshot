# Cost and invoice input ledger

Status: **pending measured inputs**.

[`../cost/COST_ANALYSIS.md`](../cost/COST_ANALYSIS.md) defines the nonlinear accounting method. This
ledger prevents reservation ceilings and test values from being reported as actual spend.

| Input | Required retained source | Current status |
|---|---|---|
| Development model/API usage | Provider usage export covering the development window | `pending` |
| Final campaign model usage | Per-role provider records reconciled to durable request IDs | `pending` |
| Provider invoice | Redacted invoice/export with date, currency, and covered account | `pending` |
| Railway compute/storage/egress | Environment-specific usage or invoice export | `pending` |
| Langfuse usage | Project-specific usage export for the release window | `pending` |
| CI/development infrastructure | Dated usage/invoice records if included in reported cost | `pending` |
| Currency conversion | Dated source when an invoice is not in the reporting currency | `pending if needed` |
| Final arithmetic workbook/report | Reproducible calculation linked to all source hashes | `pending` |

Do not report any of the following as spend:

- the `$50` campaign hard cap or any per-configuration cost ceiling;
- list prices multiplied by assumed tokens or case counts;
- fixture, cassette, mock, or unit-test accounting values;
- a missing provider cost field displayed as `$0`;
- local CPU time without an approved allocation method; or
- a prose-only historical claim whose billing/request manifest is not retained.

The final report must separate actual development spend, actual final-run spend, and future
100/1K/10K/100K projections. Unknown values remain `TBD`; they are not zero.
