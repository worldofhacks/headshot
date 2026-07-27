# Hosted role routing and Red Team resolution

**Reconciled:** 2026-07-26

**Current deployment evidence:** [`../CURRENT_STATE.md`](../CURRENT_STATE.md)

This document replaces the 2026-07-24 public-model-list check. A public model listing proves only that
an identifier existed at one moment; it does not prove the exact authorized upstream route, current
availability, price, or returned identity.

## Binding role set

| Role | Requested model | Required upstream |
|---|---|---|
| Orchestrator | `anthropic/claude-opus-4.8` | `anthropic` |
| Red Team | `qwen/qwen3.5-397b-a17b` | staged as `chutes` |
| Judge | `google/gemini-2.5-pro` | `google-vertex` |
| Documentation | `openai/gpt-5.4` | `openai` |

The role model, upstream, prompt hash, generation-policy hash, configuration digest, price bounds, and
per-call/campaign caps are authorization-bound. Fallback and substitution are disabled. There is no
documented “nearest substitute”; changing a role requires a reviewed append-only configuration,
capacity/preflight validation, updated calibration where applicable, and fresh campaign authorization.

## Red Team behavior

The current live Red Team call does not generate arbitrary target bytes. It returns a schema-valid
`case_ref` from the exact reviewed candidates supplied for the next authorized work unit. The Runner
creates the durable attempt before the provider call, and dispatch still uses the immutable authored
case. This keeps hosted Red Team participation and provider evidence without permitting unreviewed
text to cross the Policy Gateway.

Novel generation/mutation tooling is a different authorization domain:

```text
hosted candidate generation
  -> quarantine
  -> human review
  -> immutable provenance/workload
  -> fresh exact authorization
  -> live selection and dispatch
```

No generation output can directly become a live target request.

## Runtime acceptance

Before a live campaign, prove all of the following for the exact staged configuration:

1. Web, Runner, and Scheduler share the same packaged generation policy.
2. Every requested model/upstream route resolves without fallback.
3. The returned model and upstream exactly match the requested identity.
4. Input/output/reasoning limits, timeout, rate, physical-call, retry, token, and spend capacity cover
   the authorized workload.
5. Prompt and policy digests match the authorization.
6. Provider credentials are Runner-only and ready.
7. The exact current Judge identity has an enabled, human-approved calibration artifact—or the UI and
   evidence explicitly label its model output advisory/indeterminate.

External availability and price can change at any time. Re-run preflight immediately before launch;
do not refresh this file by guessing from a provider marketing page.
