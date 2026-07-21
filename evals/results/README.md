# M11 result boundary

This directory intentionally contains no campaign-result JSON. The offline M11 slice has not
contacted a target, run a hosted model, or executed a campaign.

The repository keeps four concepts separate:

- `evals/seeds/` contains authored `AttackCase` expectations. Every seed currently has
  `execution_status: NOT_EXECUTED`, `observed_behavior: null`,
  `result_kind: pending_live_campaign`, and `result_ref: null`.
- A local deterministic fixture result would require an actual fixture execution and a typed result
  reference. None was generated in this slice.
- `evals/ground-truth/` contains authored calibration labels and constructed evidence examples. Its
  `campaign_run_id: ground-truth-unexecuted` and `live_campaign_result: null` values make clear that
  these are labels, not observations.
- A live campaign result remains pending explicit authorization and the M4/M5/M8/M9 runtime. It must
  be written from trusted recorder and Judge contracts; it must never be inferred from authored
  expectations.

Offline admission checks:

```sh
PYTHONPATH=src python -m agentforge.evals validate-corpus evals
PYTHONPATH=src python -m agentforge.evals detect-duplicate-sequence evals/seeds
```
