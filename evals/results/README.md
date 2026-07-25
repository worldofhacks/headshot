# M11 result boundary

> **Corrected 2026-07-25 (base `107c11c`).** This file previously read "This directory intentionally
> contains no campaign-result JSON." **That is no longer true and had become self-falsifying.** Four
> result groups now sit beside this README:
>
> | Directory | What it is |
> |---|---|
> | `live-campaign-20260724/` | First exploratory adversarial scan (superseded — inline SID, 30 s timeout causing false timeouts) |
> | `live-campaign-20260724-week1/` | **Authoritative** adversarial scan: 17 probes, 17 responded |
> | `platform-live-run-20260724/` | Coordinator run; **5 attempt manifests** tracked (see the correction in its `COMBINED_SUMMARY.md`) |
> | `bruno-20260724/` | External Bruno functional/regression suites: 15 request/response pairs, 40/40 tests pass |
>
> Every adversarial verdict across all of it is `INDETERMINATE` at confidence `0.0` — 39 verdict
> records, **0 `EXPLOIT_CONFIRMED`, 0 oracle hits, 0 canary hits**, and no recorded cost. 22 of the 39
> carry the reason code `non_oracle_uncalibrated_indeterminate`; the 17 records in the superseded first
> scan (`live-campaign-20260724/verdicts.jsonl`) carry only `{attempt_id, state, confidence}` and no
> reason code at all. **No hosted model was called in any of these runs**,
> and **none went through the platform's production authorization path**: all four legacy launchers now
> fail closed, so every artifact here was produced by a script that can no longer execute. Read them as
> evidence about the target, never as evidence that the governed loop has executed. Context:
> [`docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md`](../../docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md)
> RT-01.

The boundary this file exists to defend is still real, and still worth stating: an authored
expectation is not an observation. The repository keeps four concepts separate:

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
