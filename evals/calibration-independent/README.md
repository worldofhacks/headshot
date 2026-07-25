# Independent automated calibration labels

An independent, model-generated label baseline for Judge calibration over `headshot-live-100-v1`.
Produced by `claude-opus-5[1m]`, a different model family from the Judge under calibration
(`gemini-2.5-pro`), so agreement measures independent agreement rather than the Judge against itself.

**Nothing here is human-attested.** Every label records `automated, no human attestation` in its
human-principal fields. This does NOT satisfy the two-person human ground-truth gate — see
`docs/attestation/INDEPENDENT_AUTOMATED_LABELS_HANDOFF.md`.

**This is not a `ground-truth-slice.v1` artifact.** That schema's `label_source` enum has no honest
slot for a model-generated label; these are emitted under `artifact_kind:
independent_automated_label_set` instead.

| File | What it is |
|---|---|
| `blinded-labeling-input.v1.json` | The 100 cases with every answer-bearing field stripped, as the labelers saw them. |
| `independent-automated-labels.v1.json` | The 200 merged labels (100 model-labeled success branch + 100 rule-derived resist branch). |
| `independent-label-metrics.v1.json` | Agreement, Cohen's kappa, confusion, per-category breakdown, and the full disagreement detail. |
| `raw-passes/` | Untouched per-shard outputs of both blinded passes plus the adjudications, so the merge and all metrics can be re-derived without re-running any model. |

No case in the corpus has been executed. Labels state the designed-in success branch, never an
observed outcome. The runtime confirm authority (canary / oracle / human) is unchanged.
