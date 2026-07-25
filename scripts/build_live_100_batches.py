#!/usr/bin/env python3
"""Deterministically emit the 3 batch sub-corpus manifests for the frozen live-100 workload.

WHY
---
``HOSTED_MAX_PHYSICAL_CALLS`` is 56 and the runner does NOT chunk a campaign: it passes the whole
corpus size as one ``case_count`` to ``_require_hosted_workload_capacity``, which fails closed when
``required`` exceeds a hosted role's ``max_calls`` (<= 56). A single 100-case / 121-physical hosted
invocation therefore cannot run. The authorized answer (``evals/workloads/live-100-batches.json``) is
to submit the SAME frozen corpus as 3 separately-authorized sub-workloads that aggregate EXACTLY to
the 100-case / 121-physical whole — no cap raise (each batch physical <= 56) and authored/reviewed
content ONLY.

WHAT THIS EMITS
---------------
For each batch this writes ``evals/workloads/headshot-live-100-batch-0N.json`` whose key set is
EXACTLY ``{schema_version, workload_id, cases}`` and whose ``cases`` are the SAME reviewed per-case
entries (same ``case_path`` / ``case_sha256`` / ``review`` sidecar provenance) copied verbatim from
the frozen ``headshot-live-100-v1`` manifest — never re-authored, never mutated. The batch case order
follows the authored plan's ``case_ids`` order.

This generator is a byte-for-byte reproducer: rerunning it over the same inputs yields identical
files (canonical JSON: sorted keys, no ASCII escaping, trailing newline). It also records each batch
manifest's sha256 so ``corpus.py`` can pin it, and asserts each batch aggregates back to the frozen
whole (exact partition, physical <= 56, 121 total) before writing anything.

NO NETWORK / NO TARGET / NO HOSTED CALL — reads local authored JSON only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

EVAL_ROOT = Path(__file__).resolve().parents[1] / "evals"
WORKLOADS = EVAL_ROOT / "workloads"
PLAN_PATH = WORKLOADS / "live-100-batches.json"
FROZEN_MANIFEST_PATH = WORKLOADS / "headshot-live-100-v1.json"

FROZEN_WORKLOAD_ID = "headshot-live-100-v1"
HOSTED_MAX_PHYSICAL_CALLS = 56
FROZEN_CASE_COUNT = 100
FROZEN_PHYSICAL = 121


def _canonical_bytes(obj: object) -> bytes:
    return json.dumps(
        obj, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _pretty_bytes(obj: object) -> bytes:
    """Deterministic, human-diffable on-disk form (sorted keys, trailing newline)."""
    return (
        json.dumps(obj, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def build() -> list[dict[str, object]]:
    plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
    frozen = json.loads(FROZEN_MANIFEST_PATH.read_text(encoding="utf-8"))

    if frozen.get("workload_id") != FROZEN_WORKLOAD_ID:
        raise SystemExit("frozen manifest identity is not headshot-live-100-v1")
    entry_by_instance = {entry["instance_id"]: entry for entry in frozen["cases"]}
    if len(entry_by_instance) != FROZEN_CASE_COUNT:
        raise SystemExit("frozen manifest does not carry exactly 100 unique instance ids")

    # Exact-partition guard BEFORE writing anything: union == frozen 100, no overlap, no omission.
    seen: set[str] = set()
    plan_total_cases = 0
    for batch in plan["batches"]:
        for instance_id in batch["case_ids"]:
            if instance_id not in entry_by_instance:
                raise SystemExit(f"batch case {instance_id} is not in the frozen corpus")
            if instance_id in seen:
                raise SystemExit(f"batch case {instance_id} appears in more than one batch")
            seen.add(instance_id)
        plan_total_cases += len(batch["case_ids"])
    if seen != set(entry_by_instance):
        raise SystemExit("the batches do not partition the frozen 100 exactly")
    if plan_total_cases != FROZEN_CASE_COUNT:
        raise SystemExit("the batches do not aggregate to exactly 100 cases")

    results: list[dict[str, object]] = []
    aggregate_physical = 0
    for index, batch in enumerate(plan["batches"], start=1):
        workload_id = f"headshot-{batch['batch_id']}"
        # Reuse the frozen per-case entries verbatim in the plan's declared order — no re-authoring.
        cases = [json.loads(_canonical_bytes(entry_by_instance[cid])) for cid in batch["case_ids"]]

        physical = 0
        for cid in batch["case_ids"]:
            case_payload = json.loads(
                (EVAL_ROOT / entry_by_instance[cid]["case_path"]).read_text(encoding="utf-8")
            )
            physical += len(case_payload["input_sequence"])
        if physical != batch["physical"]:
            raise SystemExit(f"{workload_id} physical {physical} != plan {batch['physical']}")
        if physical > HOSTED_MAX_PHYSICAL_CALLS:
            raise SystemExit(f"{workload_id} physical {physical} exceeds the 56 cap")
        if len(cases) != batch["case_count"]:
            raise SystemExit(f"{workload_id} case count {len(cases)} != plan {batch['case_count']}")

        manifest = {"schema_version": "1", "workload_id": workload_id, "cases": cases}
        if set(manifest) != {"schema_version", "workload_id", "cases"}:
            raise SystemExit(f"{workload_id} manifest key set is not exactly the required three")

        out_path = WORKLOADS / f"headshot-live-100-batch-0{index}.json"
        raw = _pretty_bytes(manifest)
        out_path.write_bytes(raw)
        manifest_sha256 = hashlib.sha256(raw).hexdigest()

        aggregate_physical += physical
        results.append(
            {
                "workload_id": workload_id,
                "path": str(out_path.relative_to(EVAL_ROOT.parent)),
                "case_count": len(cases),
                "physical": physical,
                "manifest_sha256": manifest_sha256,
            }
        )

    if aggregate_physical != FROZEN_PHYSICAL:
        raise SystemExit(f"batches aggregate to {aggregate_physical} physical, expected 121")
    return results


def main() -> None:
    results = build()
    for record in results:
        print(
            f"{record['workload_id']}  cases={record['case_count']}  "
            f"physical={record['physical']}  sha256={record['manifest_sha256']}"
        )


if __name__ == "__main__":
    main()
