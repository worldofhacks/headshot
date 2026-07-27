#!/usr/bin/env python3
"""Merge batched calibration sub-runs into one bundle, or refuse.

A corpus larger than ``HOSTED_MAX_PHYSICAL_CALLS`` (56) cannot be captured in one run, and raising
the cap is not the way out: ``limits`` sits inside the Judge role's ``configuration_sha256`` and
therefore inside ``judge_model_version``, so a wider cap attests a *different* evaluator. The
corpus is instead captured as several sub-runs against one unchanged staged configuration, and
merged here.

Aggregation is only meaningful if every batch measured the same thing, so this refuses unless:

* every batch carries a **byte-identical** ``judge_identity``, and identical
  ``configuration_sha256`` / ``role_configuration_sha256`` / ``generation_policy_sha256`` /
  ``requested_model`` / ``returned_model``;
* no label appears in two batches; and
* the union of the batches covers the ground-truth corpus **exactly** — no gaps, no extras.

The last check is the one that matters most: a merge that silently dropped a batch would produce a
smaller, easier corpus and a better-looking agreement rate. Coverage is verified against the slice
directory, not against the batch manifests, so a batch that was never run cannot hide.

Output is a bundle in exactly the shape ``load_captured_calibration_evaluator`` validates, plus a
batch manifest recording which labels came from which sub-run and what each cost.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from decimal import Decimal
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_GROUND_TRUTH = _ROOT / "evals" / "ground-truth"

_PINNED_PROVENANCE = (
    "capture_kind",
    "configuration_sha256",
    "role_configuration_sha256",
    "generation_policy_sha256",
    "requested_model",
    "returned_model",
)


class MergeRefused(RuntimeError):
    """The sub-runs cannot be aggregated into one measurement."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "batch_dir",
        type=Path,
        nargs="+",
        help="one capture output directory per sub-run (order does not matter)",
    )
    parser.add_argument(
        "--slice-dir",
        type=Path,
        default=_GROUND_TRUTH,
        help="ground-truth slice directory the batches must cover exactly",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="where to write the merged captured-results.json, judge-identity.json and manifest",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        bundle, manifest = merge(args.batch_dir, slice_dir=args.slice_dir)
    except MergeRefused as exc:
        raise SystemExit(f"refusing to merge: {exc}") from exc

    args.output_dir.mkdir(parents=True, exist_ok=True)
    _write(args.output_dir / "captured-results.json", bundle)
    _write(args.output_dir / "judge-identity.json", bundle["judge_identity"])
    _write(args.output_dir / "batch-manifest.json", manifest)
    langfuse_attestation = _merge_langfuse_attestations(
        args.batch_dir,
        judge_identity=bundle["judge_identity"],
        sample_count=manifest["sample_count"],
    )
    if langfuse_attestation is not None:
        _write(args.output_dir / "langfuse-attestation.json", langfuse_attestation)

    print(f"merged {manifest['batch_count']} batches -> {manifest['sample_count']} samples")
    print(f"  identity   {bundle['judge_identity']['judge_model_version']}")
    print(f"  measured   ${manifest['measured_usd_total']}")
    for batch in manifest["batches"]:
        print(
            f"  batch {batch['batch_index']}: {batch['sample_count']:>3} samples  "
            f"${batch['measured_usd']}  from {batch['source']}"
        )
    return 0


def merge(
    batch_dirs: Sequence[Path],
    *,
    slice_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not batch_dirs:
        raise MergeRefused("no batch directories were supplied")

    loaded = [_load_batch(directory) for directory in batch_dirs]
    reference = loaded[0]
    for batch in loaded[1:]:
        if batch["bundle"]["judge_identity"] != reference["bundle"]["judge_identity"]:
            raise MergeRefused(
                f"{batch['source']} measured a different Judge identity than {reference['source']}"
                " — batches of one campaign must share one staged configuration, and a differing "
                "identity means they cannot be aggregated at all"
            )
        for field in _PINNED_PROVENANCE:
            if batch["bundle"]["provenance"][field] != reference["bundle"]["provenance"][field]:
                raise MergeRefused(
                    f"{batch['source']} disagrees with {reference['source']} on provenance.{field}"
                )

    seen: dict[str, str] = {}
    samples: list[dict[str, Any]] = []
    for batch in loaded:
        for sample in batch["bundle"]["samples"]:
            label_id = sample["label_id"]
            if label_id in seen:
                raise MergeRefused(
                    f"label {label_id} appears in both {seen[label_id]} and {batch['source']}; "
                    "batches must be disjoint or the label is scored twice"
                )
            seen[label_id] = batch["source"]
            samples.append(sample)

    expected = _corpus_label_ids(slice_dir)
    missing = sorted(expected - set(seen))
    extra = sorted(set(seen) - expected)
    if missing:
        raise MergeRefused(
            f"{len(missing)} ground-truth labels are covered by no batch (first: {missing[0]}). "
            "Merging an incomplete campaign would measure a smaller, easier corpus than the one "
            "being attested — capture the missing batches"
        )
    if extra:
        raise MergeRefused(
            f"{len(extra)} captured labels are not in the ground-truth corpus (first: {extra[0]})"
        )

    indices = sorted(batch["batch_index"] for batch in loaded)
    if indices != list(range(len(loaded))):
        raise MergeRefused(
            f"batch indices {indices} are not a complete 0..{len(loaded) - 1} sequence"
        )

    samples.sort(key=lambda item: item["label_id"])
    bundle = {
        "schema_version": "1",
        "judge_identity": reference["bundle"]["judge_identity"],
        "provenance": {
            **{field: reference["bundle"]["provenance"][field] for field in _PINNED_PROVENANCE},
            # The campaign is only complete once its last sub-run is.
            "captured_at": max(batch["bundle"]["provenance"]["captured_at"] for batch in loaded),
        },
        "samples": samples,
    }

    total = sum((batch["measured_usd"] for batch in loaded), Decimal("0"))
    manifest = {
        "schema_version": "1",
        "batch_count": len(loaded),
        "sample_count": len(samples),
        "measured_usd_total": format(total, "f"),
        "identity_sha256_source": "captured-results.json judge_identity, identical across batches",
        "judge_identity": reference["bundle"]["judge_identity"],
        "label_to_batch": {label_id: source for label_id, source in sorted(seen.items())},
        "batches": [
            {
                "batch_index": batch["batch_index"],
                "source": batch["source"],
                "capture_run_id": batch["capture_run_id"],
                "sample_count": len(batch["bundle"]["samples"]),
                "measured_usd": format(batch["measured_usd"], "f"),
                "label_ids": sorted(item["label_id"] for item in batch["bundle"]["samples"]),
            }
            for batch in sorted(loaded, key=lambda item: item["batch_index"])
        ],
    }
    return bundle, manifest


def _merge_langfuse_attestations(
    batch_dirs: Sequence[Path],
    *,
    judge_identity: Mapping[str, Any],
    sample_count: int,
) -> dict[str, Any] | None:
    paths = [directory / "langfuse-attestation.json" for directory in batch_dirs]
    present = [path.exists() for path in paths]
    if not any(present):
        return None
    if not all(present):
        raise MergeRefused("Langfuse query-back exists for only part of the calibration batches")
    attestations = [_read_json(path) for path in paths]
    provider_request_ids: list[str] = []
    for directory, attestation in zip(batch_dirs, attestations, strict=True):
        if (
            not isinstance(attestation, Mapping)
            or attestation.get("attestation_kind") != "langfuse_query_back_verified"
            or attestation.get("judge_identity") != dict(judge_identity)
        ):
            raise MergeRefused("a batch carries an invalid or identity-drifted Langfuse attestation")
        bundle = _read_json(directory / "captured-results.json")
        samples = bundle.get("samples") if isinstance(bundle, Mapping) else None
        if not isinstance(samples, list):
            raise MergeRefused("a Langfuse-attested batch carries no captured samples")
        batch_request_ids = [str(sample.get("provider_request_id") or "") for sample in samples]
        expected_digest = hashlib.sha256(
            "\n".join(sorted(batch_request_ids)).encode()
        ).hexdigest()
        if (
            len(set(batch_request_ids)) != len(batch_request_ids)
            or attestation.get("provider_request_ids_sha256") != expected_digest
            or attestation.get("matched_generation_count") != len(batch_request_ids)
        ):
            raise MergeRefused(
                "a batch Langfuse attestation differs from its exact provider request id set"
            )
        provider_request_ids.extend(batch_request_ids)
    matched = sum(int(item.get("matched_generation_count") or 0) for item in attestations)
    if matched != sample_count:
        raise MergeRefused(
            f"Langfuse query-back covers {matched} generations but the bundle has {sample_count}"
        )
    if len(set(provider_request_ids)) != sample_count:
        raise MergeRefused("Langfuse-attested provider request ids are not globally unique")
    return {
        "schema_version": "1",
        "attestation_kind": "langfuse_query_back_verified",
        "judge_identity": dict(judge_identity),
        "matched_generation_count": matched,
        "provider_request_ids_sha256": hashlib.sha256(
            "\n".join(sorted(provider_request_ids)).encode()
        ).hexdigest(),
        "batch_count": len(attestations),
        "batches": [
            {
                "capture_run_id": item["capture_run_id"],
                "trace_id": item["trace_id"],
                "matched_generation_count": item["matched_generation_count"],
                "provider_request_ids_sha256": item["provider_request_ids_sha256"],
                "verified_at": item["verified_at"],
            }
            for item in attestations
        ],
        "verified_at": max(str(item["verified_at"]) for item in attestations),
        "disclosure": (
            "Every calibration generation was remotely queryable in Langfuse. This verifies the "
            "tracing projection, not an independent OpenRouter usage export."
        ),
    }


def _load_batch(directory: Path) -> dict[str, Any]:
    bundle = _read_json(directory / "captured-results.json")
    manifest = _read_json(directory / "capture-manifest.json")
    if not isinstance(bundle, Mapping) or "samples" not in bundle:
        raise MergeRefused(f"{directory} does not contain a capture bundle")
    if not isinstance(manifest, Mapping):
        raise MergeRefused(f"{directory} does not contain a capture manifest")
    batch = manifest.get("batch")
    if not isinstance(batch, Mapping) or not isinstance(batch.get("batch_index"), int):
        raise MergeRefused(
            f"{directory} carries no batch record — it was captured before batching existed, so "
            "its place in the campaign cannot be established"
        )
    try:
        measured = Decimal(str(manifest["ledger"]["measured_usd"]))
    except (KeyError, TypeError, ArithmeticError) as exc:
        raise MergeRefused(f"{directory} has no usable ledger total") from exc
    return {
        "source": str(directory),
        "bundle": bundle,
        "batch_index": batch["batch_index"],
        "capture_run_id": manifest.get("capture_run_id"),
        "measured_usd": measured,
    }


def _corpus_label_ids(slice_dir: Path) -> set[str]:
    candidates = sorted(slice_dir.glob("*.json"))
    if not candidates:
        raise MergeRefused(f"no ground-truth slices under {slice_dir}")
    labels: set[str] = set()
    for candidate in candidates:
        payload = _read_json(candidate)
        if isinstance(payload, Mapping) and isinstance(payload.get("labels"), list):
            labels.update(label["label_id"] for label in payload["labels"])
    if not labels:
        raise MergeRefused(f"ground-truth slices under {slice_dir} contain no labels")
    return labels


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise MergeRefused(f"{path} is unreadable or not valid JSON") from exc


def _write(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
