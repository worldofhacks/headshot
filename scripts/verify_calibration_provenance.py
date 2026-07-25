#!/usr/bin/env python3
"""Cross-check a capture bundle against the provider's own usage export.

``scripts/run_judge_calibration.py --captured-results`` replays an operator-supplied JSON file, and
``calibration_results.py`` validates its SHAPE only — no request-id format check, no cost
re-derivation, no network.  A hand-written bundle naming a nonexistent model, with zero tokens and
zero cost and no API key set, yields a contract-valid ``state: passed`` artifact with agreement
1.0 under the strict policy.  Nothing inside the repository can tell that apart from a real run.

The only thing that can is the provider's own record.  This tool takes an OpenRouter usage /
activity export covering the capture window and checks, per sample:

* the ``provider_request_id`` appears in the export (this is the load-bearing check — a fabricated
  id has nothing to match);
* the export's model for that generation equals the sample's ``returned_model``;
* the export's cost equals the sample's ``measured_cost_usd``;
* token counts agree where the export carries them;

and across the bundle: every exported generation in scope is accounted for, and the summed cost
equals the ledger total.  It writes a provenance attestation that ``enable_model_judge.py``
requires, so a bundle that is merely shape-valid cannot license runtime authority.

EXPORT FORMAT.  CSV or JSON, one row per generation.  Column names are matched case-insensitively
against the aliases in ``_FIELD_ALIASES``; if a required column cannot be resolved the tool prints
the headers it actually saw and refuses, rather than guessing and silently "verifying" nothing.
A normalized JSON form is always accepted:

    [{"id": "gen-...", "model": "google/gemini-2.5-pro", "cost": "0.0174575",
      "tokens_prompt": 1030, "tokens_completion": 1617}]

``tokens_completion`` is compared against ``output_tokens + reasoning_tokens``, because OpenRouter
reports reasoning inside completion tokens while the bundle splits them.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

_FIELD_ALIASES: Mapping[str, tuple[str, ...]] = {
    "id": ("id", "generation_id", "gen_id", "request_id", "provider_request_id"),
    "model": ("model", "model_permaslug", "model_id"),
    "cost": ("cost", "total_cost", "usage", "amount", "cost_usd"),
    "tokens_prompt": ("tokens_prompt", "prompt_tokens", "native_tokens_prompt", "input_tokens"),
    "tokens_completion": (
        "tokens_completion",
        "completion_tokens",
        "native_tokens_completion",
        "output_tokens",
    ),
}
_REQUIRED = ("id", "model", "cost")
#: Providers report cost in USD with more precision than we need to compare; allow a hundredth of
#: a cent of drift so a rounding difference in the export is not read as a mismatch.
_COST_TOLERANCE = Decimal("0.0001")


class ProvenanceRefused(RuntimeError):
    """The bundle could not be reconciled against the provider's record."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--captured-results",
        type=Path,
        required=True,
        help="the capture bundle (merged, if the campaign was batched)",
    )
    parser.add_argument(
        "--usage-export",
        type=Path,
        required=True,
        help="OpenRouter usage/activity export (CSV or JSON) covering the capture window",
    )
    parser.add_argument(
        "--ledger-total-usd",
        help="optional expected measured total, e.g. from the merged batch manifest",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="where to write the provenance attestation enable_model_judge.py requires",
    )
    parser.add_argument(
        "--allow-extra-generations",
        action="store_true",
        help=(
            "tolerate exported generations the bundle does not claim (use when the export covers "
            "a wider window than the capture; the reverse is never tolerated)"
        ),
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        attestation = verify(
            _read_json(args.captured_results),
            _load_export(args.usage_export),
            ledger_total_usd=args.ledger_total_usd,
            allow_extra_generations=args.allow_extra_generations,
            export_path=str(args.usage_export),
        )
    except ProvenanceRefused as exc:
        raise SystemExit(f"provenance NOT established: {exc}") from exc

    args.output.write_text(
        json.dumps(attestation, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"provenance ESTABLISHED for {attestation['sample_count']} samples")
    print("  every provider_request_id matched the provider's own usage export")
    print(f"  measured total ${attestation['measured_usd_total']} reconciled")
    print(f"  export {attestation['usage_export_path']}")
    return 0


def verify(
    bundle: Mapping[str, Any],
    export_rows: Sequence[Mapping[str, Any]],
    *,
    ledger_total_usd: str | None = None,
    allow_extra_generations: bool = False,
    export_path: str = "",
) -> dict[str, Any]:
    samples = bundle.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ProvenanceRefused("the bundle carries no samples")
    if not export_rows:
        raise ProvenanceRefused("the usage export is empty")

    exported: dict[str, Mapping[str, Any]] = {}
    for row in export_rows:
        identifier = str(row["id"]).strip()
        if identifier in exported:
            raise ProvenanceRefused(f"usage export lists generation {identifier} more than once")
        exported[identifier] = row

    total = Decimal("0")
    matched: list[str] = []
    for sample in samples:
        identifier = str(sample.get("provider_request_id", "")).strip()
        if not identifier:
            raise ProvenanceRefused(f"sample {sample.get('label_id')} has no provider_request_id")
        row = exported.get(identifier)
        if row is None:
            raise ProvenanceRefused(
                f"provider_request_id {identifier} (sample {sample.get('label_id')}) does not "
                "appear in the usage export — the provider has no record of this call"
            )
        if str(row["model"]).strip() != str(sample.get("returned_model", "")).strip():
            raise ProvenanceRefused(
                f"generation {identifier} was served by {row['model']!r} but the bundle records "
                f"{sample.get('returned_model')!r}"
            )
        exported_cost = _decimal(row["cost"], f"cost of generation {identifier}")
        bundle_cost = _decimal(
            sample.get("measured_cost_usd"),
            f"measured_cost_usd of sample {sample.get('label_id')}",
        )
        if abs(exported_cost - bundle_cost) > _COST_TOLERANCE:
            raise ProvenanceRefused(
                f"generation {identifier} cost {exported_cost} in the export but "
                f"{bundle_cost} in the bundle"
            )
        _check_tokens(sample, row, identifier)
        total += bundle_cost
        matched.append(identifier)

    unclaimed = sorted(set(exported) - set(matched))
    if unclaimed and not allow_extra_generations:
        raise ProvenanceRefused(
            f"{len(unclaimed)} exported generations are not claimed by the bundle "
            f"(first: {unclaimed[0]}). Either the export covers a wider window — pass "
            "--allow-extra-generations — or calls were made that the bundle does not report"
        )

    if ledger_total_usd is not None:
        expected = _decimal(ledger_total_usd, "ledger total")
        if abs(expected - total) > _COST_TOLERANCE:
            raise ProvenanceRefused(
                f"ledger total {expected} does not reconcile with the summed exported cost {total}"
            )

    return {
        "schema_version": "1",
        "attestation_kind": "openrouter_usage_export_reconciled",
        "judge_identity": bundle["judge_identity"],
        "sample_count": len(samples),
        "matched_generation_count": len(matched),
        "unclaimed_generation_count": len(unclaimed),
        "measured_usd_total": format(total, "f"),
        "usage_export_path": export_path,
        "checks": [
            "every sample provider_request_id appears in the provider usage export",
            "exported model equals the bundle's returned_model for every sample",
            "exported cost equals the bundle's measured_cost_usd for every sample",
            "token counts agree where the export carries them",
            (
                "no unclaimed exported generations"
                if not unclaimed
                else "unclaimed exported generations explicitly allowed by the operator"
            ),
        ],
        "what_this_does_not_prove": (
            "That the evidence judged was produced by a live target. The calibration corpus is "
            "authored synthetic ground truth; this attestation establishes only that the Judge "
            "model calls really happened and cost what the bundle says."
        ),
    }


def _check_tokens(
    sample: Mapping[str, Any],
    row: Mapping[str, Any],
    identifier: str,
) -> None:
    prompt = row.get("tokens_prompt")
    if prompt is not None and int(prompt) != int(sample.get("input_tokens", -1)):
        raise ProvenanceRefused(
            f"generation {identifier} used {prompt} prompt tokens in the export but "
            f"{sample.get('input_tokens')} in the bundle"
        )
    completion = row.get("tokens_completion")
    if completion is None:
        return
    # OpenRouter counts reasoning inside completion tokens; the bundle splits the two.
    combined = int(sample.get("output_tokens", 0)) + int(sample.get("reasoning_tokens", 0))
    if int(completion) not in {combined, int(sample.get("output_tokens", -1))}:
        raise ProvenanceRefused(
            f"generation {identifier} reports {completion} completion tokens, which matches "
            f"neither the bundle's output tokens nor output+reasoning ({combined})"
        )


def _load_export(path: Path) -> list[dict[str, Any]]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ProvenanceRefused(f"{path} is unreadable") from exc

    stripped = raw.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        payload = json.loads(stripped)
        rows = payload.get("data", payload) if isinstance(payload, Mapping) else payload
        if not isinstance(rows, list):
            raise ProvenanceRefused("the JSON usage export is not a list of generations")
        return [_normalize(dict(row), source=str(path)) for row in rows]

    reader = csv.DictReader(raw.splitlines())
    if reader.fieldnames is None:
        raise ProvenanceRefused(f"{path} has no CSV header row")
    return [_normalize(dict(row), source=str(path)) for row in reader]


def _normalize(row: Mapping[str, Any], *, source: str) -> dict[str, Any]:
    lowered = {str(key).strip().lower(): value for key, value in row.items()}
    resolved: dict[str, Any] = {}
    for field, aliases in _FIELD_ALIASES.items():
        for alias in aliases:
            if alias in lowered and lowered[alias] not in (None, ""):
                resolved[field] = lowered[alias]
                break
    missing = [field for field in _REQUIRED if field not in resolved]
    if missing:
        raise ProvenanceRefused(
            f"{source} is missing required column(s) {missing}. Columns seen: "
            f"{sorted(lowered)}. Rename them or supply the normalized JSON form documented in "
            "this script's header — the tool refuses rather than guess, because a column it "
            "guessed wrong would 'verify' nothing."
        )
    return resolved


def _decimal(value: Any, label: str) -> Decimal:
    try:
        parsed = Decimal(str(value).strip().lstrip("$"))
    except (InvalidOperation, AttributeError, TypeError) as exc:
        raise ProvenanceRefused(f"{label} is not a number: {value!r}") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ProvenanceRefused(f"{label} is not a valid cost: {value!r}")
    return parsed


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ProvenanceRefused(f"{path} is unreadable or not valid JSON") from exc


if __name__ == "__main__":
    raise SystemExit(main())
