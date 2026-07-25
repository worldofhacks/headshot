#!/usr/bin/env python3
"""Deterministic validator for the reproduction control manifest (headshot-repro-controls-v1).

This is the enforcement half of the honesty rules the reproduction pack asserts in prose. Run it
in the authoring workflow AND in CI so guidance and enforcement cannot drift (the same discipline
the adversarial-eval-lifecycle skill applies to attack cases via validate-eval-case).

What it enforces
----------------
AC1  Anti-echo: the token an oracle checks for (a probe's bound_canary_ref) never appears in that
     probe's own dispatched input. A substring canary oracle that finds its token in an input we
     supplied would "confirm" our own echo -- a manufactured confirmation. Positive attack cases
     are checked too when their corpus dir is supplied (--corpus-dir), otherwise reported deferred.
AC2  Decoy integrity: no decoy token is a member of the target's seeded-canary set.
AC3  Instrument identity: every non-decoy control binds the SAME oracle_id + canary_ref as the
     positive it controls for (one variable changes: the input). Decoys bind a non-seeded token.
AC4  Pre-registration shape: negative_control asserts non-fire; invariant_guard asserts the oracle
     precedence holds; every finding carries >=1 negative_control, an OWASP mapping, and a
     pre-registered confirmed condition + honest fallback on its positive arm.

Exit code 0 iff every check passes; non-zero (and a printed report) otherwise.

Usage:
    python3 scripts/validate_repro_controls.py \
        [--manifest evals/repro-controls/headshot-repro-controls-v1.json] \
        [--corpus-dir /path/to/rtg/evals/workloads/live-100-cases]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

DEFAULT_MANIFEST = "evals/repro-controls/headshot-repro-controls-v1.json"


def _fail(problems: list[str], msg: str) -> None:
    problems.append(msg)


def _load_positive_inputs(corpus_dir: Path) -> dict[str, list[str]]:
    """Map case_id -> input_sequence for every case JSON found under corpus_dir (best effort)."""
    inputs: dict[str, list[str]] = {}
    if not corpus_dir.is_dir():
        return inputs
    for path in sorted(corpus_dir.glob("*.json")):
        try:
            case = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        cid = case.get("case_id")
        seq = case.get("input_sequence")
        if isinstance(cid, str) and isinstance(seq, list):
            inputs[cid] = [str(s) for s in seq]
    return inputs


def validate(
    manifest: dict[str, Any], positive_inputs: dict[str, list[str]]
) -> tuple[list[str], list[str]]:
    problems: list[str] = []
    notes: list[str] = []

    seeded = {c["canary_ref"] for c in manifest.get("seeded_canaries_required", [])}
    decoys = set(manifest.get("decoy_tokens_must_not_be_seeded", []))

    # AC2 -- decoy integrity (manifest-level).
    for tok in decoys:
        if tok in seeded:
            _fail(problems, f"AC2 decoy integrity: decoy token {tok!r} is also in the seeded set")

    findings = manifest.get("findings", [])
    if not findings:
        _fail(problems, "manifest has no findings")

    for f in findings:
        ref = f.get("finding_ref", "<?>")
        pos = f.get("positive_case", {})
        pos_id = pos.get("case_id", "<?>")
        pos_oracle = pos.get("oracle_id")
        pos_canary = pos.get("canary_ref")

        # AC4 -- positive arm pre-registration shape.
        if not f.get("owasp"):
            _fail(problems, f"[{ref}] AC4: missing OWASP mapping")
        for field in (
            "pre_registered_confirmed_condition",
            "pre_registered_honest_fallback",
            "expected_confirmed_source",
        ):
            if not pos.get(field):
                _fail(problems, f"[{ref}] AC4: positive_case missing {field}")
        if pos.get("expected_confirmed_source") not in {"oracle", "canary", "human"}:
            _fail(
                problems,
                f"[{ref}] AC4: expected_confirmed_source must be oracle|canary|human "
                f"(got {pos.get('expected_confirmed_source')!r})",
            )

        # AC1 -- positive attack input never contains its own canary token.
        if pos_canary:
            seq = positive_inputs.get(pos_id)
            if seq is None:
                notes.append(
                    f"[{ref}] AC1 for positive {pos_id}: DEFERRED (corpus input not "
                    f"available; re-run with --corpus-dir at reproduction time)"
                )
            else:
                joined = "\n".join(seq)
                if pos_canary in joined:
                    _fail(
                        problems,
                        f"[{ref}] AC1: positive {pos_id} input contains its own canary "
                        f"{pos_canary!r} -- oracle would fire on our echo",
                    )
                else:
                    notes.append(
                        f"[{ref}] AC1 for positive {pos_id}: OK (canary absent from input)"
                    )

        controls = f.get("controls", [])
        neg = [c for c in controls if c.get("control_kind") == "negative_control"]
        if not neg:
            _fail(problems, f"[{ref}] AC4: finding has no negative_control")

        for c in controls:
            pid = c.get("probe_id", "<?>")
            kind = c.get("control_kind")
            bound_oracle = c.get("bound_oracle_id")
            bound_canary = c.get("bound_canary_ref")
            text = "\n".join(str(x) for x in ([c.get("input")] if c.get("input") else []))

            # AC1 -- probe input never contains its own bound token.
            if bound_canary and bound_canary in text:
                _fail(
                    problems,
                    f"[{ref}] AC1: probe {pid} input contains its bound token "
                    f"{bound_canary!r} -- oracle would fire on our echo",
                )

            is_decoy = "decoy" in str(bound_oracle or "").lower() or (bound_canary in decoys)

            # AC3 -- instrument identity.
            if is_decoy:
                if bound_canary not in decoys:
                    _fail(
                        problems,
                        f"[{ref}] AC3: decoy probe {pid} binds {bound_canary!r} which is "
                        f"not declared in decoy_tokens_must_not_be_seeded",
                    )
            else:
                if bound_oracle != pos_oracle or bound_canary != pos_canary:
                    _fail(
                        problems,
                        f"[{ref}] AC3: control {pid} binds ({bound_oracle},{bound_canary}) "
                        f"but must match the positive instrument ({pos_oracle},{pos_canary})",
                    )

            # AC4 -- pre-registration direction.
            if kind == "negative_control":
                if c.get("expected_oracle_hit") is not False:
                    _fail(
                        problems,
                        f"[{ref}] AC4: negative_control {pid} must set expected_oracle_hit=false",
                    )
            elif kind == "invariant_guard":
                if c.get("expected_oracle_hit_if_leak") is not True:
                    _fail(
                        problems,
                        f"[{ref}] AC4: invariant_guard {pid} must set expected_oracle_hit_if_leak=true",
                    )
            else:
                _fail(problems, f"[{ref}] control {pid} has unknown control_kind {kind!r}")

    return problems, notes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST)
    ap.add_argument(
        "--corpus-dir",
        default=None,
        help="dir of positive AttackCase JSON (e.g. rtg evals/workloads/live-100-cases) "
        "to enable AC1 on positive arms",
    )
    args = ap.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.is_file():
        print(f"FAIL: manifest not found: {manifest_path}", file=sys.stderr)
        return 2
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    positive_inputs: dict[str, list[str]] = {}
    if args.corpus_dir:
        positive_inputs = _load_positive_inputs(Path(args.corpus_dir))

    problems, notes = validate(manifest, positive_inputs)

    for n in notes:
        print(f"note: {n}")
    if problems:
        print(f"\nFAIL: {len(problems)} anti-cheat violation(s):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(
        f"\nOK: reproduction control manifest {manifest.get('manifest_id')} passes all anti-cheat "
        f"invariants ({len(manifest.get('findings', []))} findings)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
