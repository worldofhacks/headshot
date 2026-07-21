"""Command-line entry points for the shared M11 deterministic validators."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping
from pathlib import Path

from agentforge.evals.validation import (
    MAX_CORPUS_ARTIFACTS,
    EvalValidationError,
    detect_duplicate_sequences,
    load_fixture_registry,
    load_json_file,
    validate_attack_case,
    validate_corpus,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m agentforge.evals")
    subparsers = parser.add_subparsers(dest="command", required=True)

    corpus = subparsers.add_parser("validate-corpus", help="validate the complete evals tree")
    corpus.add_argument("root", type=Path)

    case = subparsers.add_parser("validate-eval-case", help="validate one AttackCase JSON file")
    case.add_argument("path", type=Path)
    case.add_argument("--fixtures-dir", type=Path, required=True)

    duplicate = subparsers.add_parser(
        "detect-duplicate-sequence", help="detect duplicate AttackCase sequences in a directory"
    )
    duplicate.add_argument("seeds_dir", type=Path)
    return parser


def _print_issues(error: EvalValidationError) -> None:
    for issue in error.issues:
        print(str(issue), file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate-corpus":
            summary = validate_corpus(args.root)
            print(
                f"valid corpus: {summary.case_count} cases, "
                f"{summary.ground_truth_label_count} ground-truth labels, "
                f"{len(summary.categories)} categories, {summary.fixture_count} fixtures"
            )
            return 0
        if args.command == "validate-eval-case":
            registry = load_fixture_registry(args.fixtures_dir)
            payload = load_json_file(args.path)
            validate_attack_case(
                payload,
                source=args.path,
                fixture_ids=registry.fixture_ids,
                fixture_canaries=registry.canaries_by_fixture,
                fixture_versions=registry.versions_by_fixture,
                fixture_sources=registry.sources_by_fixture,
            )
            print("valid AttackCase")
            return 0
        if args.command == "detect-duplicate-sequence":
            if args.seeds_dir.is_symlink() or not args.seeds_dir.is_dir():
                raise RuntimeError("seed directory is unavailable")
            paths: list[Path] = []
            for path in args.seeds_dir.iterdir():
                if path.suffix == ".json":
                    paths.append(path)
                    if len(paths) > MAX_CORPUS_ARTIFACTS:
                        raise RuntimeError("seed directory has too many artifacts")
            paths.sort(key=lambda path: path.name)
            if not paths:
                raise RuntimeError("seed directory has an invalid artifact count")
            cases: list[Mapping[str, object]] = []
            for path in paths:
                payload = load_json_file(path)
                validate_attack_case(payload, source=path)
                if not isinstance(payload, Mapping):  # pragma: no cover - validator guarantees this
                    raise RuntimeError("validated AttackCase is not an object")
                cases.append(payload)
            issues = detect_duplicate_sequences(cases)
            if issues:
                raise EvalValidationError(issues)
            print(f"no duplicate input sequences: {len(cases)} cases")
            return 0
    except EvalValidationError as exc:
        _print_issues(exc)
        return 1
    except (OSError, RuntimeError):
        print("operational-error: validator could not complete", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
