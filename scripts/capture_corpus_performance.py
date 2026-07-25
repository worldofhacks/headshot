#!/usr/bin/env python3
"""Capture an honest local corpus-admission baseline and a non-authorizing run envelope."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentforge.campaign.corpus import (
    LIVE_100_CORPUS_ID,
    CorpusUnavailable,
    resolve_workload,
    reviewed_bundle_root,
)
from agentforge.performance.corpus_baseline import (
    CorpusBaselineError,
    build_run_authorization_envelope,
    capture_local_corpus_admission,
    verify_bound_caps,
    write_corpus_baseline_artifacts,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the byte-pinned reviewed 100-case corpus, derive its exact 100/121/0 "
            "caps and a cumulative-four-role hosted batching plan, and measure local admission "
            "work. No target, provider, database, or Railway call is made."
        )
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--workload-sha256", required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    root = arguments.repo_root.resolve()
    try:
        corpus = resolve_workload(
            LIVE_100_CORPUS_ID,
            root=root / "evals",
            bundle_root=reviewed_bundle_root(root / "security-tools" / "reviewed"),
            expected_content_hash=arguments.workload_sha256,
        )
        bound_caps = verify_bound_caps(root)
        envelope = build_run_authorization_envelope(
            corpus=corpus,
            release_sha=arguments.release_sha,
            run_id=arguments.run_id,
            bound_caps=bound_caps,
        )
        baseline = capture_local_corpus_admission(
            corpus=corpus,
            release_sha=arguments.release_sha,
            run_id=arguments.run_id,
        )
        result = write_corpus_baseline_artifacts(
            output_directory=arguments.output_dir,
            envelope=envelope,
            local_baseline=baseline,
        )
    except (CorpusBaselineError, CorpusUnavailable) as exc:
        raise SystemExit(str(exc)) from exc
    print(
        json.dumps(
            {
                "output_directory": str(result.output_directory),
                "artifact_sha256s": dict(result.artifact_sha256s),
                "scope": "local-offline-corpus-admission-only",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
