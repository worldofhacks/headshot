#!/usr/bin/env python3
"""Capture an honest local corpus-admission baseline and a non-authorizing run envelope."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from agentforge.agents.hosted_policy import (
    HostedGenerationPolicyError,
    resolve_hosted_generation_policy,
)
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
    load_batch_budget_plan,
    load_staged_configuration_receipt,
    write_corpus_baseline_artifacts,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the byte-pinned reviewed 100-case corpus, derive its exact 100/121/0 "
            "caps and a staged-configuration-bound four-role batching plan, and measure local "
            "admission work. No target, provider, database, or Railway call is made."
        )
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--workload-sha256", required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--staged-configuration-receipt", type=Path, required=True)
    parser.add_argument("--generation-policy-sha256", required=True)
    parser.add_argument("--batch-budget-plan", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def _repo_relative_path(root: Path, value: Path) -> Path:
    return value if value.is_absolute() else root / value


def main() -> int:
    arguments = _arguments()
    root = Path(os.path.abspath(arguments.repo_root))
    try:
        corpus = resolve_workload(
            LIVE_100_CORPUS_ID,
            root=root / "evals",
            bundle_root=reviewed_bundle_root(root / "security-tools" / "reviewed"),
            expected_content_hash=arguments.workload_sha256,
        )
        staged_configuration = load_staged_configuration_receipt(
            _repo_relative_path(root, arguments.staged_configuration_receipt)
        )
        budget_plan = load_batch_budget_plan(_repo_relative_path(root, arguments.batch_budget_plan))
        generation_policy = resolve_hosted_generation_policy(arguments.generation_policy_sha256)
        envelope = build_run_authorization_envelope(
            corpus=corpus,
            repo_root=root,
            release_sha=arguments.release_sha,
            run_id=arguments.run_id,
            staged_configuration=staged_configuration,
            generation_policy=generation_policy,
            budget_plan=budget_plan,
        )
        baseline = capture_local_corpus_admission(
            corpus=corpus,
            release_sha=arguments.release_sha,
            run_id=arguments.run_id,
        )
        result = write_corpus_baseline_artifacts(
            repo_root=root,
            output_directory=_repo_relative_path(root, arguments.output_dir),
            envelope=envelope,
            local_baseline=baseline,
        )
    except (
        CorpusBaselineError,
        CorpusUnavailable,
        HostedGenerationPolicyError,
    ) as exc:
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
