#!/usr/bin/env python3
"""Validate native artifacts through AgentForge's bounded adapters."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentforge.security_tools import (
    GarakAdapter,
    GiskardAdapter,
    NormalizationContext,
    PromptfooAdapter,
    PyritAdapter,
)
from agentforge.security_tools.candidates import build_tool_attack_bundle


def context(tool: str, version: str, path: Path) -> NormalizationContext:
    return NormalizationContext(
        tool_name=tool,
        tool_version=version,
        configuration_sha256="0" * 64,
        run_id=f"offline-{tool}",
        run_nonce="offline-native-evidence",
        target_id="no-target",
        surface_id="offline-tooling",
        scan_provenance="local_fake",
        observed_at="2026-07-22T00:00:00Z",
        artifact_locator=f"ci-artifact://{path.name}",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_dir", type=Path)
    args = parser.parse_args()
    specs = (
        ("garak", "0.15.1", GarakAdapter(), args.artifact_dir / "garak.report.jsonl"),
        ("pyrit", "0.14.0", PyritAdapter(), args.artifact_dir / "pyrit.json"),
        ("giskard", "1.0.0b3", GiskardAdapter(), args.artifact_dir / "giskard.json"),
        ("promptfoo", "0.121.19", PromptfooAdapter(), args.artifact_dir / "promptfoo.json"),
    )
    summary: dict[str, object] = {}
    for tool, version, adapter, path in specs:
        result = adapter.import_artifact(path.read_bytes(), context(tool, version, path))
        summary[tool] = {
            "artifact_sha256": result.artifact_sha256,
            "records_seen": result.records_seen,
            "candidate_count": len(result.candidates),
            "finding_count": len(result.findings),
        }
        if result.candidates:
            bundle = build_tool_attack_bundle(
                bundle_id=f"offline-{tool}-{result.artifact_sha256[:16]}",
                tool_name=tool,
                tool_version=version,
                configuration_sha256="0" * 64,
                generated_at="2026-07-22T00:00:00Z",
                artifact_sha256=result.artifact_sha256,
                candidates=result.candidates,
            )
            (args.artifact_dir / f"{tool}.bundle.json").write_text(
                json.dumps(bundle, sort_keys=True, separators=(",", ":")), encoding="utf-8"
            )
            summary[tool]["bundle"] = f"{tool}.bundle.json"
        else:
            summary[tool]["bundle"] = "not_emitted_no_explicit_candidates"
    (args.artifact_dir / "adapter-summary.json").write_text(
        json.dumps(summary, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
