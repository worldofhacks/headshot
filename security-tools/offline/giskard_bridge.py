#!/usr/bin/env python3
"""Load and validate Giskard Scan's packaged prompt-injection scenarios offline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from giskard.scan import PromptInjectionScenarioGenerator, __version__


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    scenarios = PromptInjectionScenarioGenerator().load_scenarios(
        "Synthetic clinical co-pilot; no PHI and no target connection", ["en"]
    )
    if not scenarios:
        raise RuntimeError("Giskard packaged prompt-injection dataset was empty")
    payload = {
        "tool": "giskard-scan",
        "tool_version": __version__,
        "execution_scope": "packaged-scenario-load-only",
        "scenarios": [scenario.model_dump(mode="json") for scenario in scenarios],
        "scan_results": [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
