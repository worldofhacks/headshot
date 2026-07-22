#!/usr/bin/env python3
"""Run one bounded Garak probe against Garak's local Repeat test generator."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="agentforge-garak-") as temporary:
        root = Path(temporary)
        prefix = root / "native-garak"
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(root / "home"),
            "TMPDIR": str(root / "tmp"),
            "LANG": "C.UTF-8",
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "NO_PROXY": "*",
        }
        (root / "home").mkdir()
        (root / "tmp").mkdir()
        command = [
            sys.executable,
            "-m",
            "garak",
            "--target_type",
            "test.Repeat",
            "--probes",
            "dan.Dan_11_0",
            "--generations",
            "1",
            "--parallel_attempts",
            "1",
            "--report_prefix",
            str(prefix),
            "--narrow_output",
            "--seed",
            "42",
            "--confidence_interval_method",
            "none",
        ]
        subprocess.run(command, check=True, env=environment, timeout=120)
        report = prefix.with_suffix(".report.jsonl")
        if not report.is_file() or report.stat().st_size > 10 * 1024 * 1024:
            raise RuntimeError("Garak did not produce a bounded native JSONL report")
        shutil.copyfile(report, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
