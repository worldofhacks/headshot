#!/usr/bin/env python3
"""Publish the packaged contract schemas to the reviewer-facing root directory.

``src/agentforge/contracts/v1`` remains the runtime and authoring source of truth.
This script creates a byte-for-byte publication at ``contracts/v1`` so reviewers
can find the JSON Schemas at the location required by the PRD without creating a
second independently editable contract set.
"""

from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "src" / "agentforge" / "contracts" / "v1"
PUBLISHED_DIR = ROOT / "contracts" / "v1"


def _json_files(directory: Path) -> dict[str, Path]:
    return {path.name: path for path in sorted(directory.glob("*.json"))}


def _write_publication(source: dict[str, Path]) -> None:
    PUBLISHED_DIR.mkdir(parents=True, exist_ok=True)
    published = _json_files(PUBLISHED_DIR)

    for stale_name in sorted(published.keys() - source.keys()):
        published[stale_name].unlink()
    for name, source_path in source.items():
        (PUBLISHED_DIR / name).write_bytes(source_path.read_bytes())


def _drift_messages(source: dict[str, Path], published: dict[str, Path]) -> list[str]:
    messages: list[str] = []
    for name in sorted(source.keys() - published.keys()):
        messages.append(f"missing published schema: contracts/v1/{name}")
    for name in sorted(published.keys() - source.keys()):
        messages.append(f"unexpected published schema: contracts/v1/{name}")
    for name in sorted(source.keys() & published.keys()):
        if source[name].read_bytes() != published[name].read_bytes():
            messages.append(f"published schema differs from package source: {name}")
    return messages


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check or refresh the root contract-schema publication."
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="refresh contracts/v1 from the canonical packaged schemas",
    )
    args = parser.parse_args()

    source = _json_files(SOURCE_DIR)
    if not source:
        parser.error(f"no canonical JSON Schemas found under {SOURCE_DIR}")
    if args.write:
        _write_publication(source)

    messages = _drift_messages(source, _json_files(PUBLISHED_DIR))
    if messages:
        for message in messages:
            print(message)
        print("run: python scripts/sync_contracts.py --write")
        return 1

    action = "published" if args.write else "verified"
    print(f"{action} {len(source)} byte-identical v1 contract schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
