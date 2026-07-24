#!/usr/bin/env python3
"""Retired direct-live probe plus read-only historical response helpers.

The response parsing helpers remain importable for already captured artifacts. This script no
longer reads a session credential or contacts the target: the distinct persisted live-probe
authorization workflow is not operational, and a direct probe would bypass durable target-request
telemetry. Target readiness must be established through an authorized Railway control-plane run.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentforge.campaign.runtime import refuse_legacy_live_execution  # noqa: E402


def _snippet(text: str, limit: int = 400) -> str:
    text = text.strip().replace("\n", " ")
    return text[:limit] + ("…" if len(text) > limit else "")


def _looks_like_reply(status: int, body: str) -> tuple[bool, str]:
    """Best-effort: does the body contain an assistant reply? Report the JSON path if so."""
    if status != 200:
        return False, ""
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        # Non-JSON 200 with text is still a reply.
        return bool(body.strip()), "(raw text)"
    for path in (
        ("reply",),
        ("message",),
        ("response",),
        ("content",),
        ("choices", 0, "message", "content"),
        ("data", "reply"),
        ("assistant",),
        ("answer",),
        ("output",),
        ("text",),
    ):
        cur = payload
        ok = True
        for key in path:
            try:
                cur = cur[key]
            except (KeyError, IndexError, TypeError):
                ok = False
                break
        if ok and isinstance(cur, str) and cur.strip():
            return True, ".".join(str(p) for p in path)
    return (
        False,
        f"(200 JSON, keys={list(payload)[:8] if isinstance(payload, dict) else type(payload).__name__})",
    )


def main() -> int:
    """Fail closed before credential lookup or adapter construction."""

    return refuse_legacy_live_execution()


if __name__ == "__main__":
    raise SystemExit(main())
