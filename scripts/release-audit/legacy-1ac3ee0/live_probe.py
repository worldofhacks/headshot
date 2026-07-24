#!/usr/bin/env python3
"""Step 1 auth-proof probe for an authorized, synthetic-only live Co-Pilot campaign.

Sends ONE benign /chat turn through the real ``OpenEmrAdapter`` (copilot_chat profile) and
reports whether the target answered 200 with an assistant reply. The session credential is read
from ``TARGET_SESSION_SID`` in ``os.environ`` ONLY, wrapped in a redacting ``Secret``, and placed
in the request BODY (``session_id``) at the send boundary — never inlined, logged, or committed.

An allowlist guard refuses any base URL whose host is not the single authorized target host.

Usage: ``TARGET_SESSION_SID=... python scripts/live_probe.py [--path chat] [--message "..."]``
Exit codes: 0 = 200 + reply (auth proven); 3 = 401/403 (STOP); 4 = other non-200; 5 = error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentforge.secrets import Secret  # noqa: E402
from agentforge.target.base import (  # noqa: E402
    AdapterError,
    RateLimitedError,
    TargetRequest,
    TargetSessionExpiredError,
    TargetUnreachableError,
)
from agentforge.target.openemr_adapter import OpenEmrAdapter  # noqa: E402

# The single allowlisted, README-documented authorized live target host (NOT a secret).
AUTHORIZED_HOST = "agent-production-9f62.up.railway.app"
BASE_URL = f"https://{AUTHORIZED_HOST}"

# Benign, synthetic, non-adversarial probe. No PHI, no attack payload.
DEFAULT_MESSAGE = (
    "Hello — can you confirm you are the clinical co-pilot assistant and are ready to help?"
)


def _allowlist_guard(base_url: str) -> None:
    from urllib.parse import urlsplit

    host = urlsplit(base_url).hostname
    if host != AUTHORIZED_HOST:
        raise SystemExit(
            f"REFUSED: base URL host {host!r} is off-allowlist (only {AUTHORIZED_HOST} allowed)"
        )


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
        (
            "(200 JSON, keys="
            f"{list(payload)[:8] if isinstance(payload, dict) else type(payload).__name__})"
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default="chat", help="relative /chat path (default: chat)")
    parser.add_argument("--message", default=DEFAULT_MESSAGE)
    args = parser.parse_args()

    raw = os.environ.get("TARGET_SESSION_SID")
    if not raw:
        print(
            "BLOCKED: TARGET_SESSION_SID is not set in the environment — cannot prove auth.",
            file=sys.stderr,
        )
        return 5

    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        payload_profile="copilot_chat",
        relative_path=args.path,
        credential=Secret(raw),
        destination_validator=_allowlist_guard,
        timeout_seconds=30.0,
    )
    request = TargetRequest(
        turns=(args.message,), metadata={"probe": "auth-proof", "synthetic": "true"}
    )

    print(f"PROBE  POST {BASE_URL}/{args.path}  (copilot_chat, session_id in body)")
    try:
        response = adapter.send(request)
    except TargetSessionExpiredError as exc:
        print(f"RESULT AUTH-FAIL (session expired / 401): {exc.__class__.__name__}: {exc}")
        return 3
    except RateLimitedError as exc:
        print(f"RESULT RATE-LIMITED (429): {exc}")
        return 4
    except TargetUnreachableError as exc:
        print(f"RESULT UNREACHABLE: {exc}")
        return 5
    except AdapterError as exc:
        print(f"RESULT ADAPTER-ERROR: {exc.__class__.__name__}: {exc}")
        return 4
    finally:
        adapter.close()

    status = response.status
    has_reply, reply_path = _looks_like_reply(status, response.output)
    print(f"RESULT HTTP {status}")
    print(f"REPLY? {has_reply}  path={reply_path!r}")
    print(f"SNIPPET {_snippet(response.output)}")
    if status in (401, 403):
        print("VERDICT AUTH-FAIL — STOP (unauthorized). Do not scan.")
        return 3
    if status == 200 and has_reply:
        print(
            "VERDICT AUTH-OK — 200 with an assistant reply. "
            "Cleared to proceed (bounded, rate-limited)."
        )
        return 0
    print("VERDICT INCONCLUSIVE — non-200 or no recognizable reply. Investigate before scanning.")
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
