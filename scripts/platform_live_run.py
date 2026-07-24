#!/usr/bin/env python3
"""Retired direct-live campaign launcher.

Historical artifacts produced by the former script remain under ``evals/results`` for provenance,
but this executable can no longer contact a target. Live campaigns must be launched through the
authenticated Railway Web control plane and consumed by the private durable Runner so every agent,
target request, cost, and Langfuse observation is tied to the authoritative campaign ledger.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agentforge.campaign.runtime import refuse_legacy_live_execution  # noqa: E402


def main() -> int:
    """Fail closed before reading credentials, opening storage, or constructing an adapter."""

    return refuse_legacy_live_execution()


if __name__ == "__main__":
    raise SystemExit(main())
