#!/usr/bin/env python3
"""Retired direct-live retry launcher.

The old retry path mutated local artifacts and resent target requests outside the durable Railway
campaign/agent ledger. Historical files remain readable, but retries now require a newly authorized
control-plane campaign; this executable never reads a target credential or opens a target socket.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agentforge.campaign.runtime import refuse_legacy_live_execution  # noqa: E402


def main() -> int:
    """Fail closed before reading historical files, credentials, or target configuration."""

    return refuse_legacy_live_execution()


if __name__ == "__main__":
    raise SystemExit(main())
