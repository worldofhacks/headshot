"""``python -m agentforge.campaign`` entry point.

Delegates to :func:`agentforge.campaign.cli.main`. This module-level entry is intentionally thin:
the real, injection-driven ``main`` (engine / adapter factory / clock / accounting) is exercised
directly in tests with no subprocess and no network. Invoking the module without those injected
collaborators is not a supported runtime path for the MVP secure coordinator (a live run requires
an explicit, authorized wiring), so this guard fails closed rather than constructing a real client.
"""

from __future__ import annotations

import sys


def _fail_closed() -> int:
    print(
        "refused: `python -m agentforge.campaign` requires an explicit authorized wiring "
        "(engine + bound adapter factory) — a live run is never launched from bare defaults",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(_fail_closed())
