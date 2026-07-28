"""Every resource the console asks for must have a route that serves it.

The run-level campaign report was wired end to end -- contract, migration, composer, read model,
decoder, screen -- and every layer was verified. It still returned `request_failed` in the browser,
because `router.py` declares each resource as an explicit FastAPI handler and no handler was added.
`/api/v1/campaign_reports` answered 404 while `/api/v1/reports` answered 401, which is the exact
signature of a resource that exists everywhere except the one place that exposes it.

Nothing else caught it: the backend read model, the contract tests, the decoder tests and the
browser fixture all bypass the real router. This test closes that specific gap by comparing what
the console asks for against what the application actually serves.
"""

from __future__ import annotations

import re
from pathlib import Path

from agentforge.api.router import router

_CONSOLE_PATHS = Path(__file__).resolve().parents[1] / "console" / "src" / "api" / "paths.ts"


def _served_paths() -> set[str]:
    """Concrete first segments the router exposes, with path parameters normalised away."""

    served: set[str] = set()
    for route in router.routes:
        path = getattr(route, "path", "")
        if not path:
            continue
        normalised = re.sub(r"\{[^}]+\}", "*", path).strip("/")
        # Routes are mounted under the versioned api prefix; the console paths are
        # relative to it, so compare on the same footing.
        served.add(normalised.removeprefix("api/v1/"))
    return served


def test_every_console_resource_has_a_route() -> None:
    source = _CONSOLE_PATHS.read_text()
    served = _served_paths()

    # Bare string resources: `name: "resource"`. Function-valued entries build parameterised paths
    # and are covered by the campaign-scoped assertion below.
    requested = set(re.findall(r'^\s*\w+:\s*"([a-z0-9_\-]+)",\s*$', source, re.M))
    assert requested, "console resource paths could not be parsed"

    missing = {name for name in requested if name not in served}
    assert not missing, (
        f"console requests resources the router does not serve: {sorted(missing)}. "
        "A resource wired through the read model but not declared in router.py answers 404 "
        "and surfaces as request_failed in the browser."
    )


def test_the_run_level_report_routes_exist() -> None:
    """Pinned by name because this is the one that shipped missing."""

    served = _served_paths()
    assert "campaign_reports" in served
    assert "campaigns/*/campaign_report" in served
