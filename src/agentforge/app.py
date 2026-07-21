"""ASGI entrypoint for the deployment/health surface.

spec(M1a:AC-3)

This is the module the container runs under uvicorn (``agentforge.app:app``). It wires the
health app factory (:func:`agentforge.health.create_app`) to a readiness check.

The real readiness check — "DB reachable + migrations current" — lands with the storage
layer in a later phase. Until then the default check is **fail-closed** (returns ``False``)
so ``/ready`` reports ``503 not_ready`` and no orchestrator ever routes live traffic to a
pod whose dependencies have not been verified. ``/health`` stays ``200 alive`` regardless,
which is exactly the liveness-vs-readiness split the probes exist to provide.
"""

from __future__ import annotations

from agentforge.health import create_app


def _default_readiness_check() -> bool:
    """Fail-closed placeholder until the storage layer provides a real DB/migration check."""
    return False


app = create_app(readiness_check=_default_readiness_check)
