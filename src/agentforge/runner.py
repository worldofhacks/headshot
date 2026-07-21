"""Private durable-queue Runner process.

The module intentionally contains no HTTP listener. Production execution remains unavailable
until a trusted credential-value resolver and surface-bound adapter factory are composed; it
never turns a secret reference into bearer material or substitutes a fake adapter.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Mapping
from typing import Any


class DispatchUnavailable(RuntimeError):
    """The persisted work cannot pass every current dispatch gate."""


def _persisted_identity(job: Any) -> tuple[str, str]:
    run_id = getattr(job, "campaign_run_id", None)
    attempt_id = getattr(job, "attempt_id", None)
    if (
        not isinstance(run_id, str)
        or not run_id
        or not isinstance(attempt_id, str)
        or not attempt_id
    ):
        raise DispatchUnavailable("job_identity_invalid")
    return run_id, attempt_id


def _scope_from_authorized(value: Any) -> Any:
    if isinstance(value, Mapping):
        scope = value.get("scope") or value.get("authorization_scope")
    else:
        scope = getattr(value, "scope", None) or getattr(value, "authorization_scope", None)
    if scope is None:
        raise DispatchUnavailable("canonical_scope_unavailable")
    return scope


def process_agent_work(
    job: Any,
    *,
    control_plane: Any,
    adapters: Any,
    executor: Callable[[Any, Any, Any], Any] | None = None,
) -> Any:
    """Revalidate persisted authority before adapter construction or any external action.

    Queue payload routing, approval booleans, roles, permissions, hosts, and credentials are
    deliberately ignored. The immutable queue row supplies identifiers only; the control plane
    reloads the exact organization-scoped approval and current registry state.
    """

    run_id, attempt_id = _persisted_identity(job)
    resolver = getattr(control_plane, "resolve_dispatch", None)
    if callable(resolver):
        authorized = resolver(run_id, attempt_id)
    else:
        loader = getattr(control_plane, "load_run_for_execution", None)
        if not callable(loader):
            raise DispatchUnavailable("control_plane_dispatch_resolver_missing")
        authorized = loader(run_id)
    scope = _scope_from_authorized(authorized)

    # Prove the complete trusted composition before constructing an adapter or allowing
    # an executor to create an external effect. A missing atomic commit seam must therefore
    # fail before target/model code is reachable, not after an irreversible request.
    if executor is None:
        raise DispatchUnavailable("trusted_execution_composition_missing")
    commit = getattr(control_plane, "record_result_and_complete", None)
    if not callable(commit):
        raise DispatchUnavailable("atomic_result_commit_missing")

    # This is the first point an adapter may exist. All authorization, expiry, hash, abort,
    # target lifecycle, and effective surface-state checks must have completed above.
    adapter = adapters.resolve(scope)
    result = executor(adapter, authorized, job)
    commit(job, result)
    return result


def check_runtime(database_url: str | None = None) -> bool:
    """Offline-safe startup check; no target, model, Clerk, or socket activity."""

    url = database_url if database_url is not None else os.environ.get("DATABASE_URL")
    if not url:
        return False
    # Execution must stay disabled until the exact-reference resolver is explicitly composed.
    return os.environ.get("AGENTFORGE_RUNNER_EXECUTION_READY") == "true"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentforge-runner")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    ready = check_runtime()
    if args.check:
        return 0 if ready else 1
    if not ready:
        print("runner unavailable: trusted execution composition is incomplete", file=sys.stderr)
        return 1
    # The readiness flag cannot itself create trusted factories. A future composition must
    # replace this refusal in the same change that wires the audited resolver and executor.
    print(
        "runner unavailable: no trusted adapter/executor composition is installed", file=sys.stderr
    )
    return 1


if __name__ == "__main__":  # pragma: no cover - subprocess/container smoke owns this path
    raise SystemExit(main())


__all__ = ["DispatchUnavailable", "check_runtime", "main", "process_agent_work"]
