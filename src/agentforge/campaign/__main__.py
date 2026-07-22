"""``python -m agentforge.campaign`` entry point — the production composition root.

This is the ONE place the injection-driven :func:`agentforge.campaign.cli.main` is wired to its REAL
production collaborators: a real DB engine (from ``DATABASE_URL``), a real live-adapter factory (an
:class:`~agentforge.target.openemr_adapter.OpenEmrAdapter` with a lazy ``httpx`` client), a real
clock, and real run accounting. Building them opens NO socket — the target connection is made only
at the first post-gate dispatch inside ``run_case`` — so this entry is safe to reach from a
preflight/CI context.

A missing ``DATABASE_URL`` for a ``run`` is a typed operational error (exit 2), not a silent default
— the bounded run never launches against an unspecified evidence store. This is distinct from a
fail-closed AUTHORIZATION refusal (exit 1), which the coordinator raises when a run reaches the gate
without a valid, in-scope grant.
"""

from __future__ import annotations

import os
import sys

from agentforge.campaign import cli, runtime

# The environment the run executes under. Live-target credentials resolve ONLY in production (O1),
# so this defaults to production; override for a staging/dry exercise against a non-live target.
_ENVIRONMENT_ENV = "HEADSHOT_ENVIRONMENT"


def main(argv: list[str] | None = None) -> int:
    """Route to the ``run`` or ``scope`` command, composing REAL deps only for ``run``.

    Returns the CLI's exit code (0 success / 1 fail-closed refusal / 2 operational error). The
    ``scope`` command is network-free and needs no runtime — it is dispatched WITHOUT building an
    engine, so requesting an authorization needs no ``DATABASE_URL`` and touches no live resource.
    ``run`` builds the engine + adapter factory + clock + accounting from the environment; a missing
    ``DATABASE_URL`` (or other runtime-config failure) maps to the operational exit code BEFORE any
    live object is used, and no live object is used until a valid, in-scope, authorized run
    dispatches.
    """
    args = cli._parser().parse_args(argv)  # argparse exits on --help / a bad subcommand
    if args.command != "run":
        return cli.main(argv)  # scope (or any non-run command) — no runtime composed

    try:
        engine = runtime.production_engine(os.environ.get("DATABASE_URL"))
    except runtime.RuntimeConfigError as exc:
        print(f"operational-error: {exc}", file=sys.stderr)
        return 2

    return cli.main(
        argv,
        engine=engine,
        adapter_factory=runtime.live_adapter_factory(),
        clock=runtime.SystemClock(),
        accounting=runtime.accounting_from_environment(),
        environment=os.environ.get(_ENVIRONMENT_ENV, "production"),
    )


if __name__ == "__main__":
    raise SystemExit(main())
