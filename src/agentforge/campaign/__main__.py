"""``python -m agentforge.campaign`` legacy entry point.

``scope`` remains a network-free authorization-request authoring tool. ``run`` is permanently
retired: live campaigns must enter through the authenticated Railway control plane and private
durable Runner so campaign, agent, target-request, cost, and Langfuse telemetry are all recorded.
"""

from __future__ import annotations

from agentforge.campaign import cli, runtime


def main(argv: list[str] | None = None) -> int:
    """Run network-free ``scope`` or refuse retired direct ``run`` before composition."""

    args = cli._parser().parse_args(argv)  # argparse exits on --help / a bad subcommand
    if args.command != "run":
        return cli.main(argv)  # scope (or any non-run command) — no runtime composed
    return runtime.refuse_legacy_live_execution()


if __name__ == "__main__":
    raise SystemExit(main())
