"""Authorized bounded-run CLI — ``python -m agentforge.campaign run ...`` (M11-coordinator).

The CLI loads the IMMUTABLE binding + caps + a run-scoped authorization off disk, builds the
:class:`~agentforge.campaign.coordinator.SecureCampaignCoordinator`, replays the authored seed
corpus deterministically (M8 seed replay — hosted generation is SKIPPED), and writes the immutable
manifests under the run directory.

WITHOUT a valid authorization it REFUSES (a non-zero exit) — a configured binding + caps is NOT
authorization. The CLI LOADS the persisted, pre-minted grant's own bound operation_hash + run_nonce
(it does not fabricate one); the coordinator independently recomputes the operation hash over the
loaded immutable binding + caps and fail-closed-BLOCKS a stale/expired/out-of-scope grant before any
dispatch. A malformed caps file (unbounded ceiling) or a malformed grant is a fail-closed refusal.

**No network is opened from the CLI's own code.** The bound live adapter is built by an injected
``adapter_factory`` (a fake HTTP client under test); there is no fallback to the P9 fake. The
``main(argv, ...)`` entry mirrors :mod:`agentforge.evals.__main__`: it returns an exit code
(0 success / non-zero refusal), takes no subprocess and opens no socket.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from sqlalchemy import Engine

from agentforge.agents.red_team.seed_replay import load_seed_attempts
from agentforge.campaign.authorization import AuthorizationError, RunAuthorization
from agentforge.campaign.binding import BindingError, TargetBinding
from agentforge.campaign.caps import CapError, RunCaps
from agentforge.campaign.coordinator import (
    CampaignAbort,
    RunConfig,
    SecureCampaignCoordinator,
)
from agentforge.campaign.manifest import ManifestStore

# Exit codes: 0 success, 1 a fail-closed refusal (unauthorized / blocked / malformed caps),
# 2 an operational error (a missing/unreadable input file).
_EXIT_OK = 0
_EXIT_REFUSED = 1
_EXIT_OPERATIONAL = 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m agentforge.campaign")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="run an AUTHORIZED bounded live campaign")
    run.add_argument("--binding", type=Path, required=True, help="immutable binding.json")
    run.add_argument("--caps", type=Path, required=True, help="run caps.json (fail-closed)")
    run.add_argument("--seeds-dir", type=Path, required=True, help="authored seed corpus dir")
    run.add_argument("--run-dir", type=Path, required=True, help="run-scoped manifest root")
    run.add_argument("--run-nonce", type=str, required=True, help="the run instance nonce")
    run.add_argument("--canary", type=str, required=True, help="the synthetic canary token")
    run.add_argument(
        "--corpus-id",
        type=str,
        default="m11-seed-corpus-v1",
        help="the authored-corpus identity the authorization is scoped to (target/surface/corpus)",
    )
    run.add_argument(
        "--authorization",
        type=Path,
        required=False,
        default=None,
        help="a run-scoped authorization.json (REQUIRED to run — a config is not authorization)",
    )
    return parser


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main(
    argv: list[str] | None = None,
    *,
    engine: Engine,
    adapter_factory: Any,
    clock: Any,
    accounting: Any,
    environment: str = "production",
    fallback_adapter: Any | None = None,
) -> int:
    """Run the authorized bounded campaign; return an exit code (0 ok / non-zero refusal).

    All effectful collaborators are injected — the migrated ``engine``, an ``adapter_factory``
    (``factory(base_url=...) -> adapter`` with an injected fake client), and the deterministic
    ``clock`` / ``accounting`` doubles — so the CLI opens no socket and makes no hosted call.
    """
    args = _parser().parse_args(argv)
    if args.command != "run":  # argparse guarantees a subcommand; defensive.
        return _EXIT_OPERATIONAL

    # Load the immutable inputs. A missing/unreadable input file is an operational error.
    try:
        binding_config = _load_json(args.binding)
        caps_config = _load_json(args.caps)
        auth_config = _load_json(args.authorization) if args.authorization is not None else None
    except (OSError, ValueError):
        print("operational-error: could not read a run input file", file=sys.stderr)
        return _EXIT_OPERATIONAL

    # Parse the immutable binding + fail-closed caps. A malformed binding/caps is a REFUSAL — the
    # bounded run never launches unbounded or against an invalid target.
    try:
        binding = TargetBinding(
            target_id=binding_config["target_id"],
            host=binding_config["host"],
            adapter_kind=binding_config["adapter_kind"],
            # Optional: an auth_mode=none binding omits credential_ref (resolves to None).
            credential_ref=binding_config.get("credential_ref"),
        )
        policy = RunCaps.parse(caps_config)
    except (BindingError, CapError, KeyError, TypeError) as exc:
        print(f"refused: invalid binding/caps — {type(exc).__name__}: {exc}", file=sys.stderr)
        return _EXIT_REFUSED

    # The run-scoped authorization is a PERSISTED, pre-minted grant: load its OWN bound
    # operation_hash + run_nonce + deadline from the file — the CLI does NOT recompute or
    # fabricate one. The coordinator independently recomputes the operation hash over the loaded
    # binding+caps and fail-closed-BLOCKS on any scope / nonce / expiry mismatch. WITHOUT a grant,
    # REFUSE — a configured environment is NOT authorization; a malformed grant is a refusal too.
    try:
        authorization = _load_authorization(auth_config)
    except (KeyError, TypeError, ValueError) as exc:
        print(
            f"refused: malformed authorization grant — {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return _EXIT_REFUSED

    # Build the bound live adapter via the injected factory (an injected fake client under test).
    # There is NO fallback to the P9 fake — a blocked live path raises and refuses.
    adapter = adapter_factory(base_url=binding.host_base_url())

    coordinator = SecureCampaignCoordinator(
        config=RunConfig(
            binding=binding,
            authorization=authorization,
            policy=policy,
            run_nonce=args.run_nonce,
            canary_token=args.canary,
            environment=environment,
            corpus_id=args.corpus_id,
        ),
        adapter=adapter,
        engine=engine,
        manifests=ManifestStore(root=args.run_dir),
        clock=clock,
        accounting=accounting,
        fallback_adapter=fallback_adapter,
    )

    # Replay the authored seed corpus deterministically (hosted generation is skipped).
    try:
        seeds = load_seed_attempts(args.seeds_dir)
    except (OSError, ValueError):
        print("operational-error: could not load the seed corpus", file=sys.stderr)
        return _EXIT_OPERATIONAL

    try:
        for attempt in seeds:
            coordinator.run_case(_attempt_to_seed_case(attempt))
    except (AuthorizationError, BindingError, CampaignAbort) as exc:
        # Distinguish a PRE-dispatch gate refusal from a POST-dispatch human-gate stop. If NO
        # dispatch has occurred, this is a fail-closed refusal (unauthorized / blocked binding /
        # unbounded caps) -> non-zero exit. If a dispatch DID occur, the run halted durably on a
        # confirmed finding (human approval gate) -> a SUCCESSFUL bounded run (exit 0); the
        # evidence + manifests are preserved and no publication/remediation was produced.
        if not coordinator.dispatched_any:
            print(f"refused: {type(exc).__name__}: {exc}", file=sys.stderr)
            return _EXIT_REFUSED
        print(f"halted for human approval on a confirmed finding: {exc}", file=sys.stderr)
        return _EXIT_OK

    return _EXIT_OK


def _load_authorization(auth_config: dict[str, Any] | None) -> RunAuthorization | None:
    """Load the PERSISTED, pre-minted run-scoped grant from its file, or ``None`` if none supplied.

    The grant carries its OWN bound ``operation_hash`` + ``run_nonce`` + ``deadline``; the CLI does
    NOT recompute or fabricate them. The coordinator independently recomputes the operation hash
    over the loaded binding+caps and fail-closed-BLOCKS on any scope / nonce / expiry mismatch, so
    a grant minted for a different run config (or nonce) can never authorize THIS run. A ``None``
    means no authorization was supplied — the coordinator refuses it (a config is not
    authorization). A grant missing a bound field raises (caught by the caller as a refusal).
    """
    if auth_config is None:
        return None
    return RunAuthorization(
        operation_hash=str(auth_config["operation_hash"]),
        run_nonce=str(auth_config["run_nonce"]),
        deadline=float(auth_config["deadline"]),
    )


def _attempt_to_seed_case(attempt: dict[str, Any]) -> dict[str, Any]:
    """Shape a replayed attack_attempt back into the seed-case dict the coordinator consumes.

    Seed replay already produced the schema-valid attempt; the coordinator re-runs seed_to_attempt
    over a ``{case_id, input_sequence, category}`` case, so map the attempt's fields back to it.
    """
    case: dict[str, Any] = {
        "case_id": attempt["case_ref"],
        "input_sequence": list(attempt["input_sequence"]),
    }
    if "category" in attempt:
        case["category"] = attempt["category"]
    return case


if __name__ == "__main__":  # pragma: no cover - module entry is exercised via __main__.py
    raise SystemExit(main(engine=None, adapter_factory=None, clock=None, accounting=None))  # type: ignore[arg-type]
