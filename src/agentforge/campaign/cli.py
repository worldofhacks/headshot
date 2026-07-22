"""Authorized bounded-run CLI — ``python -m agentforge.campaign {run,scope} …`` (M11-coordinator).

Two network-free subcommands:

* ``scope`` — emit an immutable **authorization-REQUEST** artifact. It loads the exact binding +
  caps + corpus + corpus id + nonce, computes the corpus sha and the canonical operation hash with
  the SAME production functions ``run`` uses, and writes a request naming that hash. It carries NO
  secret/credential value, and it CANNOT approve or mint a :class:`RunAuthorization` — a distinct,
  authenticated Approver (the future Clerk two-person path) must approve that exact hash. This
  command is a request, not an approval.

* ``run`` — replay the authored seed corpus against the bound live target under a run-scoped grant.
  It runs a PREPARE/GATE phase FIRST: parse binding + caps, load and hash the corpus, compute the
  canonical operation hash, and VERIFY the authorization (missing / expired / nonce / scope) —
  BEFORE the live adapter is ever constructed. Only after that gate passes is ``adapter_factory``
  invoked. The coordinator then RE-VERIFIES the same gate per case (defense in depth).

WITHOUT a valid, in-scope grant ``run`` REFUSES (non-zero exit) and NEVER constructs the live
adapter — a configured binding + caps is not authorization. The grant's own bound operation_hash +
run_nonce + deadline are loaded from disk (the CLI fabricates nothing); the coordinator
independently recomputes and fail-closed-BLOCKS a stale/expired/out-of-scope grant.

``main(argv, ...)`` is INJECTION-DRIVEN for ``run``: the engine, ``adapter_factory``, clock, and
accounting are passed in. The CLI's OWN code opens no socket — the only outbound path is the
injected adapter, and only at the first POST-GATE dispatch inside ``run_case``. Tests inject fakes
(fully network-free); the production composition root (:mod:`agentforge.campaign.__main__`) injects
the real engine + a real ``OpenEmrAdapter`` (lazy client). A confirmed exploit does NOT stop the run
(D13):
every case is replayed and confirmed findings are recorded approval-required with publication /
remediation / regression-promotion BLOCKED.

**NOT live-operational yet.** ``run`` accepts a pre-minted ``authorization.json``, but this repo
provides NO authenticated Approver / two-person service that mints one — the ``scope`` command only
*requests*. Until that service exists, a valid approved grant for the exact scope is a BLOCKER, not
merely an operator step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from sqlalchemy import Engine

from agentforge.agents.red_team.seed_replay import corpus_sha256, load_seed_attempts
from agentforge.campaign.authorization import AuthorizationError, RunAuthorization
from agentforge.campaign.binding import BindingError, TargetBinding
from agentforge.campaign.caps import CapError, RunCaps
from agentforge.campaign.coordinator import (
    CampaignAbort,
    RunConfig,
    SecureCampaignCoordinator,
    operation_hash_for,
    verify_authorization_gate,
)
from agentforge.campaign.manifest import ManifestStore

# Exit codes: 0 success, 1 a fail-closed refusal (unauthorized / blocked / malformed caps),
# 2 an operational error (a missing/unreadable input file, or an immutable-artifact collision).
_EXIT_OK = 0
_EXIT_REFUSED = 1
_EXIT_OPERATIONAL = 2

# The marker that stamps a `scope` artifact as a REQUEST, never a grant — `run` refuses to treat a
# file carrying it as an authorization (a request is not approval).
_AUTHORIZATION_REQUEST_ARTIFACT = "authorization-request"


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

    scope = subparsers.add_parser(
        "scope",
        help="emit an immutable authorization-REQUEST for the exact run scope (cannot approve)",
    )
    scope.add_argument("--binding", type=Path, required=True, help="immutable binding.json")
    scope.add_argument("--caps", type=Path, required=True, help="run caps.json (fail-closed)")
    scope.add_argument("--seeds-dir", type=Path, required=True, help="authored seed corpus dir")
    scope.add_argument("--run-nonce", type=str, required=True, help="the run instance nonce")
    scope.add_argument(
        "--corpus-id",
        type=str,
        default="m11-seed-corpus-v1",
        help="the authored-corpus identity the request is scoped to",
    )
    scope.add_argument(
        "--out",
        type=Path,
        required=True,
        help="path to write the immutable authorization-request.json (never overwritten)",
    )
    return parser


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main(
    argv: list[str] | None = None,
    *,
    engine: Engine | None = None,
    adapter_factory: Any | None = None,
    clock: Any | None = None,
    accounting: Any | None = None,
    environment: str = "production",
    fallback_adapter: Any | None = None,
) -> int:
    """Parse argv and dispatch to the ``run`` or ``scope`` command; return an exit code.

    ``run`` needs the injected effectful collaborators (engine / adapter_factory / clock /
    accounting); ``scope`` is pure and needs none. Tests call this directly (injecting fakes for
    ``run``); the production composition root injects the real collaborators for ``run`` only.
    """
    args = _parser().parse_args(argv)
    if args.command == "scope":
        return _scope_command(args)
    if args.command == "run":
        return _run_command(
            args,
            engine=engine,
            adapter_factory=adapter_factory,
            clock=clock,
            accounting=accounting,
            environment=environment,
            fallback_adapter=fallback_adapter,
        )
    return _EXIT_OPERATIONAL  # argparse guarantees a subcommand; defensive.


# ---------------------------------------------------------------------------- run command


def _run_command(
    args: argparse.Namespace,
    *,
    engine: Engine | None,
    adapter_factory: Any | None,
    clock: Any | None,
    accounting: Any | None,
    environment: str,
    fallback_adapter: Any | None,
) -> int:
    """Run the authorized bounded campaign; the live adapter is built ONLY after the gate passes."""
    if engine is None or adapter_factory is None or clock is None or accounting is None:
        print("operational-error: `run` requires a composed runtime", file=sys.stderr)
        return _EXIT_OPERATIONAL

    # Load the immutable inputs. A missing/unreadable input file is an operational error.
    try:
        binding_config = _load_json(args.binding)
        caps_config = _load_json(args.caps)
        auth_config = _load_json(args.authorization) if args.authorization is not None else None
    except (OSError, ValueError):
        print("operational-error: could not read a run input file", file=sys.stderr)
        return _EXIT_OPERATIONAL

    # PREPARE / GATE phase — everything below runs BEFORE the live adapter is constructed. Parse the
    # binding + caps, load + hash the corpus, load the grant, then VERIFY authorization + scope. A
    # refusal here returns WITHOUT ever invoking adapter_factory (no live resource is built for a
    # run that is not authorized for this exact scope).
    try:
        binding = TargetBinding(
            target_id=binding_config["target_id"],
            host=binding_config["host"],
            adapter_kind=binding_config["adapter_kind"],
            # Optional: an auth_mode=none binding omits credential_ref (resolves to None). A
            # credential auth mode (bearer/session/oauth) REQUIRES a matching reference.
            credential_ref=binding_config.get("credential_ref"),
            auth_mode=binding_config.get("auth_mode", "none"),
        )
        policy = RunCaps.parse(caps_config)
    except (BindingError, CapError, KeyError, TypeError) as exc:
        print(f"refused: invalid binding/caps — {type(exc).__name__}: {exc}", file=sys.stderr)
        return _EXIT_REFUSED

    try:
        authorization = _load_authorization(auth_config)
    except (KeyError, TypeError, ValueError) as exc:
        print(
            f"refused: malformed authorization grant — {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return _EXIT_REFUSED

    # Load + hash the corpus the authorization is scoped to (D14) — before the gate, before the run.
    try:
        seeds = load_seed_attempts(args.seeds_dir)
    except (OSError, ValueError):
        print("operational-error: could not load the seed corpus", file=sys.stderr)
        return _EXIT_OPERATIONAL
    corpus_sha = corpus_sha256(seeds)

    # THE GATE — compute the canonical operation hash and verify the grant (missing / expired /
    # nonce / scope) using the SAME production gate the coordinator re-runs per case. A refusal here
    # blocks BEFORE adapter_factory is called.
    try:
        verify_authorization_gate(
            binding,
            policy=policy,
            corpus_id=args.corpus_id,
            corpus_sha=corpus_sha,
            run_nonce=args.run_nonce,
            authorization=authorization,
            now=clock.now(),
        )
    except (AuthorizationError, CampaignAbort) as exc:
        print(f"refused: {type(exc).__name__}: {exc}", file=sys.stderr)
        return _EXIT_REFUSED

    # GATE PASSED — ONLY NOW construct the bound live adapter. In the production composition root
    # the factory returns a real OpenEmrAdapter whose HTTP client is LAZY; constructing it opens no
    # socket (the connection is made at the first post-gate dispatch). No fallback to the P9 fake.
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
            corpus_sha=corpus_sha,
        ),
        adapter=adapter,
        engine=engine,
        manifests=ManifestStore(root=args.run_dir),
        clock=clock,
        accounting=accounting,
        fallback_adapter=fallback_adapter,
    )

    # Replay EVERY case. A confirmed exploit does NOT stop the run (D13): it is recorded
    # approval-required and the campaign continues. Only a fail-closed HARD ABORT halts the run.
    # Each run_case RE-VERIFIES the authorization gate (defense in depth) before it dispatches.
    try:
        for attempt in seeds:
            coordinator.run_case(_attempt_to_seed_case(attempt))
    except (AuthorizationError, BindingError, CampaignAbort) as exc:
        # A PRE-dispatch gate refusal (zero dispatch) is a fail-closed REFUSAL (exit 1). A
        # POST-dispatch HARD ABORT (a gateway cap breach / operator abort after the target was
        # reached) halted the bounded run safely — evidence + manifests preserved, no publication /
        # remediation produced (exit 0).
        if not coordinator.dispatched_any:
            print(f"refused: {type(exc).__name__}: {exc}", file=sys.stderr)
            return _EXIT_REFUSED
        print(f"hard-aborted after dispatch (evidence preserved): {exc}", file=sys.stderr)
        return _EXIT_OK

    pending = len(coordinator.pending_approvals)
    if pending:
        print(
            f"bounded run complete: {pending} confirmed finding(s) recorded and BLOCKED pending "
            "human approval — no publication / remediation / regression-promotion was produced",
            file=sys.stderr,
        )
    return _EXIT_OK


def _load_authorization(auth_config: dict[str, Any] | None) -> RunAuthorization | None:
    """Load the PERSISTED, pre-minted run-scoped grant from its file, or ``None`` if none supplied.

    The grant carries its OWN bound ``operation_hash`` + ``run_nonce`` + ``deadline``; the CLI does
    NOT recompute or fabricate them. A ``scope`` authorization-REQUEST artifact is REFUSED here (it
    is a request, not a grant) so a request can never be renamed into a grant. A ``None`` means no
    authorization was supplied — the coordinator refuses it. A grant missing a bound field raises.
    """
    if auth_config is None:
        return None
    if auth_config.get("artifact") == _AUTHORIZATION_REQUEST_ARTIFACT:
        raise ValueError(
            "this is an authorization-REQUEST artifact, not a grant — a request is not approval; "
            "an authenticated Approver must mint a RunAuthorization for this exact operation_hash"
        )
    return RunAuthorization(
        operation_hash=str(auth_config["operation_hash"]),
        run_nonce=str(auth_config["run_nonce"]),
        deadline=float(auth_config["deadline"]),
    )


def _attempt_to_seed_case(attempt: dict[str, Any]) -> dict[str, Any]:
    """Shape a replayed attack_attempt back into the seed-case dict the coordinator consumes."""
    case: dict[str, Any] = {
        "case_id": attempt["case_ref"],
        "input_sequence": list(attempt["input_sequence"]),
    }
    if "category" in attempt:
        case["category"] = attempt["category"]
    return case


# --------------------------------------------------------------------------- scope command


def _scope_command(args: argparse.Namespace) -> int:
    """Emit an immutable authorization-REQUEST for the exact run scope (cannot approve/mint).

    Computes the corpus sha + canonical operation hash with the SAME production functions ``run``
    uses, writes an immutable request artifact (never overwritten) carrying NO secret/credential
    value, and reports that a distinct authenticated Approver must approve that exact hash. It does
    NOT (and structurally cannot) mint a :class:`RunAuthorization`.
    """
    try:
        binding_config = _load_json(args.binding)
        caps_config = _load_json(args.caps)
    except (OSError, ValueError):
        print("operational-error: could not read a scope input file", file=sys.stderr)
        return _EXIT_OPERATIONAL

    try:
        binding = TargetBinding(
            target_id=binding_config["target_id"],
            host=binding_config["host"],
            adapter_kind=binding_config["adapter_kind"],
            credential_ref=binding_config.get("credential_ref"),
            auth_mode=binding_config.get("auth_mode", "none"),
        )
        policy = RunCaps.parse(caps_config)
    except (BindingError, CapError, KeyError, TypeError) as exc:
        print(f"refused: invalid binding/caps — {type(exc).__name__}: {exc}", file=sys.stderr)
        return _EXIT_REFUSED

    try:
        seeds = load_seed_attempts(args.seeds_dir)
    except (OSError, ValueError):
        print("operational-error: could not load the seed corpus", file=sys.stderr)
        return _EXIT_OPERATIONAL
    corpus_sha = corpus_sha256(seeds)

    op_hash = operation_hash_for(
        binding,
        policy=policy,
        corpus_id=args.corpus_id,
        corpus_sha=corpus_sha,
        run_nonce=args.run_nonce,
    )

    # The request artifact. It names the EXACT operation hash an authenticated Approver must sign;
    # it carries the credential MARKER (a no-auth marker or a ref digest) — never the raw credential
    # reference, never a secret value — and it deliberately carries NO deadline / grant, so it
    # cannot be used as (or silently become) a RunAuthorization.
    request: dict[str, Any] = {
        "artifact": _AUTHORIZATION_REQUEST_ARTIFACT,
        "schema_version": "1",
        "operation_hash": op_hash,
        "run_nonce": args.run_nonce,
        "scope": {
            "target_id": binding.target_id,
            "host": binding.host,
            "adapter_kind": binding.adapter_kind,
            "auth_mode": binding.auth_mode,
            "credential_marker": binding.credential_marker(),
            "corpus_id": args.corpus_id,
            "corpus_sha": corpus_sha,
            "caps": {
                "budget_usd": policy.budget_usd,
                "max_attempts_per_run": policy.max_attempts_per_run,
                "target_requests_per_second": policy.target_requests_per_second,
                "run_timeout_seconds": policy.run_timeout_seconds,
            },
        },
        "notice": (
            "This is an authorization REQUEST, not a grant. It does NOT authorize any run. A "
            "distinct AUTHENTICATED Approver (two-person control) must approve this EXACT "
            "operation_hash before a RunAuthorization can be minted. This command cannot approve "
            "or mint an authorization, and this artifact — carrying no deadline and no grant — is "
            "refused if presented to `run` as an authorization."
        ),
    }
    request["content_hash"] = _canonical_hash(request)

    # IMMUTABLE write — refuse to overwrite an existing artifact (a request once emitted is fixed).
    if args.out.exists():
        print(
            f"operational-error: refusing to overwrite an existing authorization-request at "
            f"{args.out} (a request is immutable)",
            file=sys.stderr,
        )
        return _EXIT_OPERATIONAL
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(request, sort_keys=True, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # Report the hash + the approval requirement (never any secret value).
    print(f"authorization-request written: {args.out}")
    print(f"operation_hash: {op_hash}")
    print(
        "APPROVAL REQUIRED: a distinct authenticated Approver (two-person control) must approve "
        "this EXACT operation_hash. This command cannot approve or mint a RunAuthorization."
    )
    return _EXIT_OK


def _canonical_hash(payload: dict[str, Any]) -> str:
    """Canonical sha256 of the request payload (order-independent; content_hash excluded)."""
    body = {k: v for k, v in payload.items() if k != "content_hash"}
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(canonical).hexdigest()


if __name__ == "__main__":  # pragma: no cover - the real entry is agentforge.campaign.__main__
    from agentforge.campaign.__main__ import main as _composition_main

    raise SystemExit(_composition_main())
