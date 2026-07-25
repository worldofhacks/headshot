#!/usr/bin/env python3
"""Execute ONE governed, target-bound four-role acceptance run; print only safe identities.

This is the production entrypoint for the governed composition. Unlike
``run_hosted_agent_acceptance.py`` (target-free), this run DOES reach a target — exactly once,
through the Policy Gateway — so every authority it needs must already exist and is only ever READ
here, never created:

* the four-role hosted configuration set, staged through the authenticated CONFIG_MANAGE path;
* an approved campaign authorization request under two-person control;
* the reviewed case, recomputed from a trusted workload identity in the closed corpus registry; and
* the Judge calibration artifact, from an explicit sealed path — there is deliberately no default
  path and no environment-variable discovery for calibration authority.

Nothing about the attack is free text: the dispatched bytes are recomputed from the reviewed case,
and the target/surface identity, caps and execution profile are read from the APPROVED scope — the
command line cannot name a target, widen a cap, or change a profile.

**Adapter construction is an injected seam, on purpose.** Deriving a LIVE target adapter from a
surface's transport policy is security-critical and already owned by the campaign runner's
preflight (``runner.DurableCampaignRunner._adapter``). Re-deriving it here would create a second
place to get target-dispatch authority wrong, so this entrypoint refuses to invent it: a synthetic
profile is served natively from the reviewed corpus cassette, and a live profile must have its
runner-derived adapter injected by the deployment composition root. Fail-closed is the only safe
default for the one component that is allowed to touch a real clinical system.

Exit codes are distinct so an operator can tell very different outcomes apart:

* ``0`` — the four-role chain completed and produced a draft-only, unpublished report;
* ``2`` — the target was NOT confirmed exploited, so Documentation could not open and the run
  terminated aborted. A real, honest acceptance outcome, not a crash;
* ``1`` — the composition failed for any other reason.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine

from agentforge.campaign.corpus import resolve_workload, verified_case_payload
from agentforge.config import Settings
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.governed_acceptance import (
    GOVERNED_TARGET_CALL_LIMIT,
    GovernedAcceptanceUnconfirmed,
    GovernedTargetDispatch,
    ReviewedCase,
    resolve_reviewed_case,
    run_governed_acceptance,
)
from agentforge.policy.gateway import RunPolicy
from agentforge.policy.scoped_credentials import (
    CredentialResolutionError,
    SealedEnvironmentCredentialResolver,
)
from agentforge.providers.openrouter import HostedUsageLedger, OpenRouterTransport
from agentforge.target.cassette_adapter import SyntheticCassetteAdapter
from agentforge.target.spec import ExecutionProfile
from agentforge.telemetry import OutboundHttpTelemetry

_ORGANIZATION_ID = re.compile(r"\Aorg_[A-Za-z0-9]+\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,119}\Z")

#: Exit code for "the bound target was not confirmed exploited" — not a platform failure.
UNCONFIRMED_EXIT = 2


class GovernedEntrypointError(RuntimeError):
    """The entrypoint could not assemble the run from persisted authority."""


@dataclass(frozen=True, slots=True)
class GovernedDependencies:
    """The remote-service seams a governed run needs, kept injectable for tests and deployment."""

    transport: Any
    telemetry: Any
    adapter: Any
    credential: Any = None


def _database_url() -> str:
    value = os.environ.get("DATABASE_URL", "").strip()
    if not value:
        raise SystemExit("DATABASE_URL is required")
    if value.startswith("postgresql://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql://")
    if value.startswith("postgres://"):
        return "postgresql+psycopg://" + value.removeprefix("postgres://")
    return value


def _arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the governed four-role acceptance over ONE reviewed corpus case against an "
            "already-authorized target."
        )
    )
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--configuration-set-sha256", required=True)
    parser.add_argument("--release-sha256", required=True)
    parser.add_argument("--generation-policy-sha256", required=True)
    parser.add_argument(
        "--authorization-request-id",
        required=True,
        help="An already-approved campaign authorization request (two-person control).",
    )
    parser.add_argument("--workload-id", required=True, help="A trusted workload identity.")
    parser.add_argument("--case-id", required=True, help="The reviewed case to replay.")
    parser.add_argument(
        "--judge-calibration-path",
        required=True,
        help="Absolute path to the sealed judge_calibration artifact. No default, no env lookup.",
    )
    parser.add_argument(
        "--oracle-canary-marker",
        action="append",
        required=True,
        metavar="MARKER",
        help="A reviewed synthetic canary marker; repeat for more than one.",
    )
    parser.add_argument(
        "--expected-corpus-content-hash",
        default=None,
        help="Optional pin: refuse to run if the resolved workload differs from this hash.",
    )
    parser.add_argument("--credential-environment-variable", default="OPENROUTER_API_KEY")
    arguments = parser.parse_args(argv)
    if _ORGANIZATION_ID.fullmatch(arguments.organization_id) is None:
        parser.error("--organization-id must be one Clerk organization ID")
    for field in ("configuration_set_sha256", "release_sha256", "generation_policy_sha256"):
        if _SHA256.fullmatch(getattr(arguments, field)) is None:
            parser.error(f"--{field.replace('_', '-')} must be one lowercase SHA-256 digest")
    if arguments.expected_corpus_content_hash is not None and (
        _SHA256.fullmatch(arguments.expected_corpus_content_hash) is None
    ):
        parser.error("--expected-corpus-content-hash must be one lowercase SHA-256 digest")
    for field in ("workload_id", "case_id"):
        if _IDENTIFIER.fullmatch(getattr(arguments, field)) is None:
            parser.error(f"--{field.replace('_', '-')} is not a bounded identifier")
    if any(not marker.strip() for marker in arguments.oracle_canary_marker):
        parser.error("--oracle-canary-marker must not be blank")
    if not Path(arguments.judge_calibration_path).is_absolute():
        parser.error("--judge-calibration-path must be absolute")
    return arguments


def load_judge_calibration(path: str | Path) -> dict[str, Any]:
    """Read the sealed calibration artifact from one explicit absolute path.

    The artifact is NOT validated here — ``run_governed_acceptance`` puts it through
    ``require_model_judge_enablement``, which is the only thing allowed to decide that the model
    Judge may run for this exact identity.
    """

    candidate = Path(path)
    if not candidate.is_absolute():
        raise GovernedEntrypointError("judge calibration path must be absolute")
    try:
        artifact = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GovernedEntrypointError("judge calibration artifact is unavailable") from exc
    if not isinstance(artifact, dict):
        raise GovernedEntrypointError("judge calibration artifact is not an object")
    return artifact


def build_dependencies(
    *,
    engine: Engine,
    environment: str,
    configuration: Any,
    scope: Any,
    reviewed: ReviewedCase,
    credential_environment_variable: str,
) -> GovernedDependencies:
    """Assemble the real remote seams from persisted authority.

    The provider transport and Langfuse telemetry are real. The target adapter is only built here
    for a SYNTHETIC execution profile, where the cassette is served from the same trusted corpus
    the run replays; a LIVE profile fails closed rather than duplicate the campaign runner's
    transport-policy-derived adapter construction.
    """

    references = {
        role.credential_reference: credential_environment_variable for role in configuration.roles
    }
    resolver = SealedEnvironmentCredentialResolver(references)

    def resolve_credential(reference: str):
        credential = resolver.resolve(reference)
        if credential is None:
            raise CredentialResolutionError("hosted credential reference is unavailable")
        return credential

    if scope.execution_profile is not ExecutionProfile.SYNTHETIC:
        raise GovernedEntrypointError(
            "live-target adapter construction is owned by the campaign runner preflight; "
            "inject the runner-derived adapter through build_dependencies for a live profile"
        )
    corpus = resolve_workload(
        reviewed.corpus_id, expected_content_hash=reviewed.corpus_content_hash
    )
    adapter = SyntheticCassetteAdapter.for_cases(
        tuple(verified_case_payload(case) for case in corpus.cases),
        base_url=f"https://{scope.exact_host}",
    )
    return GovernedDependencies(
        transport=OpenRouterTransport(
            configuration=configuration,
            credential_resolver=resolve_credential,
            ledger=HostedUsageLedger(configuration),
            lineage_recorder=ControlPlaneStore(engine, environment=environment),
        ),
        telemetry=OutboundHttpTelemetry(engine, environment=environment),
        adapter=adapter,
        credential=None,
    )


def main(
    argv: list[str] | None = None,
    *,
    engine: Engine | None = None,
    dependencies: Any = None,
) -> int:
    """Run one governed acceptance. ``engine``/``dependencies`` are seams for an e2e harness."""

    arguments = _arguments(argv)
    settings = Settings.from_env()
    owns_engine = engine is None
    engine = engine if engine is not None else create_engine(_database_url(), pool_pre_ping=True)
    build = dependencies if dependencies is not None else build_dependencies
    result = None
    try:
        store = ControlPlaneStore(engine, environment=settings.environment)
        configuration = store.load_hosted_configuration_set(
            organization_id=arguments.organization_id,
            configuration_set_sha256=arguments.configuration_set_sha256,
            release_sha256=arguments.release_sha256,
        )
        authorization = store.load_authorization_request(
            organization_id=arguments.organization_id,
            request_id=arguments.authorization_request_id,
        )
        scope = _scope_of(authorization)
        # The reviewed case is recomputed and content-verified; never taken as free text.
        reviewed = resolve_reviewed_case(
            workload_id=arguments.workload_id,
            case_id=arguments.case_id,
            expected_corpus_content_hash=arguments.expected_corpus_content_hash,
        )
        built = build(
            engine=engine,
            environment=settings.environment,
            configuration=configuration,
            scope=scope,
            reviewed=reviewed,
            credential_environment_variable=arguments.credential_environment_variable,
        )
        try:
            result = run_governed_acceptance(
                engine=engine,
                environment=settings.environment,
                organization_id=arguments.organization_id,
                authorization_request_id=arguments.authorization_request_id,
                scope_hash=authorization.scope_hash,
                launcher_user_id=authorization.launcher_user_id,
                launcher_session_id=authorization.launcher_session_id,
                configuration=configuration,
                generation_policy_sha256=arguments.generation_policy_sha256,
                reviewed=reviewed,
                oracle_canary_markers=tuple(arguments.oracle_canary_marker),
                dispatch=GovernedTargetDispatch(
                    adapter=built.adapter,
                    clock=_WallClock(),
                    accounting=_MeasuredAccounting(),
                    # One attempt, always: the composition refuses any other policy.
                    run_policy=RunPolicy(
                        budget_usd=scope.caps.budget_usd,
                        max_attempts_per_run=GOVERNED_TARGET_CALL_LIMIT,
                        target_requests_per_second=scope.caps.target_requests_per_second,
                        run_timeout_seconds=scope.caps.run_timeout_seconds,
                    ),
                    target_id=scope.target_id,
                    target_version=scope.target_version,
                    surface_id=scope.surface_id,
                    surface_version=scope.surface_version,
                    execution_profile=str(scope.execution_profile.value),
                    authorization_scope_hash=authorization.scope_hash,
                    credential=built.credential,
                    environment=settings.environment,
                ),
                transport=built.transport,
                telemetry=built.telemetry,
                judge_calibration=load_judge_calibration(arguments.judge_calibration_path),
            )
        finally:
            close = getattr(built.transport, "close", None)
            if callable(close):
                close()
    except GovernedAcceptanceUnconfirmed as exc:
        # Not a crash: the target was not confirmed exploited, so the four-role chain could not
        # complete. Reported explicitly so an operator never reads it as a platform failure.
        print(json.dumps({"status": "unconfirmed", "detail": str(exc)}, sort_keys=True))
        return UNCONFIRMED_EXIT
    finally:
        if owns_engine:
            engine.dispose()
    print(
        json.dumps(
            {
                "status": "complete",
                "run_id": result.run_id,
                "attempt_id": result.attempt_id,
                "organization_id": result.organization_id,
                "verdict_state": result.verdict_state,
                "decision_authority": result.decision_authority,
                "model_decisive": result.model_decisive,
                "ground_truth_agreement": result.ground_truth_agreement,
                "calibration_state": result.calibration_state,
                "execution_ids": list(result.execution_ids),
                "evidence_content_hash": result.evidence_content_hash,
                "target_response_sha256": result.target_response_sha256,
                "target_dispatch_count": result.target_dispatch_count,
                "generated_variant_count": result.generated_variant_count,
                "documentation_report_id": result.documentation_report_id,
                "documentation_publication_state": result.documentation_publication_state,
            },
            sort_keys=True,
        )
    )
    return 0


def _scope_of(authorization: Any) -> Any:
    from agentforge.control_plane.serialization import scope_from_payload

    return scope_from_payload(dict(authorization.scope_payload))


class _WallClock:
    """Wall clock for gateway rate accounting on the single bounded target call."""

    def now(self) -> float:
        return time.time()


class _MeasuredAccounting:
    """Per-call spend accounting for the single bounded target call."""

    def __init__(self) -> None:
        self.per_call_usd = 0.0
        self.spent_usd = 0.0

    def charge(self) -> None:
        self.spent_usd += self.per_call_usd


if __name__ == "__main__":
    raise SystemExit(main())
