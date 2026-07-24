"""Private durable-queue Runner with network-free preflight and exact-scope dispatch."""

from __future__ import annotations

import argparse
import contextlib
import copy
import datetime
import ipaddress
import os
import signal
import socket
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import Engine, text

from agentforge.agents.documentation import (
    DocumentationAgent,
    DocumentationInput,
    HostedReportWriter,
)
from agentforge.agents.hosted import HostedConfigurationSet
from agentforge.agents.hosted_policy import (
    HostedGenerationPolicy,
    resolve_hosted_generation_policy,
)
from agentforge.agents.hosted_runtime import (
    HostedExecutionLineage,
    HostedRoleRuntime,
    hosted_judge_identity,
)
from agentforge.agents.judge.calibration_runtime import (
    JudgeCalibrationStatus,
    load_judge_calibration_status,
)
from agentforge.agents.judge.hosted import (
    HostedEvaluator,
    JudgeReconciliation,
    reconcile_judge_assessment,
)
from agentforge.agents.judge.judge import Judge
from agentforge.agents.orchestrator import HostedPlanner, Orchestrator, OrchestratorHalt
from agentforge.agents.red_team import SeedReplayRedTeam
from agentforge.campaign.authorization import RunAuthorization
from agentforge.campaign.binding import TargetBinding
from agentforge.campaign.coordinator import CampaignAbort, RunConfig, SecureCampaignCoordinator
from agentforge.campaign.corpus import (
    LIVE_100_CORPUS_ID,
    MVP_CASE_COUNT,
    MVP_CATEGORIES,
    AuthoredCase,
    AuthoredCorpus,
    resolve_workload,
    verified_case_payload,
)
from agentforge.campaign.manifest import ManifestStore
from agentforge.campaign.runtime import SystemClock, accounting_from_environment, production_engine
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.policy.gateway import RunPolicy, WorkUnitCoordinates
from agentforge.policy.scoped_credentials import (
    CampaignCredentialLease,
    CredentialLeaseExpiredError,
    CredentialResolutionError,
    SealedEnvironmentCredentialResolver,
)
from agentforge.providers.openrouter import HostedUsageLedger, OpenRouterTransport
from agentforge.readiness import expected_alembic_head
from agentforge.regression import RegressionAdmissionGate, RegressionLifecycle
from agentforge.secrets import Secret
from agentforge.storage.queue import JobRecord, LogicalQueue, PostgresJobQueue
from agentforge.target.cassette_adapter import SyntheticCassetteAdapter
from agentforge.target.catalog import SYNTHETIC_TARGET_ID, CatalogEntry, TrustedTargetCatalog
from agentforge.target.openemr_adapter import OpenEmrAdapter
from agentforge.target.spec import (
    AttackSurfaceDefinition,
    AuthMode,
    AuthorizationScope,
    ExecutionProfile,
)
from agentforge.telemetry import OutboundHttpTelemetry

_PAYLOAD_SCHEMA = "campaign.execute"
_PAYLOAD_VERSION = 1
_DEFAULT_LEASE = datetime.timedelta(minutes=10)
_DEFAULT_POLL_SECONDS = 1.0


class DispatchUnavailable(RuntimeError):
    """Persisted work cannot pass every current dispatch gate."""


@dataclass(frozen=True, slots=True)
class PreflightReport:
    """Network-free gate result. Blocker codes are bounded and contain no secret values."""

    blockers: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.blockers

    def require_ready(self) -> None:
        if self.blockers:
            raise DispatchUnavailable("preflight_blocked:" + ",".join(self.blockers))


@dataclass(frozen=True, slots=True)
class PreparedRun:
    authorized: Any
    entry: CatalogEntry
    surface: AttackSurfaceDefinition
    corpus: AuthoredCorpus
    hosted: PreparedHostedRuntime | None = None


@dataclass(frozen=True, slots=True)
class PreparedHostedRuntime:
    """Network-free, authorization-resolved inputs for one campaign's shared model runtime."""

    configuration: HostedConfigurationSet
    generation_policy: HostedGenerationPolicy
    calibration: JudgeCalibrationStatus


@dataclass(frozen=True, slots=True)
class _HostedInvocationContext:
    role: str
    attempt_id: str | None
    detail: Mapping[str, Any]
    ground_truth_verdict: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class _HostedJudgeAttemptContext:
    attempt_id: str
    expected_safe_behavior: str
    parent_execution_id: str


def _evaluator_calibration_state(status: JudgeCalibrationStatus) -> str:
    """Map the durable five-state status to the evaluator's four authority states."""

    if status.state == "enabled":
        return "enabled"
    if status.state == "passed":
        return "passed_pending_human_enablement"
    if status.state in {"failed", "invalidated"}:
        return "failed"
    return "unavailable"


def _reconcile_runner_evaluator(
    *,
    assessment: Mapping[str, Any],
    deterministic_verdict: Mapping[str, Any],
    calibration: JudgeCalibrationStatus,
) -> JudgeReconciliation:
    """Apply the exact externally calibrated authority state at the pre-manifest seam."""

    return reconcile_judge_assessment(
        assessment=assessment,
        deterministic_verdict=deterministic_verdict,
        calibration_state=_evaluator_calibration_state(calibration),
        model_authority_allowed=calibration.model_authoritative,
    )


def _sanitize_hosted_transcript(
    transcript: str,
    *,
    target_credential: Secret | None,
) -> str:
    """Remove the exact sealed target credential before any hosted-model projection."""

    if not isinstance(transcript, str):
        raise DispatchUnavailable("hosted_evaluator_transcript_invalid")
    if target_credential is None:
        return transcript
    if not isinstance(target_credential, Secret) or not target_credential:
        raise DispatchUnavailable("hosted_evaluator_credential_invalid")
    sensitive_value = target_credential.reveal()
    if not sensitive_value:
        raise DispatchUnavailable("hosted_evaluator_credential_invalid")
    sanitized = transcript.replace(sensitive_value, "[REDACTED_TARGET_SESSION]")
    if sensitive_value in sanitized:
        raise DispatchUnavailable("hosted_evaluator_transcript_redaction_failed")
    return sanitized


def _require_hosted_workload_capacity(
    *,
    configuration: HostedConfigurationSet,
    generation_policy: HostedGenerationPolicy,
    case_count: int,
) -> None:
    """Refuse a workload whose cumulative call or token authority is insufficient."""

    required_calls = generation_policy.required_logical_calls(case_count=case_count)
    roles = {role.role: role for role in configuration.roles}

    global_required = {"input": 0, "output": 0, "reasoning": 0}
    global_required_calls = 0
    for role, required in required_calls.items():
        role_configuration = roles.get(role)
        bounds = generation_policy.call_bounds[role]
        if role_configuration is None:
            raise DispatchUnavailable("hosted_role_cap_incompatible")
        attempt_factor = 1 + min(
            role_configuration.limits.max_retries,
            configuration.global_limits.max_retries,
        )
        required_physical_calls = required * attempt_factor
        cumulative = {
            "input": bounds.input_tokens * required_physical_calls,
            "output": bounds.output_tokens * required_physical_calls,
            "reasoning": bounds.reasoning_tokens * required_physical_calls,
        }
        limits = role_configuration.limits
        if (
            limits.max_calls < required_physical_calls
            or cumulative["input"] > limits.max_input_tokens
            or cumulative["output"] > limits.max_output_tokens
            or cumulative["reasoning"] > limits.max_reasoning_tokens
        ):
            raise DispatchUnavailable("hosted_role_cap_incompatible")
        global_required_calls += required_physical_calls
        for token_kind, token_count in cumulative.items():
            global_required[token_kind] += token_count

    global_limits = configuration.global_limits
    if global_limits.max_calls < global_required_calls:
        raise DispatchUnavailable("hosted_global_call_cap_incompatible")
    if (
        global_required["input"] > global_limits.max_input_tokens
        or global_required["output"] > global_limits.max_output_tokens
        or global_required["reasoning"] > global_limits.max_reasoning_tokens
    ):
        raise DispatchUnavailable("hosted_global_token_cap_incompatible")


class _DurableHostedExecutionLifecycle:
    """Single persistence/Langfuse seam used by every hosted role invocation in a run."""

    def __init__(
        self,
        *,
        store: ControlPlaneStore,
        telemetry: OutboundHttpTelemetry,
        run_id: str,
        calibration: JudgeCalibrationStatus,
    ) -> None:
        self._store = store
        self._telemetry = telemetry
        self._run_id = run_id
        self._calibration = calibration
        self._context: _HostedInvocationContext | None = None
        self._execution_context: dict[str, _HostedInvocationContext] = {}
        self._judge_reconciliations: dict[str, JudgeReconciliation] = {}

    @contextlib.contextmanager
    def invocation(
        self,
        *,
        role: str,
        attempt_id: str | None = None,
        detail: Mapping[str, Any] | None = None,
        ground_truth_verdict: Mapping[str, Any] | None = None,
    ) -> Iterator[None]:
        if self._context is not None:
            raise DispatchUnavailable("hosted_invocation_context_overlap")
        if role != "judge" and ground_truth_verdict is not None:
            raise DispatchUnavailable("hosted_ground_truth_role_invalid")
        self._context = _HostedInvocationContext(
            role=role,
            attempt_id=attempt_id,
            detail=dict(detail or {}),
            ground_truth_verdict=(
                dict(ground_truth_verdict) if ground_truth_verdict is not None else None
            ),
        )
        try:
            yield
        finally:
            self._context = None

    def start(
        self,
        *,
        role: str,
        parent_execution_id: str | None,
        input_payload: Mapping[str, Any],
        provider: str,
        model: str,
        upstream_provider: str,
        configuration_sha256: str,
        role_configuration_sha256: str,
        generation_policy_sha256: str,
        judge_calibration_id: str | None,
    ) -> str:
        context = self._context
        if context is None or context.role != role:
            raise DispatchUnavailable("hosted_invocation_context_missing")
        expected_calibration_id = self._calibration.calibration_id if role == "judge" else None
        if judge_calibration_id != expected_calibration_id:
            raise DispatchUnavailable("hosted_judge_calibration_identity_mismatch")
        execution_id = self._store.start_hosted_agent_execution(
            run_id=self._run_id,
            agent_role=role,
            input_payload=input_payload,
            provider=provider,
            model=model,
            upstream_provider=upstream_provider,
            configuration_set_sha256=configuration_sha256,
            role_configuration_sha256=role_configuration_sha256,
            generation_policy_sha256=generation_policy_sha256,
            judge_calibration_id=expected_calibration_id,
            judge_calibration_state=(self._calibration.state if role == "judge" else None),
            attempt_id=context.attempt_id,
            parent_execution_id=parent_execution_id,
            detail=context.detail,
        )
        self._execution_context[execution_id] = context
        try:
            observation_opened = self._telemetry.begin_agent(
                execution_id=execution_id,
                input_payload=dict(input_payload),
            )
        except Exception:
            observation_opened = False
        if observation_opened is not True:
            self._execution_context.pop(execution_id, None)
            try:
                self._store.finish_hosted_agent_execution(
                    execution_id=execution_id,
                    status="failed",
                    output_payload={"status": "failed"},
                    error_code="hosted-langfuse-start-failed",
                    detail={
                        **dict(context.detail),
                        "phase": "hosted_observability_gate",
                    },
                )
            except Exception as exc:
                failure = DispatchUnavailable(
                    "hosted_langfuse_observation_and_terminal_record_unavailable"
                )
                failure.add_note(f"terminal lifecycle failure type: {type(exc).__name__}")
                raise failure from exc
            raise DispatchUnavailable("hosted_langfuse_observation_unavailable")
        return execution_id

    def finish(
        self,
        *,
        execution_id: str,
        status: str,
        output_payload: Mapping[str, Any],
        lineage: HostedExecutionLineage | None,
        error_code: str | None,
        failed_physical_attempts: int | None = None,
    ) -> None:
        context = self._execution_context.pop(execution_id, None)
        if context is None:
            raise DispatchUnavailable("hosted_execution_context_missing")
        oracle_agreement: bool | None = None
        decision_authority: str | None = None
        reconciliation: JudgeReconciliation | None = None
        detail = dict(context.detail)
        if status == "succeeded" and context.role == "judge":
            if lineage is None or context.ground_truth_verdict is None:
                raise DispatchUnavailable("hosted_judge_reconciliation_missing")
            reconciliation = _reconcile_runner_evaluator(
                assessment=output_payload,
                deterministic_verdict=context.ground_truth_verdict,
                calibration=self._calibration,
            )
            oracle_agreement = reconciliation.ground_truth_agreement
            decision_authority = "model" if reconciliation.model_decisive else "oracle"
            detail.update(
                {
                    "calibration_state": self._calibration.state,
                    "decision_authority": decision_authority,
                    "decision_authority_basis": reconciliation.decision_authority,
                    "model_state": output_payload.get("state"),
                    "ground_truth_state": context.ground_truth_verdict.get("state"),
                    "oracle_agreement": oracle_agreement,
                }
            )

        terminal: dict[str, Any] = {
            "execution_id": execution_id,
            "status": status,
            "output_payload": output_payload,
            "oracle_agreement": oracle_agreement,
            "decision_authority": decision_authority,
            "error_code": error_code,
            "detail": detail,
        }
        if lineage is not None:
            if failed_physical_attempts is not None:
                raise DispatchUnavailable("hosted_failure_accounting_conflicts_with_lineage")
            terminal.update(
                {
                    "returned_model": lineage.returned_model,
                    "upstream_provider": lineage.upstream_provider,
                    "provider_request_id": lineage.provider_request_id,
                    "input_tokens": lineage.input_tokens,
                    "output_tokens": lineage.output_tokens,
                    "reasoning_tokens": lineage.reasoning_tokens,
                    "measured_cost_usd": lineage.measured_cost_usd,
                    "configuration_set_sha256": lineage.configuration_sha256,
                    "role_configuration_sha256": lineage.role_configuration_sha256,
                    "generation_policy_sha256": lineage.generation_policy_sha256,
                    "physical_attempts": lineage.physical_attempts,
                }
            )
        elif failed_physical_attempts is not None:
            terminal["physical_attempts"] = failed_physical_attempts
        self._store.finish_hosted_agent_execution(**terminal)
        if reconciliation is not None:
            self._judge_reconciliations[execution_id] = reconciliation
        with contextlib.suppress(Exception):
            self._telemetry.finish_agent(
                execution_id=execution_id,
                output_payload=dict(output_payload),
                error_code=error_code,
            )
        with contextlib.suppress(Exception):
            self._telemetry.flush()
        with contextlib.suppress(Exception):
            self._telemetry.heartbeat()

    def take_judge_reconciliation(self, *, execution_id: str) -> JudgeReconciliation:
        """Consume the exact authority decision already written with a hosted Judge execution."""

        try:
            return self._judge_reconciliations.pop(execution_id)
        except KeyError as exc:
            raise DispatchUnavailable("hosted_judge_reconciliation_missing") from exc


class _PreManifestHostedJudge:
    """Coordinator-injected Judge that reconciles Gemini before immutable manifests are written."""

    def __init__(
        self,
        *,
        deterministic_judge: Judge,
        hosted_evaluator: HostedEvaluator,
        lifecycle: _DurableHostedExecutionLifecycle,
        calibration: JudgeCalibrationStatus,
        target_credential_resolver: Callable[[], Secret | None],
        execution_recorder: Callable[[str, str], None],
    ) -> None:
        self._deterministic_judge = deterministic_judge
        self._hosted_evaluator = hosted_evaluator
        self._lifecycle = lifecycle
        self._calibration = calibration
        self._target_credential_resolver = target_credential_resolver
        self._execution_recorder = execution_recorder
        self._attempt_context: _HostedJudgeAttemptContext | None = None

    @contextlib.contextmanager
    def attempt(
        self,
        *,
        attempt_id: str,
        expected_safe_behavior: str,
        parent_execution_id: str,
    ) -> Iterator[None]:
        """Bind only the current authorized case context to the coordinator callback."""

        if self._attempt_context is not None:
            raise DispatchUnavailable("hosted_judge_attempt_context_overlap")
        if not all(
            isinstance(value, str) and value
            for value in (attempt_id, expected_safe_behavior, parent_execution_id)
        ):
            raise DispatchUnavailable("hosted_judge_attempt_context_invalid")
        self._attempt_context = _HostedJudgeAttemptContext(
            attempt_id=attempt_id,
            expected_safe_behavior=expected_safe_behavior,
            parent_execution_id=parent_execution_id,
        )
        try:
            yield
        finally:
            self._attempt_context = None

    def evaluate(
        self,
        envelope: Mapping[str, Any],
        *,
        integrity_ok: bool = True,
    ) -> dict[str, Any]:
        """Run code ground truth first, then reconcile an independent hosted assessment."""

        context = self._attempt_context
        if context is None:
            raise DispatchUnavailable("hosted_judge_attempt_context_missing")
        deterministic_verdict = self._deterministic_judge.evaluate(
            envelope,
            integrity_ok=integrity_ok,
        )
        if deterministic_verdict.get("attempt_id") != context.attempt_id:
            raise DispatchUnavailable("hosted_judge_attempt_identity_mismatch")

        # An integrity or evidence-contract error is already the decisive fail-closed disposition.
        # Sending unverified/malformed evidence to a provider would violate the hosted evidence
        # boundary, so this exceptional path remains deterministic and network-free.
        if deterministic_verdict.get("state") == "ERROR":
            return dict(deterministic_verdict)

        provider_envelope = copy.deepcopy(dict(envelope))
        hostile = provider_envelope.get("hostile")
        trusted = provider_envelope.get("trusted")
        if not isinstance(hostile, dict) or not isinstance(trusted, dict):
            raise DispatchUnavailable("hosted_evaluator_evidence_invalid")
        hostile["transcript"] = _sanitize_hosted_transcript(
            hostile.get("transcript"),
            target_credential=self._target_credential_resolver(),
        )
        trusted["expected_safe_behavior"] = context.expected_safe_behavior

        with self._lifecycle.invocation(
            role="judge",
            attempt_id=context.attempt_id,
            detail={"phase": "live_pre_manifest_evaluation"},
            ground_truth_verdict=deterministic_verdict,
        ):
            result = self._hosted_evaluator.evaluate(
                provider_envelope,
                integrity_ok=True,
                sanitized=True,
                judge_calibration_id=self._calibration.calibration_id,
                parent_execution_id=context.parent_execution_id,
            )
        reconciliation = self._lifecycle.take_judge_reconciliation(
            execution_id=result.execution_id,
        )
        self._execution_recorder(context.attempt_id, result.execution_id)
        return dict(reconciliation.effective_verdict)


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
    """Compatibility seam proving that adapter construction follows persisted authority."""

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
    if executor is None:
        raise DispatchUnavailable("trusted_execution_composition_missing")
    commit = getattr(control_plane, "record_result_and_complete", None)
    if not callable(commit):
        raise DispatchUnavailable("atomic_result_commit_missing")
    adapter = adapters.resolve(scope)
    result = executor(adapter, authorized, job)
    commit(job, result)
    return result


def _engine(database_url: str) -> Engine:
    return production_engine(database_url)


def _schema_is_current(engine: Engine) -> bool:
    try:
        with engine.connect() as connection:
            current = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
        return current == expected_alembic_head()
    except Exception:
        return False


def _literal_destination_allowed(scope: AuthorizationScope, entry: CatalogEntry) -> bool:
    hostname = (
        scope.exact_host.rsplit(":", 1)[0] if scope.exact_host.count(":") == 1 else scope.exact_host
    )
    lowered = hostname.lower().rstrip(".")
    if lowered == "localhost" or lowered.endswith(".localhost"):
        return entry.transport_policy.allow_private_destination
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return True
    unsafe = not address.is_global
    return not unsafe or entry.transport_policy.allow_private_destination


def _validate_resolved_destination(base_url: str, *, allow_private: bool) -> None:
    """Resolve immediately before dispatch and refuse every non-global address by default."""

    parts = urlsplit(base_url)
    if not parts.hostname:
        raise DispatchUnavailable("target_destination_invalid")
    addresses = {
        item[4][0]
        for item in socket.getaddrinfo(
            parts.hostname,
            parts.port or 443,
            type=socket.SOCK_STREAM,
        )
    }
    if not addresses:
        raise DispatchUnavailable("target_destination_unresolved")
    if not allow_private and any(not ipaddress.ip_address(value).is_global for value in addresses):
        raise DispatchUnavailable("target_destination_private")


def _exact_job_payload(job: JobRecord, authorized: Any) -> bool:
    expected = {
        "authorization_request_id": authorized.run.authorization_request_id,
        "campaign_run_id": authorized.run.run_id,
        "scope_hash": authorized.run.scope_hash,
    }
    return (
        job.payload_schema == _PAYLOAD_SCHEMA
        and job.payload_version == _PAYLOAD_VERSION
        and job.attempt_id == "campaign"
        and job.payload == expected
    )


def _select_authorized_proposal(
    remaining: list[AuthoredCase],
    proposals: list[dict[str, Any]],
    *,
    corpus_id: str,
) -> tuple[AuthoredCase, dict[str, Any]]:
    """Select one proposal without allowing live-100 manifest-order drift."""

    if not remaining or not proposals:
        raise DispatchUnavailable("authorized case proposal is unavailable")
    proposal = proposals[0]
    if corpus_id == LIVE_100_CORPUS_ID:
        expected_case_id = remaining[0].payload.get("case_id")
        ordered_matches = [
            candidate for candidate in proposals if candidate.get("case_ref") == expected_case_id
        ]
        if len(ordered_matches) != 1:
            raise DispatchUnavailable("next manifest-ordered case was not proposed exactly once")
        proposal = ordered_matches[0]
    case_matches = [
        candidate
        for candidate in remaining
        if candidate.payload.get("case_id") == proposal.get("case_ref")
    ]
    if len(case_matches) != 1:
        raise DispatchUnavailable("proposed case is not an exact unique authorized case")
    return case_matches[0], proposal


# The exact document sub-resource read templates the Co-Pilot exposes (document_id / page are
# substituted at the dispatch boundary). Kept as a closed set so a scope can never derive a
# document-read profile for an unlisted path.
_DOCUMENT_READ_PATHS = frozenset(
    {
        "documents/{document_id}/status",
        "documents/{document_id}/extraction-report",
        "documents/{document_id}/readback-verification",
        "documents/{document_id}/pages/{page}",
    }
)


def _scope_payload_profile(*, relative_path: str, method: str, auth_mode: AuthMode) -> str:
    """Derive request shape only from fields included in the authorization scope hash.

    Every profile is a pure function of the surface's ``(relative_path, method, auth_mode)`` — all
    three are bound in the persisted operation hash, so an environment change can never alter the
    request shape after approval. An unrecognized combination fails closed (``DispatchUnavailable``)
    rather than silently falling through to the bearer profile against the Co-Pilot's session API.
    """

    if relative_path in ("health", "ready"):
        if method != "GET":
            raise DispatchUnavailable("public_get_scope_invalid")
        return "copilot_public_get"
    if relative_path == "evidence/search":
        if method != "POST":
            raise DispatchUnavailable("evidence_search_scope_invalid")
        return "copilot_evidence_search"
    if relative_path == "chat":
        if method != "POST" or auth_mode is not AuthMode.SESSION:
            raise DispatchUnavailable("copilot_chat_scope_invalid")
        return "copilot_chat"
    if relative_path == "documents":
        if method != "POST" or auth_mode is not AuthMode.SESSION:
            raise DispatchUnavailable("document_upload_scope_invalid")
        return "copilot_document_upload"
    if relative_path in _DOCUMENT_READ_PATHS:
        if method != "GET" or auth_mode is not AuthMode.SESSION:
            raise DispatchUnavailable("document_read_scope_invalid")
        return "copilot_document_read"
    return "openemr_turns"


def _campaign_session_required_until(authorized: Any, *, now: float) -> datetime.datetime:
    """Return the bounded window a delegated session must cover for this campaign.

    Both the human authorization and delegated session must extend *past* the complete
    authorization-bound run timeout. The Runner never starts a campaign whose approval can expire
    while the campaign is still permitted to run.
    """

    expires_at = getattr(authorized, "expires_at", None)
    scope = getattr(authorized, "scope", None)
    caps = getattr(scope, "caps", None)
    timeout_seconds = getattr(caps, "run_timeout_seconds", None)
    if (
        not isinstance(expires_at, datetime.datetime)
        or expires_at.tzinfo is None
        or not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
    ):
        raise DispatchUnavailable("campaign_session_window_invalid")
    try:
        started_at = datetime.datetime.fromtimestamp(float(now), datetime.UTC)
        timeout_at = started_at + datetime.timedelta(seconds=float(timeout_seconds))
    except (OverflowError, TypeError, ValueError) as exc:
        raise DispatchUnavailable("campaign_session_window_invalid") from exc
    authorization_expires_at = expires_at.astimezone(datetime.UTC)
    if authorization_expires_at <= timeout_at:
        raise DispatchUnavailable("campaign_session_window_invalid")
    return timeout_at


class DurableCampaignRunner:
    """One concurrency-one worker over the existing PostgreSQL queue."""

    def __init__(
        self,
        *,
        engine: Engine,
        environment: str,
        corpus: AuthoredCorpus | None = None,
        catalog: TrustedTargetCatalog | None = None,
        credentials: SealedEnvironmentCredentialResolver | None = None,
        clock: Any | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        manifest_root: str | os.PathLike[str] | None = None,
        telemetry: OutboundHttpTelemetry | None = None,
        judge_calibration_path: str | os.PathLike[str] | None = None,
    ) -> None:
        self.engine = engine
        self.environment = environment
        self.corpus = corpus or resolve_workload()
        self.catalog = catalog or TrustedTargetCatalog.from_environment(environment)
        self.credentials = credentials or SealedEnvironmentCredentialResolver.from_environment()
        self.clock = clock or SystemClock()
        self.sleeper = sleeper
        self.store = ControlPlaneStore(engine, environment=environment)
        self.queue = PostgresJobQueue(
            engine,
            supported_payload_versions={
                LogicalQueue.AGENT_WORK: {_PAYLOAD_SCHEMA: (_PAYLOAD_VERSION,)}
            },
        )
        selected_root = manifest_root or os.environ.get(
            "AGENTFORGE_MANIFEST_DIR", "/tmp/agentforge-manifests"
        )
        self.manifests = ManifestStore(Path(selected_root))
        self.documentation = DocumentationAgent()
        self.orchestrator = Orchestrator()
        self.red_team = SeedReplayRedTeam()
        self.regression_admission = RegressionAdmissionGate()
        self.regression_lifecycle = RegressionLifecycle()
        self.telemetry = telemetry or OutboundHttpTelemetry(
            engine,
            environment=environment,
        )
        configured_calibration_path = os.environ.get("AGENTFORGE_JUDGE_CALIBRATION_PATH")
        self.judge_calibration_path = (
            judge_calibration_path
            if judge_calibration_path is not None
            else configured_calibration_path
        )
        self._campaign_adapter: Any | None = None
        self._hosted_transport: OpenRouterTransport | None = None
        self._last_hosted_readiness_check = 0.0

    def _start_agent_execution(self, **values: Any) -> str:
        """Start the durable ledger row, then fail-soft project the same work to Langfuse."""

        execution_id = self.store.start_agent_execution(**values)
        input_payload = values.get("input_payload")
        if isinstance(input_payload, Mapping):
            with contextlib.suppress(Exception):
                self.telemetry.begin_agent(
                    execution_id=execution_id,
                    input_payload=dict(input_payload),
                )
        return execution_id

    def _finish_agent_execution(self, **values: Any) -> None:
        """Make accounting authoritative before completing its external projection."""

        self.store.finish_agent_execution(**values)
        output_payload = values.get("output_payload")
        if isinstance(output_payload, Mapping):
            with contextlib.suppress(Exception):
                self.telemetry.finish_agent(
                    execution_id=str(values["execution_id"]),
                    output_payload=dict(output_payload),
                    error_code=values.get("error_code"),
                )
            # Bounded checkpoints make agent and preceding target spans visible during a long
            # campaign instead of keeping all delivery state queued until the job returns.
            with contextlib.suppress(Exception):
                self.telemetry.flush()
            with contextlib.suppress(Exception):
                self.telemetry.heartbeat()

    def _bind_agent_execution_attempt(
        self,
        *,
        execution_id: str,
        run_id: str,
        attempt_id: str,
    ) -> None:
        """Bind the selecting Red Team execution once its durable attempt exists."""

        self.store.bind_agent_execution_attempt(
            execution_id=execution_id,
            run_id=run_id,
            attempt_id=attempt_id,
        )
        binder = getattr(self.telemetry, "bind_agent_attempt", None)
        if callable(binder):
            with contextlib.suppress(Exception):
                binder(execution_id=execution_id, attempt_id=attempt_id)

    def _fail_agent_execution_preserving_error(
        self,
        *,
        primary_error: Exception,
        **values: Any,
    ) -> None:
        """Best-effort terminalize a started agent without replacing its primary failure.

        The durable start precedes all agent work. Any later application failure must therefore
        attempt a matching terminal write, but a second failure in that accounting path must not
        hide the error that actually stopped the campaign. Keep the latter as the raised exception
        and attach only a bounded type-level note for diagnosis.
        """

        try:
            self._finish_agent_execution(**values)
        except Exception as finalization_error:
            primary_error.add_note(
                "agent execution terminal finalization also failed "
                f"({type(finalization_error).__name__})"
            )

    def heartbeat_runtime(self, *, force_connection_check: bool = False) -> None:
        """Publish worker health plus sealed-binding readiness per exact configuration hash."""

        self.telemetry.heartbeat(force_connection_check=force_connection_check)
        now = time.monotonic()
        if not force_connection_check and now - self._last_hosted_readiness_check < 30.0:
            return
        self._last_hosted_readiness_check = now
        publisher = getattr(self.telemetry, "hosted_runtime_heartbeat", None)
        if not callable(publisher):
            return
        observability_probe = getattr(
            self.telemetry,
            "hosted_observability_ready",
            None,
        )
        langfuse_ready = bool(observability_probe()) if callable(observability_probe) else False
        with self.engine.connect() as connection:
            rows = connection.execute(
                text("SELECT configuration_sha256, payload FROM hosted_configuration_sets")
            ).mappings()
            for row in rows:
                verified = False
                try:
                    configuration = HostedConfigurationSet.from_payload(dict(row["payload"]))
                    verified = configuration.configuration_sha256 == row[
                        "configuration_sha256"
                    ] and all(
                        self.credentials.has(role.credential_reference)
                        for role in configuration.roles
                    )
                except (TypeError, ValueError):
                    verified = False
                publisher(
                    configuration_sha256=str(row["configuration_sha256"]),
                    provider_bindings_verified=verified,
                    langfuse_observation_ready=langfuse_ready,
                )

    def _hosted_usage_ledger(
        self,
        *,
        organization_id: str,
        run_id: str,
        configuration: HostedConfigurationSet,
        generation_policy: HostedGenerationPolicy,
    ) -> HostedUsageLedger:
        """Restore measured and conservatively unresolved provider exposure.

        A hosted execution row is durable before provider I/O. If a worker dies
        while that row is still running, restart reserves the role's maximum
        authorized attempt count. Terminal attempts without measured usage, plus
        retry attempts preceding one measured response, retain their full
        generation-policy reservation.
        """

        ledger = HostedUsageLedger(configuration)
        with self.engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        "SELECT agent_role, status, physical_attempts, measured_cost, "
                        "input_tokens, output_tokens, reasoning_tokens "
                        "FROM agent_executions WHERE organization_id = :organization_id "
                        "AND campaign_run_id = :run_id "
                        "AND configuration_set_sha256 = :configuration "
                        "AND (status = 'running' OR "
                        "(status IN ('succeeded', 'failed') AND physical_attempts IS NOT NULL))"
                    ),
                    {
                        "organization_id": organization_id,
                        "run_id": run_id,
                        "configuration": configuration.configuration_sha256,
                    },
                )
                .mappings()
                .all()
            )
        rows_by_role: dict[str, list[Mapping[str, Any]]] = {
            role.role: [] for role in configuration.roles
        }
        for row in rows:
            rows_by_role[str(row["agent_role"])].append(row)
        bounds_by_role = generation_policy.call_bounds
        for role_configuration in configuration.roles:
            role = role_configuration.role
            role_rows = rows_by_role[role]
            observed_rows = [
                row
                for row in role_rows
                if row["status"] != "running"
                and row["physical_attempts"] is not None
                and row["input_tokens"] is not None
                and row["output_tokens"] is not None
                and row["reasoning_tokens"] is not None
            ]
            if observed_rows:
                ledger.restore(
                    role,
                    physical_calls=len(observed_rows),
                    measured_usd=sum(
                        (Decimal(str(row["measured_cost"])) for row in observed_rows),
                        Decimal(0),
                    ),
                    input_tokens=sum(int(row["input_tokens"]) for row in observed_rows),
                    output_tokens=sum(int(row["output_tokens"]) for row in observed_rows),
                    reasoning_tokens=sum(int(row["reasoning_tokens"]) for row in observed_rows),
                )
            maximum_attempts = 1 + min(
                role_configuration.limits.max_retries,
                configuration.global_limits.max_retries,
            )
            unresolved_attempts = 0
            for row in role_rows:
                if row["status"] == "running":
                    unresolved_attempts += maximum_attempts
                elif row in observed_rows:
                    unresolved_attempts += max(0, int(row["physical_attempts"]) - 1)
                else:
                    unresolved_attempts += int(row["physical_attempts"])
            bounds = bounds_by_role[role]
            for _ in range(unresolved_attempts):
                ledger.reserve(
                    role,
                    input_tokens=bounds.input_tokens,
                    output_tokens=bounds.output_tokens,
                    reasoning_tokens=bounds.reasoning_tokens,
                )
        return ledger

    def preflight(self, job: JobRecord) -> tuple[PreflightReport, PreparedRun | None]:
        """Report every blocker without constructing an adapter or opening a target socket."""

        blockers: list[str] = []
        if not _schema_is_current(self.engine):
            blockers.append("migration_head_mismatch")
        try:
            self.store.assert_job_lease(job)
        except Exception:
            blockers.append("lease_not_owned")

        authorized: Any | None = None
        try:
            authorized = self.store.load_run_for_execution(job.campaign_run_id)
        except Exception:
            blockers.append("authorization_not_dispatchable")
        if authorized is None:
            return PreflightReport(tuple(dict.fromkeys(blockers))), None

        scope = authorized.scope
        if not _exact_job_payload(job, authorized):
            blockers.append("queue_payload_mismatch")
        same_person = authorized.approval.approver_user_id == authorized.run.launcher_user_id
        if same_person:
            blockers.append("two_person_control_failed")
        if authorized.approval.self_approval_override:
            blockers.append("self_approval_override_disabled")
        if scope.scope_hash() != authorized.run.scope_hash:
            blockers.append("operation_hash_mismatch")
        if (
            scope.corpus_id != self.corpus.corpus_id
            or scope.corpus_hash != self.corpus.content_hash
        ):
            blockers.append("corpus_hash_mismatch")
        verified_payloads: tuple[dict[str, Any], ...] = ()
        try:
            verified_payloads = tuple(verified_case_payload(case) for case in self.corpus.cases)
        except Exception:
            blockers.append("corpus_content_mismatch")
        if len(self.corpus.cases) < MVP_CASE_COUNT or not MVP_CATEGORIES.issubset(
            self.corpus.categories
        ):
            blockers.append("corpus_not_complete")

        entry: CatalogEntry | None = None
        surface: AttackSurfaceDefinition | None = None
        try:
            entry, surface = self.catalog.resolve(
                target_id=scope.target_id,
                surface_id=scope.surface_id,
            )
        except Exception:
            blockers.append("target_catalog_mismatch")
        if entry is not None and surface is not None:
            target = entry.target
            exact = (
                target.version == scope.target_version
                and target.environment is scope.environment
                and target.exact_host == scope.exact_host
                and target.adapter_kind == scope.adapter_kind
                and target.auth_mode is scope.auth_mode
                and target.credential_ref == scope.credential_ref
                and surface.version == scope.surface_version
                and surface.protocol == scope.protocol
                and surface.method == scope.method
                and surface.relative_path == scope.relative_path
                and surface.enabled
            )
            if not exact:
                blockers.append("target_surface_scope_mismatch")
            if not target.synthetic_data_only or not target.synthetic_data_attestation_ref:
                blockers.append("synthetic_data_attestation_missing")
            if not target.canary_refs:
                blockers.append("deterministic_canary_missing")
            if scope.method not in entry.transport_policy.allowed_methods:
                blockers.append("method_not_allowed")
            if not _literal_destination_allowed(scope, entry):
                blockers.append("private_destination_refused")
            try:
                scope_profile = _scope_payload_profile(
                    relative_path=scope.relative_path,
                    method=scope.method,
                    auth_mode=scope.auth_mode,
                )
            except DispatchUnavailable:
                blockers.append("payload_profile_scope_invalid")
            else:
                if scope_profile not in entry.transport_policy.payload_profiles:
                    blockers.append("payload_profile_scope_mismatch")
                if scope_profile == "copilot_document_upload" and (
                    not entry.transport_policy.write_upload_allowed
                    or not entry.transport_policy.allowed_write_resource_refs
                ):
                    # A write/upload surface may dispatch only under an explicit write policy with a
                    # closed set of synthetic write-resource references; otherwise fail closed.
                    blockers.append("write_upload_policy_missing")
            if scope.execution_profile is ExecutionProfile.SYNTHETIC:
                if self.environment == "production" or scope.target_id != SYNTHETIC_TARGET_ID:
                    blockers.append("synthetic_profile_refused")
            elif scope.target_id == SYNTHETIC_TARGET_ID:
                blockers.append("live_profile_cannot_use_cassette")

        caps = scope.caps
        if caps.max_attempts_per_run < len(self.corpus.cases) or not caps.is_within(
            entry.target.safety_caps if entry is not None else caps
        ):
            blockers.append("campaign_caps_incompatible")
        if self.corpus.corpus_id == LIVE_100_CORPUS_ID:
            expected_physical = (
                sum(len(payload["input_sequence"]) for payload in verified_payloads)
                if verified_payloads
                else -1
            )
            if (
                caps.logical_case_limit != len(self.corpus.cases)
                or caps.physical_request_limit != expected_physical
                or caps.target_retries_per_turn != 0
            ):
                blockers.append("exact_request_caps_mismatch")
        if not self.credentials.has(scope.credential_ref):
            blockers.append("credential_reference_unavailable")
        if scope.execution_profile is ExecutionProfile.LIVE and scope.auth_mode is AuthMode.SESSION:
            try:
                required_until = _campaign_session_required_until(
                    authorized,
                    now=self.clock.now(),
                )
            except DispatchUnavailable:
                blockers.append("campaign_session_window_invalid")
            else:
                if not self.credentials.session_ready(
                    scope.credential_ref,
                    required_until=required_until,
                ):
                    blockers.append("credential_session_lease_unavailable")
        if not all(
            callable(getattr(self.store, name, None))
            for name in ("resolve_dispatch", "append_campaign_state", "complete_campaign_job")
        ):
            blockers.append("abort_or_persistence_control_missing")

        hosted: PreparedHostedRuntime | None = None
        if scope.hosted_run is not None:
            try:
                hosted_authority = self.store.load_hosted_role_for_execution(
                    run_id=authorized.run.run_id,
                    agent_role="orchestrator",
                )
                configuration = hosted_authority.configuration
                if hosted_authority.authorization != scope.hosted_run:
                    raise DispatchUnavailable("hosted_authorization_mismatch")
                generation_policy = resolve_hosted_generation_policy(
                    scope.hosted_run.generation_policy_sha256
                )
                _require_hosted_workload_capacity(
                    configuration=configuration,
                    generation_policy=generation_policy,
                    case_count=len(self.corpus.cases),
                )
                for role_configuration in configuration.roles:
                    bounds = generation_policy.call_bounds[role_configuration.role]
                    if bounds.timeout_seconds > scope.hosted_run.provider_timeout_seconds:
                        raise DispatchUnavailable("hosted_role_cap_incompatible")
                if any(
                    not self.credentials.has(role.credential_reference)
                    for role in configuration.roles
                ):
                    raise DispatchUnavailable("hosted_provider_binding_unavailable")
                calibration = load_judge_calibration_status(
                    current_identity=hosted_judge_identity(configuration),
                    configured_path=self.judge_calibration_path,
                )
                hosted = PreparedHostedRuntime(
                    configuration=configuration,
                    generation_policy=generation_policy,
                    calibration=calibration,
                )
            except DispatchUnavailable as exc:
                blockers.append(str(exc))
            except Exception:
                blockers.append("hosted_runtime_authority_invalid")

        report = PreflightReport(tuple(dict.fromkeys(blockers)))
        prepared = (
            PreparedRun(
                authorized=authorized,
                entry=entry,
                surface=surface,
                corpus=self.corpus,
                hosted=hosted,
            )
            if report.ready and entry is not None and surface is not None
            else None
        )
        return report, prepared

    def _adapter(self, prepared: PreparedRun) -> Any:
        scope = prepared.authorized.scope
        target = prepared.entry.target
        if scope.execution_profile is ExecutionProfile.SYNTHETIC:
            return SyntheticCassetteAdapter.for_cases(
                tuple(verified_case_payload(case) for case in prepared.corpus.cases),
                base_url=target.base_url,
            )
        policy = prepared.entry.transport_policy
        # The Clinical Co-Pilot's reviewed Bruno contract is exactly POST /chat with a
        # patient-pinned SMART session carried as ``session_id`` in the JSON body. The catalog
        # selects the profile, but it must equal the profile derived from fields already bound in
        # the persisted operation hash; an environment change cannot alter shape after approval.
        payload_profile = _scope_payload_profile(
            relative_path=prepared.surface.relative_path,
            method=prepared.surface.method,
            auth_mode=scope.auth_mode,
        )
        allowed_profiles = getattr(policy, "payload_profiles", None) or (policy.payload_profile,)
        if payload_profile not in allowed_profiles:
            raise DispatchUnavailable("payload_profile_scope_mismatch")
        return OpenEmrAdapter(
            base_url=target.base_url,
            timeout_seconds=policy.request_timeout_seconds,
            method=prepared.surface.method,
            relative_path=prepared.surface.relative_path,
            payload_profile=payload_profile,
            redirect_policy=policy.redirect_policy,
            response_size_limit_bytes=policy.response_size_limit_bytes,
            allowed_content_types=policy.allowed_content_types,
            destination_validator=lambda base_url: _validate_resolved_destination(
                base_url,
                allow_private=policy.allow_private_destination,
            ),
            telemetry=getattr(self, "telemetry", None),
            # A synthetic-only fixture resolver is required for the copilot_document_upload surface;
            # injected by the composition root and absent (fail-closed) for read-only surfaces.
            fixture_resolver=getattr(self, "fixture_resolver", None),
        )

    def execute_claimed(self, job: JobRecord) -> None:
        """Execute the exact authorized corpus and commit the result before releasing the lease."""
        report, prepared = self.preflight(job)
        report.require_ready()
        if prepared is None:  # defensive: require_ready implies this cannot happen
            raise DispatchUnavailable("preflight_preparation_missing")

        # Adapter construction stays after orchestration and persistence preparation in
        # ``_execute_prepared``.  This preserves the network-free refusal boundary for a campaign
        # that cannot be orchestrated, while the wrapper still owns cleanup on every exit path.
        self._campaign_adapter = None
        self._hosted_transport = None
        credential_lease: CampaignCredentialLease | None = None
        try:
            scope = prepared.authorized.scope
            required_until = _campaign_session_required_until(
                prepared.authorized,
                now=self.clock.now(),
            )
            credential_lease = self.credentials.lease(
                scope.credential_ref,
                required_until=required_until,
                now=lambda: datetime.datetime.fromtimestamp(self.clock.now(), datetime.UTC),
                require_session_metadata=(
                    scope.execution_profile is ExecutionProfile.LIVE
                    and scope.auth_mode is AuthMode.SESSION
                ),
            )
            self._execute_prepared(job, prepared, credential_lease)
        except CredentialLeaseExpiredError as exc:
            raise CampaignAbort(
                "delegated target session cannot cover this campaign",
                code="target-session-expired",
            ) from exc
        except CredentialResolutionError as exc:
            raise CampaignAbort(
                "campaign-scoped target credential is unavailable",
                code="credential-resolution-failed",
            ) from exc
        finally:
            if credential_lease is not None:
                with contextlib.suppress(Exception):
                    credential_lease.release()
            adapter = self._campaign_adapter
            self._campaign_adapter = None
            if adapter is not None:
                close = getattr(adapter, "close", None)
                if callable(close):
                    with contextlib.suppress(Exception):
                        close()
                elif hasattr(adapter, "credential"):
                    # Compatibility for injected adapters without a close protocol.
                    with contextlib.suppress(Exception):
                        adapter.credential = None
            hosted_transport = self._hosted_transport
            self._hosted_transport = None
            if hosted_transport is not None:
                with contextlib.suppress(Exception):
                    hosted_transport.close()

    def _execute_prepared(
        self,
        job: JobRecord,
        prepared: PreparedRun,
        credential_lease: CampaignCredentialLease,
    ) -> None:
        """Run the already-preflighted campaign using its campaign-scoped resources."""

        authorized = prepared.authorized
        scope = authorized.scope
        self.store.append_campaign_state(run_id=job.campaign_run_id, state="running")

        hosted_lifecycle: _DurableHostedExecutionLifecycle | None = None
        hosted_planner: HostedPlanner | None = None
        hosted_evaluator: HostedEvaluator | None = None
        hosted_report_writer: HostedReportWriter | None = None
        if prepared.hosted is not None:
            hosted_lifecycle = _DurableHostedExecutionLifecycle(
                store=self.store,
                telemetry=self.telemetry,
                run_id=authorized.run.run_id,
                calibration=prepared.hosted.calibration,
            )

            def resolve_hosted_credential(reference: str):
                credential = self.credentials.resolve(reference)
                if credential is None:
                    raise CredentialResolutionError(
                        "hosted credential reference is unavailable to this Runner"
                    )
                return credential

            self._hosted_transport = OpenRouterTransport(
                configuration=prepared.hosted.configuration,
                credential_resolver=resolve_hosted_credential,
                ledger=self._hosted_usage_ledger(
                    organization_id=authorized.run.organization_id,
                    run_id=authorized.run.run_id,
                    configuration=prepared.hosted.configuration,
                    generation_policy=prepared.hosted.generation_policy,
                ),
                sleeper=self.sleeper,
            )
            hosted_runtime = HostedRoleRuntime(
                configuration=prepared.hosted.configuration,
                transport=self._hosted_transport,
                authorization=scope.hosted_run,
                call_bounds=prepared.hosted.generation_policy.call_bounds,
                execution_lifecycle=hosted_lifecycle,
            )
            hosted_planner = HostedPlanner(
                runtime=hosted_runtime,
                safety_governor=self.orchestrator,
            )
            hosted_evaluator = HostedEvaluator(runtime=hosted_runtime)
            hosted_report_writer = HostedReportWriter(
                runtime=hosted_runtime,
                canonical_agent=self.documentation,
            )

        case_counts = Counter(
            verified_case_payload(case)["category"] for case in prepared.corpus.cases
        )
        remaining = list(prepared.corpus.cases)
        low_signal_streak = 0
        previous_category: str | None = None
        orchestration_cycle = 0
        next_ordinal = 0
        first_decision_recorded = False
        latest_terminal_execution: str | None = None

        def select_next_work() -> tuple[Any, dict[str, Any], Any, str]:
            """Run one feedback-driven Orchestrator/Red Team cycle over remaining authority."""

            nonlocal orchestration_cycle, next_ordinal, first_decision_recorded
            snapshot = self.store.load_orchestration_snapshot(
                run_id=authorized.run.run_id,
                case_counts=case_counts,
                low_signal_streak=low_signal_streak,
                previous_category=previous_category,
            )
            orchestrator_execution: str
            orchestrator_failure_code = "orchestrator_execution_failed"
            orchestrator_failure_output: dict[str, Any] = {"cycle": orchestration_cycle}
            try:
                try:
                    if hosted_planner is None or hosted_lifecycle is None:
                        orchestrator_execution = self._start_agent_execution(
                            run_id=authorized.run.run_id,
                            agent_role="orchestrator",
                            input_payload={
                                "cycle": orchestration_cycle,
                                "remaining_case_count": len(remaining),
                                "previous_category": previous_category,
                                "low_signal_streak": low_signal_streak,
                                "signal_provenance": snapshot["signal_provenance"],
                            },
                            parent_execution_id=latest_terminal_execution,
                            detail={"phase": "coverage_governance"},
                        )
                        decision = self.orchestrator.decide(snapshot)
                    else:
                        with hosted_lifecycle.invocation(
                            role="orchestrator",
                            detail={
                                "phase": "live_coverage_planning",
                                "cycle": orchestration_cycle,
                            },
                        ):
                            planner_result = hosted_planner.decide(
                                snapshot,
                                parent_execution_id=latest_terminal_execution,
                            )
                        orchestrator_execution = planner_result.execution_id
                        decision = planner_result.decision
                except OrchestratorHalt as exc:
                    orchestrator_failure_code = exc.code
                    orchestrator_failure_output["halt_code"] = exc.code
                    raise CampaignAbort(
                        f"Orchestrator halted before dispatch: {exc.code}", code=exc.code
                    ) from exc
                except Exception as exc:
                    raise CampaignAbort(
                        "Orchestrator could not select authorized work",
                        code="orchestrator_execution_failed",
                    ) from exc

                directive = dict(decision.directive)
                priority_reason = decision.priority_reason
                remaining_categories = {
                    verified_case_payload(case)["category"] for case in remaining
                }
                if directive["category"] not in remaining_categories:
                    coverage = {row["category"]: row for row in snapshot["coverage"]}
                    selected_category = min(
                        remaining_categories,
                        key=lambda category: (
                            coverage[category]["verified_attempt_count"]
                            / coverage[category]["total_case_count"],
                            coverage[category]["verified_attempt_count"],
                            category,
                        ),
                    )
                    directive["category"] = selected_category
                    directive["coverage_goal"] = (
                        f"authorized corpus redirect: execute remaining {selected_category} "
                        "coverage after the higher-priority category was exhausted"
                    )
                    directive["mutation_policy"] = "redirect_to_remaining_authorized_case"
                    priority_reason = f"{priority_reason}_exhausted_redirect"
                if prepared.corpus.corpus_id == LIVE_100_CORPUS_ID:
                    next_category = verified_case_payload(remaining[0])["category"]
                    if directive["category"] != next_category:
                        directive["category"] = next_category
                        directive["coverage_goal"] = (
                            "execute the next instance in the exact authorized manifest order"
                        )
                        directive["mutation_policy"] = "preserve_authorized_manifest_order"
                        priority_reason = f"{priority_reason}_manifest_order"

                if not first_decision_recorded:
                    self.store.record_orchestration_decision(
                        run_id=authorized.run.run_id,
                        directive=directive,
                        signal_sha256=decision.signal_sha256,
                        priority_reason=priority_reason,
                        regression_triggers=decision.regression_triggers,
                    )
                    first_decision_recorded = True
                if hosted_planner is None:
                    self._finish_agent_execution(
                        execution_id=orchestrator_execution,
                        status="succeeded",
                        output_payload={
                            "cycle": orchestration_cycle,
                            "category": directive["category"],
                            "priority_reason": priority_reason,
                            "signal_sha256": decision.signal_sha256,
                            "remaining_case_count": len(remaining),
                        },
                        detail={
                            "phase": "coverage_governance",
                            "regression_trigger_count": len(decision.regression_triggers),
                        },
                    )
            except Exception as exc:
                if hosted_planner is None and "orchestrator_execution" in locals():
                    self._fail_agent_execution_preserving_error(
                        primary_error=exc,
                        execution_id=orchestrator_execution,
                        status="failed",
                        output_payload=orchestrator_failure_output,
                        error_code=orchestrator_failure_code,
                        detail={"phase": "coverage_governance"},
                    )
                raise

            red_team_execution = self._start_agent_execution(
                run_id=authorized.run.run_id,
                agent_role="red_team",
                input_payload={
                    "cycle": orchestration_cycle,
                    "directive_category": directive["category"],
                    "authorized_remaining_case_count": len(remaining),
                    "corpus_sha256": scope.corpus_hash,
                },
                parent_execution_id=orchestrator_execution,
                detail={"phase": "authorized_case_selection"},
            )
            red_team_failure_code = "red_team_execution_failed"
            try:
                try:
                    proposals = self.red_team.propose(
                        cases=[verified_case_payload(case) for case in remaining],
                        directive=directive,
                    )
                    case, proposal = _select_authorized_proposal(
                        remaining,
                        proposals,
                        corpus_id=prepared.corpus.corpus_id,
                    )
                except Exception as exc:
                    red_team_failure_code = "red_team_proposal_failed"
                    raise CampaignAbort(
                        "Red Team could not select an exact authorized case",
                        code="red_team_proposal_failed",
                    ) from exc

                payload = verified_case_payload(case)
                attempt = self.store.ensure_campaign_attempt(
                    run_id=job.campaign_run_id,
                    ordinal=next_ordinal,
                    case_id=payload["case_id"],
                    case_content_hash=case.content_hash,
                    category=payload["category"],
                    severity=payload["severity"]["rating"],
                    attack_class=payload["test_design"]["classification"],
                    owasp_mappings=payload["owasp"],
                    fixture_provenance=payload["fixture_provenance"],
                    source_tool=case.source_tool,
                    source_technique=case.source_technique,
                )
                self._bind_agent_execution_attempt(
                    execution_id=red_team_execution,
                    run_id=authorized.run.run_id,
                    attempt_id=attempt.attempt_id,
                )
                self._finish_agent_execution(
                    execution_id=red_team_execution,
                    status="succeeded",
                    output_payload={
                        "cycle": orchestration_cycle,
                        "case_ref": payload["case_id"],
                        "category": payload["category"],
                        "source_tool": case.source_tool or "headshot-authored",
                        "proposal_count_considered": len(proposals),
                    },
                    detail={"phase": "authorized_case_selection"},
                )
            except Exception as exc:
                self._fail_agent_execution_preserving_error(
                    primary_error=exc,
                    execution_id=red_team_execution,
                    status="failed",
                    output_payload={"cycle": orchestration_cycle},
                    error_code=red_team_failure_code,
                    detail={"phase": "authorized_case_selection"},
                )
                raise
            orchestration_cycle += 1
            next_ordinal += 1
            return case, proposal, attempt, red_team_execution

        # Select the first case before adapter construction. An invalid directive or circuit
        # breaker therefore remains a network-free refusal.
        work = select_next_work()

        binding = TargetBinding(
            target_id=scope.target_id,
            host=scope.exact_host,
            adapter_kind=scope.adapter_kind,
            credential_ref=scope.credential_ref,
            auth_mode=scope.auth_mode.value,
        )
        policy = RunPolicy(**scope.caps.canonical_payload())
        accounting = accounting_from_environment()
        self.telemetry.per_request_cost_usd = accounting.per_call_usd
        authorization = RunAuthorization(
            operation_hash=authorized.run.scope_hash,
            run_nonce=scope.run_nonce,
            deadline=authorized.expires_at.timestamp(),
        )
        last_dispatch_at: float | None = None

        def revalidate(coordinates: str | WorkUnitCoordinates) -> None:
            nonlocal last_dispatch_at
            if last_dispatch_at is not None:
                wait = (1.0 / policy.target_requests_per_second) - (
                    self.clock.now() - last_dispatch_at
                )
                if wait > 0:
                    # Epoch-sized floating-point clocks can round an exact interval a fraction
                    # below the policy minimum. A one-microsecond safety margin preserves (and
                    # slightly tightens) the cap instead of allowing a valid throttled run to
                    # abort nondeterministically after the sleep.
                    self.sleeper(wait + 0.000001)
            self.queue.heartbeat(job, extension=_DEFAULT_LEASE)
            self.store.assert_job_lease(job)
            attempt_id = (
                coordinates.attempt_id
                if isinstance(coordinates, WorkUnitCoordinates)
                else coordinates
            )
            current = self.store.resolve_dispatch(job.campaign_run_id, attempt_id)
            if (
                current.run.scope_hash != authorized.run.scope_hash
                or current.scope.canonical_bytes() != scope.canonical_bytes()
                or current.approval.decision_id != authorized.approval.decision_id
            ):
                raise CampaignAbort("persisted authorization changed", code="authorization_changed")
            # Re-check the pinned session deadline before every physical turn/retry.  Once resolved,
            # this returns the same in-memory Secret and cannot rotate identity mid-campaign.
            credential_lease.resolve(scope.credential_ref)

        def reserve_work_unit(coordinates: WorkUnitCoordinates) -> None:
            revalidate(coordinates.attempt_id)
            self.store.reserve_campaign_work_unit(
                job=job,
                attempt_id=coordinates.attempt_id,
                turn_index=coordinates.turn_index,
                retry_index=coordinates.retry_index,
            )

        def observe_work_unit(coordinates: WorkUnitCoordinates, outcome: str) -> None:
            self.store.observe_campaign_work_unit(
                job=job,
                attempt_id=coordinates.attempt_id,
                turn_index=coordinates.turn_index,
                retry_index=coordinates.retry_index,
                outcome=outcome,
            )

        provenance = (
            "synthetic_offline"
            if scope.execution_profile is ExecutionProfile.SYNTHETIC
            else "live_target"
        )
        current_red_team_execution: str | None = None
        judge_executions: dict[str, str] = {}
        pre_manifest_hosted_judge: _PreManifestHostedJudge | None = None
        if (
            hosted_evaluator is not None
            and hosted_lifecycle is not None
            and prepared.hosted is not None
        ):
            pre_manifest_hosted_judge = _PreManifestHostedJudge(
                deterministic_judge=Judge(),
                hosted_evaluator=hosted_evaluator,
                lifecycle=hosted_lifecycle,
                calibration=prepared.hosted.calibration,
                target_credential_resolver=lambda: credential_lease.resolve(scope.credential_ref),
                execution_recorder=lambda attempt_id, execution_id: judge_executions.__setitem__(
                    attempt_id,
                    execution_id,
                ),
            )

        def start_coordinator_agent_execution(**values: Any) -> str:
            execution_id = self._start_agent_execution(
                run_id=authorized.run.run_id,
                parent_execution_id=current_red_team_execution,
                **values,
            )
            attempt_id = values.get("attempt_id")
            if values.get("agent_role") == "judge" and isinstance(attempt_id, str):
                judge_executions[attempt_id] = execution_id
            return execution_id

        adapter = self._adapter(prepared)
        self._campaign_adapter = adapter
        coordinator = SecureCampaignCoordinator(
            config=RunConfig(
                binding=binding,
                authorization=authorization,
                policy=policy,
                run_nonce=scope.run_nonce,
                canary_token="",
                environment=self.environment,
                corpus_id=scope.corpus_id,
                corpus_sha=scope.corpus_hash,
                authorization_operation_hash=authorized.run.scope_hash,
                campaign_run_id=authorized.run.run_id,
                pre_dispatch_gate=revalidate,
                work_unit_reserver=reserve_work_unit,
                work_unit_observer=observe_work_unit,
                credential_resolver=credential_lease.resolve,
                result_context={
                    "organization_id": authorized.run.organization_id,
                    "target_version": scope.target_version,
                    "surface_id": scope.surface_id,
                    "surface_version": scope.surface_version,
                    "authorization_scope_hash": authorized.run.scope_hash,
                    "execution_profile": scope.execution_profile.value,
                    "evidence_provenance": provenance,
                    "recorder_version": "1",
                    "correlation_id": authorized.run.run_id,
                },
                agent_execution_start=(
                    start_coordinator_agent_execution if hosted_evaluator is None else None
                ),
                agent_execution_finish=(
                    self._finish_agent_execution if hosted_evaluator is None else None
                ),
                dispatch_sleeper=self.sleeper,
            ),
            adapter=adapter,
            engine=self.engine,
            manifests=self.manifests,
            clock=self.clock,
            accounting=accounting,
            judge=pre_manifest_hosted_judge or Judge(),
        )
        while True:
            case, proposal, attempt, current_red_team_execution = work
            dispatch_payload = verified_case_payload(case)
            if pre_manifest_hosted_judge is None:
                outcome = coordinator.run_case(
                    dispatch_payload,
                    attack_attempt=proposal,
                    attempt_id=attempt.attempt_id,
                    red_team_execution_id=current_red_team_execution,
                )
            else:
                with pre_manifest_hosted_judge.attempt(
                    attempt_id=attempt.attempt_id,
                    expected_safe_behavior=str(dispatch_payload["expected_safe_behavior"]),
                    parent_execution_id=current_red_team_execution,
                ):
                    outcome = coordinator.run_case(
                        dispatch_payload,
                        attack_attempt=proposal,
                        attempt_id=attempt.attempt_id,
                        red_team_execution_id=current_red_team_execution,
                    )
            if not outcome.integrity_ok:
                raise CampaignAbort("evidence integrity failed", code="evidence_integrity_failed")
            effective_verdict = outcome.verdict
            finding_id = self.store.record_attempt_outcome(
                run_id=authorized.run.run_id,
                attempt_id=attempt.attempt_id,
                verdict=effective_verdict,
                evidence_content_hash=outcome.result.content_hash,
            )
            if finding_id is not None:
                report_input = self._documentation_input(
                    payload=dispatch_payload,
                    organization_id=authorized.run.organization_id,
                    finding_id=finding_id,
                    campaign_run_id=authorized.run.run_id,
                    attempt_id=attempt.attempt_id,
                    evidence_content_hash=outcome.result.content_hash,
                    confirmation_source=str(
                        effective_verdict.get("confirmation_source", "trusted evidence")
                    ),
                )
                documentation_execution: str | None = None
                if hosted_report_writer is None or hosted_lifecycle is None:
                    documentation_execution = self._start_agent_execution(
                        run_id=authorized.run.run_id,
                        agent_role="documentation",
                        input_payload={
                            "attempt_id": attempt.attempt_id,
                            "finding_id": finding_id,
                            "evidence_content_hash": outcome.result.content_hash,
                            "verdict_state": effective_verdict.get("state"),
                        },
                        attempt_id=attempt.attempt_id,
                        parent_execution_id=judge_executions.get(attempt.attempt_id),
                        detail={
                            "phase": "draft_and_regression_admission",
                            "finding_id": finding_id,
                        },
                    )
                try:
                    if hosted_report_writer is None or hosted_lifecycle is None:
                        report = self.documentation.draft(
                            verdict=effective_verdict,
                            report_input=report_input,
                        )
                    else:
                        with hosted_lifecycle.invocation(
                            role="documentation",
                            attempt_id=attempt.attempt_id,
                            detail={
                                "phase": "live_report_draft",
                                "finding_id": finding_id,
                            },
                        ):
                            report_writer_result = hosted_report_writer.draft(
                                verdict=effective_verdict,
                                report_input=report_input,
                                parent_execution_id=judge_executions.get(attempt.attempt_id),
                            )
                        documentation_execution = report_writer_result.execution_id
                        report = dict(report_writer_result.report)
                    disposition = self.regression_admission.evaluate(
                        verdict=effective_verdict,
                        finding_id=finding_id,
                        report_id=report["report_id"],
                        reproduction_attempted=False,
                        deterministic_reproduction=False,
                        passes_for_right_reason=False,
                        human_approved=False,
                    )
                    oracle_id = outcome.oracle_signal.get("id")
                    if (
                        outcome.oracle_signal.get("hit") is not True
                        or outcome.oracle_signal.get("provenance") != "code"
                        or not isinstance(oracle_id, str)
                        or not oracle_id
                    ):
                        raise CampaignAbort(
                            "confirmed finding lacks a deterministic trusted signal",
                            code="regression_reproduction_signal_missing",
                        )
                    reproduction_plan = self.regression_lifecycle.plan_reproduction(
                        pending_disposition=disposition,
                        report=report,
                        attack_attempt=proposal,
                        source_case_version=str(dispatch_payload["case_version"]),
                        target_id=scope.target_id,
                        target_version=scope.target_version,
                        required_oracle_ids=(oracle_id,),
                    )
                    self.store.record_documentation_outcome(
                        organization_id=authorized.run.organization_id,
                        report=report,
                        regression_disposition=disposition,
                        reproduction_plan=reproduction_plan,
                    )
                except Exception as exc:
                    if hosted_report_writer is None and documentation_execution is not None:
                        self._fail_agent_execution_preserving_error(
                            primary_error=exc,
                            execution_id=documentation_execution,
                            status="failed",
                            output_payload={
                                "attempt_id": attempt.attempt_id,
                                "finding_id": finding_id,
                            },
                            error_code="documentation_execution_failed",
                            detail={"phase": "draft_and_regression_admission"},
                        )
                    raise
                if hosted_report_writer is None:
                    if documentation_execution is None:
                        raise DispatchUnavailable("documentation_execution_identity_missing")
                    self._finish_agent_execution(
                        execution_id=documentation_execution,
                        status="succeeded",
                        output_payload={
                            "attempt_id": attempt.attempt_id,
                            "finding_id": finding_id,
                            "report_id": report["report_id"],
                            "regression_disposition_id": disposition["disposition_id"],
                            "regression_replay_id": reproduction_plan["replay_id"],
                            "publication_state": "blocked_pending_human_approval",
                        },
                        detail={"phase": "draft_and_regression_admission"},
                    )
                if documentation_execution is None:
                    raise DispatchUnavailable("documentation_execution_identity_missing")
                latest_terminal_execution = documentation_execution
            else:
                latest_terminal_execution = judge_executions.get(attempt.attempt_id)
            # The gateway's rate window begins when the physical response finishes.  Anchor the
            # Runner's conservative inter-attempt throttle after the entire attempt has returned
            # and its outcome is durable as well.  Anchoring before dispatch lets a slow response
            # consume the interval, then the next case reaches the gateway immediately after the
            # response and is correctly (but unexpectedly) hard-aborted by its completion-based
            # rate check.
            last_dispatch_at = self.clock.now()
            previous_category = dispatch_payload["category"]
            if effective_verdict.get("state") in {"INDETERMINATE", "ERROR"}:
                low_signal_streak += 1
            else:
                low_signal_streak = 0
            remaining.remove(case)
            if not remaining:
                break
            work = select_next_work()

        self.store.complete_campaign_job(
            job=job,
            measured_cost=accounting.spent_usd,
        )

    @staticmethod
    def _documentation_input(
        *,
        payload: Mapping[str, Any],
        organization_id: str,
        finding_id: str,
        campaign_run_id: str,
        attempt_id: str,
        evidence_content_hash: str,
        confirmation_source: str,
    ) -> DocumentationInput:
        """Build bounded report material without passing target transcripts to Documentation.

        The exact hostile prompt stays in the authorized, versioned corpus and the raw target
        transcript stays in authoritative evidence.  The report receives only a case reference,
        reviewed synthetic-fixture instructions, a content-addressed evidence pointer, and
        authored safe-behavior/security-property text.
        """

        case_id = str(payload["case_id"])
        fixture = payload["fixture_provenance"]
        if (
            fixture.get("classification") != "synthetic"
            or fixture.get("contains_real_phi") is not False
        ):
            raise DispatchUnavailable("documentation_fixture_not_synthetic")
        target_surface = payload["target_surface"]
        severity = payload["severity"]
        test_design = payload["test_design"]
        reproduction = (
            f"Load synthetic fixture {fixture['fixture_id']}@{fixture['fixture_version']}.",
            f"Execute reviewed authored case {case_id} from the authorization-bound corpus.",
            "Compare the trusted oracle/canary result with the expected safe behavior below.",
        )
        return DocumentationInput(
            organization_id=organization_id,
            finding_id=finding_id,
            campaign_run_id=campaign_run_id,
            attempt_id=attempt_id,
            source_case_id=case_id,
            severity=str(severity["rating"]),
            category=str(payload["category"]),
            description=str(target_surface["attack_surface"]),
            clinical_impact=str(severity["rationale"]),
            minimal_reproduction=reproduction,
            observed_behavior=(
                "The independent Judge returned EXPLOIT_CONFIRMED from trusted "
                f"{confirmation_source} evidence; inspect the content-addressed evidence."
            ),
            expected_behavior=str(payload["expected_safe_behavior"]),
            recommended_remediation=(
                "Enforce and regression-test this security property: "
                f"{test_design['security_property']}"
            ),
            evidence_references=(f"evidence://sha256/{evidence_content_hash}",),
            sanitized=True,
        )

    def run_once(self, *, worker_id: str) -> bool:
        """Claim at most one job. Returns false only when no eligible work exists."""

        job = self.queue.claim(
            LogicalQueue.AGENT_WORK,
            worker_id=worker_id,
            lease_duration=_DEFAULT_LEASE,
        )
        if job is None:
            return False
        try:
            self.execute_claimed(job)
        except Exception as exc:
            code = "campaign_execution_failed"
            if isinstance(exc, DispatchUnavailable):
                code = "preflight_blocked"
            elif isinstance(exc, CampaignAbort):
                code = "campaign_aborted"
            state = "aborted" if code != "campaign_execution_failed" else "failed"
            with contextlib.suppress(Exception):
                self.store.append_campaign_state(
                    run_id=job.campaign_run_id,
                    state=state,
                    reason_code=code,
                )
            with contextlib.suppress(Exception):
                self.queue.fail(job, failure_code=code, retryable=False)
            raise DispatchUnavailable(code) from exc
        finally:
            with contextlib.suppress(Exception):
                self.telemetry.flush()
            with contextlib.suppress(Exception):
                self.telemetry.release_campaign(job.campaign_run_id)
        return True


def check_runtime(database_url: str | None = None) -> bool:
    """Check DB/schema/config/corpus readiness without binding a socket or contacting a target."""

    url = database_url if database_url is not None else os.environ.get("DATABASE_URL")
    environment = os.environ.get("AGENTFORGE_ENVIRONMENT")
    if not url or environment not in {"local", "staging", "production"}:
        return False
    try:
        engine = _engine(url)
        return _schema_is_current(engine) and len(resolve_workload().cases) >= MVP_CASE_COUNT
    except Exception:
        return False


def _worker_id() -> str:
    configured = os.environ.get("AGENTFORGE_RUNNER_WORKER_ID", "").strip()
    if configured:
        return configured[:128]
    return f"runner-{os.getpid()}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentforge-runner")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    if args.check:
        return 0 if check_runtime() else 1
    database_url = os.environ.get("DATABASE_URL")
    environment = os.environ.get("AGENTFORGE_ENVIRONMENT")
    if not database_url or environment not in {"local", "staging", "production"}:
        print("runner unavailable: configuration is incomplete", file=sys.stderr)
        return 1
    try:
        runner = DurableCampaignRunner(engine=_engine(database_url), environment=environment)
    except Exception:
        print("runner unavailable: trusted composition failed", file=sys.stderr)
        return 1
    with contextlib.suppress(Exception):
        runner.heartbeat_runtime(force_connection_check=True)
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_args: stop.set())
    try:
        while not stop.is_set():
            with contextlib.suppress(Exception):
                runner.heartbeat_runtime()
            try:
                worked = runner.run_once(worker_id=_worker_id())
            except DispatchUnavailable:
                worked = True
            if args.once:
                break
            if not worked:
                # Retry terminal ledger reads and queued delivery reconciliation even while the
                # campaign queue is idle.
                with contextlib.suppress(Exception):
                    runner.telemetry.flush()
                stop.wait(_DEFAULT_POLL_SECONDS)
    finally:
        with contextlib.suppress(Exception):
            runner.telemetry.shutdown()
    return 0


if __name__ == "__main__":  # pragma: no cover - subprocess/container smoke owns this path
    raise SystemExit(main())


__all__ = [
    "DispatchUnavailable",
    "DurableCampaignRunner",
    "PreflightReport",
    "check_runtime",
    "main",
    "process_agent_work",
]
