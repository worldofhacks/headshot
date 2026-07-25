"""Durable outbound HTTP telemetry with a fail-soft Langfuse exporter.

PostgreSQL is the authoritative request ledger.  Langfuse is an external projection: its SDK is
imported lazily only when complete credentials are present, and exporter failure never changes the
target response or causes a second target dispatch.  Request bodies deliberately contain the
credential-free :class:`TargetRequest` rather than the wire body, so session credentials cannot be
copied into either store.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import Engine, text

from agentforge.correlation import campaign_trace_id
from agentforge.secrets import looks_like_provider_key, redact_mapping
from agentforge.target.base import TargetRequest

_logger = logging.getLogger("agentforge.telemetry.outbound")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_LABELED_SECRET = re.compile(
    r"(?i)\b(?:access[_ -]?token|api[_ -]?key|authorization|bearer|cookie|credential|"
    r"password|refresh[_ -]?token|secret|session[_ -]?(?:id|token))\b"
    r"\s*[:=]\s*[^\s;,]+"
)
_PROVIDER_KEY = re.compile(r"\bsk-(?:lf-|ant-|or-|proj-)?[A-Za-z0-9_-]{8,}\b")
_AUTHORIZATION_SECRET = re.compile(
    r"(?i)\b(?:authorization\s*[:=]\s*)?(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+"
)
_COOKIE_SECRET = re.compile(r"(?i)\b(?:cookie|set-cookie)\s*:\s*[^\r\n]*")
_URL_USERINFO_SECRET = re.compile(r"(?i)https?://[^\s/@:]+:[^\s/@]+@")
_STATUS_VALUES = {
    "operational and evidenced",
    "adapter integrated, execution deferred",
    "evaluated and rejected",
    "blocked pending authorization",
}
_REQUEST_METADATA_ALLOWLIST = frozenset(
    {
        "organization_id",
        "campaign_run_id",
        "attempt_id",
        "red_team_execution_id",
        "case_id",
        "attack_category",
        "target_id",
        "target_version",
        "surface_id",
        "surface_version",
        "execution_profile",
    }
)


def _sanitize_text(value: str, redactions: tuple[str, ...]) -> str:
    safe = value
    for secret in redactions:
        if secret:
            safe = safe.replace(secret, "***REDACTED***")
    safe = _JWT.sub("***REDACTED***", safe)
    safe = _AUTHORIZATION_SECRET.sub("***REDACTED_AUTHORIZATION***", safe)
    safe = _COOKIE_SECRET.sub("***REDACTED_COOKIE***", safe)
    safe = _URL_USERINFO_SECRET.sub("https://***REDACTED_USERINFO***@", safe)
    safe = _LABELED_SECRET.sub("***REDACTED_LABELED_SECRET***", safe)
    safe = _PROVIDER_KEY.sub("***REDACTED***", safe)
    if looks_like_provider_key(safe.strip()):
        return "***REDACTED***"
    return safe


def _sanitize(value: Any, redactions: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _sanitize(item, redactions) for key, item in redact_mapping(value).items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item, redactions) for item in value]
    if isinstance(value, str):
        return _sanitize_text(value, redactions)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _sanitize_text(str(value), redactions)


class _LangfuseBridge:
    """Lazy SDK wrapper; importing this module alone never imports the external SDK."""

    def __init__(self) -> None:
        self.client: Any | None = None

    @staticmethod
    def configured() -> bool:
        if not all(
            os.environ.get(name, "").strip()
            for name in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_BASE_URL")
        ):
            return False
        try:
            base = urlsplit(os.environ["LANGFUSE_BASE_URL"].strip())
            _ = base.port
        except (KeyError, ValueError):
            return False
        return bool(
            base.scheme == "https"
            and base.hostname
            and not base.username
            and not base.password
            and base.path in {"", "/"}
            and not base.query
            and not base.fragment
        )

    def _client(self) -> Any:
        if self.client is None:
            # Lazy by design: the provider-neutral core and network-free preflight remain
            # external-out.
            from langfuse import get_client

            self.client = get_client()
        return self.client

    def auth_check(self) -> bool:
        if not self.configured():
            return False
        return bool(self._client().auth_check())

    def start(
        self,
        *,
        trace_id: str,
        model: str,
        version: str,
        request_payload: dict[str, Any],
        metadata: dict[str, Any],
        measured_cost: float,
        parent_observation_id: str | None = None,
    ) -> tuple[Any, Any] | None:
        if not self.configured():
            return None
        trace_context = {"trace_id": trace_id}
        if parent_observation_id is not None:
            trace_context["parent_span_id"] = parent_observation_id
        manager = self._client().start_as_current_observation(
            trace_context=trace_context,
            as_type="generation",
            name="target-http-request",
            model=model,
            input=request_payload,
            metadata=metadata,
            version=version,
            cost_details={"total": measured_cost},
        )
        observation = manager.__enter__()
        return manager, observation

    def finish(
        self,
        state: tuple[Any, Any] | None,
        *,
        output: Any,
        metadata: dict[str, Any],
        error_code: str | None,
        measured_cost: float,
    ) -> None:
        if state is None:
            return
        manager, observation = state
        try:
            observation.update(
                output=output,
                metadata=metadata,
                level="ERROR" if error_code else "DEFAULT",
                status_message=error_code,
                cost_details={"total": measured_cost},
            )
        finally:
            if error_code:
                error = RuntimeError(error_code)
                manager.__exit__(RuntimeError, error, error.__traceback__)
            else:
                manager.__exit__(None, None, None)

    def start_agent(
        self,
        *,
        trace_id: str,
        role: str,
        provider: str,
        model: str,
        execution_mode: str,
        version: str,
        input_payload: dict[str, Any],
        metadata: dict[str, Any],
        parent_observation_id: str | None = None,
    ) -> tuple[Any, Any, str, str] | None:
        """Start an agent root plus a cost-bearing runtime generation."""

        if not self.configured():
            return None
        client = self._client()
        trace_context = {"trace_id": trace_id}
        if parent_observation_id is not None:
            trace_context["parent_span_id"] = parent_observation_id
        agent = client.start_observation(
            trace_context=trace_context,
            as_type="agent",
            name=f"agent.{role}",
            input=input_payload,
            metadata=metadata,
            version=version,
        )
        cost_source = (
            "provider_pending" if execution_mode == "hosted_advisory" else "deterministic_zero"
        )
        try:
            generation = agent.start_observation(
                as_type="generation",
                name=f"agent.{role}.runtime",
                model=model,
                input=input_payload,
                metadata={
                    **metadata,
                    "agent.provider": provider,
                    "agent.execution_mode": execution_mode,
                    "cost.source": cost_source,
                },
                version=version,
            )
        except Exception:
            with contextlib.suppress(Exception):
                agent.end()
            raise
        return agent, generation, cost_source, str(agent.id)

    def finish_agent(
        self,
        state: tuple[Any, Any, str, str] | None,
        *,
        output: Any,
        metadata: dict[str, Any],
        error_code: str | None,
        status: str,
        input_tokens: int | None,
        output_tokens: int | None,
        reasoning_tokens: int | None,
        measured_cost: float | None,
        cost_measurement_state: str,
        provider_event_ids: list[str],
        returned_model: str | None,
    ) -> None:
        if state is None:
            return
        agent, generation, cost_source, _observation_id = state
        generation_values: dict[str, Any] = {
            "output": output,
            "metadata": metadata,
            "level": "ERROR" if error_code else "DEFAULT",
            "status_message": error_code or status,
        }
        usage_details = {
            key: value
            for key, value in (
                ("input", input_tokens),
                ("output", output_tokens),
                ("reasoning", reasoning_tokens),
            )
            if value is not None
        }
        if usage_details:
            # The transport normalizes OpenRouter's inclusive completion count into disjoint
            # final-output and reasoning counters before persistence.
            usage_details["total"] = sum(usage_details.values())
            generation_values["usage_details"] = usage_details
        final_cost_source = (
            "deterministic_zero"
            if cost_source == "deterministic_zero"
            else {
                "measured": "provider_measured",
                "partial": "provider_partial_known",
                "not_observed": "unavailable",
                "invalid": "invalid",
            }[cost_measurement_state]
        )
        authoritative_metadata = {
            **metadata,
            "cost.source": final_cost_source,
            "cost.measurement_state": cost_measurement_state,
            "agent.provider_event_ids": provider_event_ids,
        }
        generation_values["metadata"] = authoritative_metadata
        # A deterministic execution has a real, observed cost of zero. For a hosted execution,
        # only attach cost when provider usage/cost accounting was actually returned.
        if cost_measurement_state in {"measured", "partial"} and measured_cost is not None:
            generation_values["cost_details"] = {"total": measured_cost}
        if returned_model is not None:
            generation_values["model"] = returned_model
        generation_ended = False
        agent_ended = False
        try:
            generation.update(**generation_values).end()
            generation_ended = True
            agent.update(
                output=output,
                metadata=authoritative_metadata,
                level="ERROR" if error_code else "DEFAULT",
                status_message=error_code or status,
            ).end()
            agent_ended = True
        finally:
            # The SDK is fail-soft, but ensure a partially updated pair does not remain open if a
            # custom/test bridge raises between child and parent completion.
            if not generation_ended:
                with contextlib.suppress(Exception):
                    generation.end()
            if not agent_ended:
                with contextlib.suppress(Exception):
                    agent.end()

    def flush(self) -> None:
        if self.client is not None:
            self.client.flush()

    def shutdown(self) -> None:
        if self.client is not None:
            self.client.shutdown()


@dataclass
class _RequestHandle:
    owner: OutboundHttpTelemetry
    request_id: str
    trace_id: str
    started_monotonic: float
    measured_cost: float
    redactions: tuple[str, ...]
    metadata: dict[str, Any]
    langfuse_state: tuple[Any, Any] | None
    langfuse_status: str
    finished: bool = field(default=False, init=False)

    def finish(
        self,
        *,
        response_text: str | None,
        status_code: int | None,
        error_code: str | None = None,
    ) -> None:
        if self.finished:
            return
        self.finished = True
        duration_ms = max(0.0, (self.owner.monotonic() - self.started_monotonic) * 1000.0)
        sanitized_response = (
            None if response_text is None else _sanitize_text(response_text, self.redactions)
        )
        response_bytes = (
            None if sanitized_response is None else len(sanitized_response.encode("utf-8"))
        )
        terminal_status = "failed" if error_code else "succeeded"
        langfuse_status = self.langfuse_status
        persisted = True
        canonical_duration_ms = duration_ms
        try:
            with self.owner.engine.begin() as connection:
                canonical_duration_ms = float(
                    connection.execute(
                        text(
                            "UPDATE outbound_http_requests SET status = :status, "
                            "status_code = :status_code, error_code = :error_code, "
                            "response_payload = :response, response_bytes = :response_bytes, "
                            "duration_ms = :duration, langfuse_status = :langfuse_status, "
                            "finished_at = clock_timestamp() WHERE request_id = :request_id "
                            "RETURNING duration_ms"
                        ),
                        {
                            "status": terminal_status,
                            "status_code": status_code,
                            "error_code": error_code,
                            "response": sanitized_response,
                            "response_bytes": response_bytes,
                            "duration": duration_ms,
                            "langfuse_status": langfuse_status,
                            "request_id": self.request_id,
                        },
                    ).scalar_one()
                )
        except Exception:
            # The target call already happened. Never turn a telemetry completion failure into a
            # retry that would send the adversarial request twice.
            persisted = False
            _logger.warning("outbound telemetry completion persistence failed")

        metadata = {
            **self.metadata,
            "http.status_code": status_code,
            "http.response.body.size": response_bytes,
            "http.response.body.sha256": (
                hashlib.sha256(sanitized_response.encode("utf-8")).hexdigest()
                if sanitized_response is not None
                else None
            ),
            "transport.status": terminal_status,
            # PostgreSQL Numeric columns are the authoritative accounting representation. Use
            # the value returned after persistence so Langfuse query-back compares the same
            # rounded value rather than the pre-write floating-point measurement.
            "duration_ms": canonical_duration_ms,
            "request_id": self.request_id,
            "error_code": error_code,
            "ledger.persisted": persisted,
        }
        langfuse_output = (
            None
            if sanitized_response is None
            else {
                "sha256": hashlib.sha256(sanitized_response.encode("utf-8")).hexdigest(),
                "bytes": response_bytes,
            }
        )
        try:
            self.owner.langfuse.finish(
                self.langfuse_state,
                output=langfuse_output,
                metadata=metadata,
                error_code=error_code if persisted else "telemetry_persistence_failed",
                measured_cost=self.measured_cost,
            )
        except Exception:
            _logger.warning("Langfuse observation completion failed")
            with contextlib.suppress(Exception), self.owner.engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE outbound_http_requests SET langfuse_status = 'error' "
                        "WHERE request_id = :request_id"
                    ),
                    {"request_id": self.request_id},
                )
        else:
            if persisted and self.langfuse_state is not None and self.langfuse_status == "queued":
                self.owner._queued_request_ids.add(self.request_id)


@dataclass
class _AgentHandle:
    execution_id: str
    campaign_run_id: str
    role: str
    trace_id: str
    redactions: tuple[str, ...]
    metadata: dict[str, Any]
    langfuse_state: tuple[Any, Any, str, str] | None


@dataclass(frozen=True)
class _PendingAgentFinish:
    """Safe, bounded state retained while a terminal ledger read is retried."""

    error_code: str | None
    output_sha256: str
    output_bytes: int


class OutboundHttpTelemetry:
    """Tracks physical target requests and every runtime agent in PostgreSQL and Langfuse."""

    def __init__(
        self,
        engine: Engine,
        *,
        environment: str,
        per_request_cost_usd: float = 0.01,
        monotonic: Any = time.perf_counter,
    ) -> None:
        self.engine = engine
        self.environment = environment
        self.per_request_cost_usd = max(0.0, float(per_request_cost_usd))
        self.monotonic = monotonic
        self.langfuse = _LangfuseBridge()
        # One campaign trace contains many observations, so delivery is acknowledged by the
        # observation's durable primary key rather than by trace_id.
        self._queued_request_ids: set[str] = set()
        self._queued_agent_execution_ids: set[str] = set()
        self._agent_handles: dict[str, _AgentHandle] = {}
        self._pending_agent_finishes: dict[str, _PendingAgentFinish] = {}
        self._agent_observation_ids: dict[str, str] = {}
        self._agent_campaign_ids: dict[str, str] = {}
        self._agent_attempt_ids: dict[str, str | None] = {}
        self._agent_roles: dict[str, str] = {}
        self._last_connection_check = 0.0

    def begin(
        self,
        *,
        request: TargetRequest,
        method: str,
        url: str,
        provider: str,
        redactions: tuple[str, ...] = (),
    ) -> _RequestHandle:
        metadata = {
            str(key): str(value)
            for key, value in request.metadata.items()
            if str(key) in _REQUEST_METADATA_ALLOWLIST
        }
        organization_id = metadata.get("organization_id", "")
        campaign_run_id = metadata.get("campaign_run_id", "")
        attempt_id = metadata.get("attempt_id", "")
        red_team_execution_id = metadata.get("red_team_execution_id", "")
        if not organization_id or not campaign_run_id or not attempt_id:
            raise RuntimeError("outbound telemetry correlation context is incomplete")
        parsed = urlsplit(url)
        request_id = uuid.uuid4().hex
        trace_id = campaign_trace_id(campaign_run_id)
        payload = _sanitize({"turns": list(request.turns)}, redactions)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        request_sha256 = hashlib.sha256(encoded).hexdigest()
        configured = self.langfuse.configured()
        with self.engine.begin() as connection:
            measured_cost = float(
                connection.execute(
                    text(
                        "INSERT INTO outbound_http_requests "
                        "(request_id, organization_id, campaign_run_id, attempt_id, trace_id, "
                        "operation, provider, method, destination_host, relative_path, "
                        "request_payload, request_bytes, measured_cost, langfuse_status) VALUES "
                        "(:request_id, :org, :run_id, :attempt_id, :trace_id, 'target.http', "
                        ":provider, :method, :host, :path, CAST(:payload AS JSONB), "
                        ":request_bytes, :cost, :langfuse_status) RETURNING measured_cost"
                    ),
                    {
                        "request_id": request_id,
                        "org": organization_id,
                        "run_id": campaign_run_id,
                        "attempt_id": attempt_id,
                        "trace_id": trace_id,
                        "provider": provider,
                        "method": method,
                        "host": parsed.netloc,
                        "path": parsed.path.lstrip("/"),
                        "payload": encoded.decode("utf-8"),
                        "request_bytes": len(encoded),
                        "cost": self.per_request_cost_usd,
                        "langfuse_status": "queued" if configured else "disabled",
                    },
                ).scalar_one()
            )

        langfuse_state = None
        langfuse_status = "queued" if configured else "disabled"
        parent_observation_id: str | None = None
        if red_team_execution_id:
            same_attempt_parent = (
                self._agent_campaign_ids.get(red_team_execution_id) == campaign_run_id
                and self._agent_attempt_ids.get(red_team_execution_id) == attempt_id
                and self._agent_roles.get(red_team_execution_id) == "red_team"
            )
            parent_observation_id = (
                self._agent_observation_ids.get(red_team_execution_id)
                if same_attempt_parent
                else None
            )
            if parent_observation_id is None and configured:
                # Correlation projection must never change or retry target traffic. Keep the
                # durable request, skip an incorrectly rooted external observation, and make the
                # acceptance verifier reject the campaign.
                langfuse_status = "error"
                with contextlib.suppress(Exception), self.engine.begin() as connection:
                    connection.execute(
                        text(
                            "UPDATE outbound_http_requests SET langfuse_status = 'error' "
                            "WHERE request_id = :request_id"
                        ),
                        {"request_id": request_id},
                    )
        langfuse_metadata = _sanitize(
            {
                **metadata,
                "deployment.environment": self.environment,
                "target.provider": provider,
                "http.method": method,
                "http.request.body.size": len(encoded),
                "http.request.body.sha256": request_sha256,
                "server.address": parsed.hostname,
                "url.path": parsed.path,
                "cost.usd": measured_cost,
                "request_id": request_id,
            },
            redactions,
        )
        if configured and langfuse_status == "queued":
            try:
                langfuse_state = self.langfuse.start(
                    trace_id=trace_id,
                    model=provider,
                    version=metadata.get("target_version", "unknown"),
                    request_payload={
                        "sha256": request_sha256,
                        "bytes": len(encoded),
                    },
                    metadata=langfuse_metadata,
                    measured_cost=measured_cost,
                    parent_observation_id=parent_observation_id,
                )
            except Exception:
                _logger.warning("Langfuse observation start failed")
                langfuse_status = "error"
                with contextlib.suppress(Exception), self.engine.begin() as connection:
                    connection.execute(
                        text(
                            "UPDATE outbound_http_requests SET langfuse_status = 'error' "
                            "WHERE request_id = :request_id"
                        ),
                        {"request_id": request_id},
                    )

        return _RequestHandle(
            owner=self,
            request_id=request_id,
            trace_id=trace_id,
            started_monotonic=self.monotonic(),
            measured_cost=measured_cost,
            redactions=redactions,
            metadata=dict(langfuse_metadata),
            langfuse_state=langfuse_state,
            langfuse_status=langfuse_status,
        )

    def begin_agent(
        self,
        *,
        execution_id: str,
        input_payload: dict[str, Any],
        redactions: tuple[str, ...] = (),
    ) -> bool:
        """Project a durable start and report whether a Langfuse observation opened.

        Existing deterministic callers deliberately ignore the boolean and remain fail-soft.
        Hosted provider composition uses it as a fail-before-provider observability gate.
        """

        try:
            with self.engine.begin() as connection:
                row = (
                    connection.execute(
                        text(
                            "SELECT execution_id, organization_id, campaign_run_id, attempt_id, "
                            "parent_execution_id, agent_role, provider, model, execution_mode, "
                            "configuration_version, trace_id, input_sha256, "
                            "configuration_set_sha256, role_configuration_sha256, "
                            "generation_policy_sha256, judge_calibration_id, "
                            "judge_calibration_state "
                            "FROM agent_executions WHERE execution_id = :execution_id"
                        ),
                        {"execution_id": execution_id},
                    )
                    .mappings()
                    .one()
                )
                configured = self.langfuse.configured()
                parent_execution_id = (
                    str(row["parent_execution_id"])
                    if row["parent_execution_id"] is not None
                    else None
                )
                parent_observation_id = (
                    self._agent_observation_ids.get(parent_execution_id)
                    if parent_execution_id is not None
                    and self._agent_campaign_ids.get(parent_execution_id)
                    == str(row["campaign_run_id"])
                    else None
                )
                parent_projection_missing = (
                    configured and parent_execution_id is not None and parent_observation_id is None
                )
                connection.execute(
                    text(
                        "UPDATE agent_executions SET langfuse_status = :status "
                        "WHERE execution_id = :execution_id"
                    ),
                    {
                        "execution_id": execution_id,
                        "status": (
                            "error"
                            if parent_projection_missing
                            else ("queued" if configured else "disabled")
                        ),
                    },
                )
        except Exception:
            _logger.warning("agent telemetry start persistence failed")
            return False

        if parent_projection_missing:
            # A durable parent link must not become an unrelated Langfuse root. Hosted callers
            # treat ``False`` as a pre-provider gate; deterministic callers remain fail-soft while
            # the durable row exposes the projection error for reconciliation.
            _logger.warning("agent telemetry parent observation is unavailable")
            return False

        metadata = _sanitize(
            {
                "deployment.environment": self.environment,
                "organization_id": str(row["organization_id"]),
                "campaign_run_id": str(row["campaign_run_id"]),
                "attempt_id": (str(row["attempt_id"]) if row["attempt_id"] is not None else None),
                "parent_execution_id": (
                    str(row["parent_execution_id"])
                    if row["parent_execution_id"] is not None
                    else None
                ),
                "agent.execution_id": execution_id,
                "agent.role": str(row["agent_role"]),
                "agent.provider": str(row["provider"]),
                "agent.model": str(row["model"]),
                "agent.execution_mode": str(row["execution_mode"]),
                "agent.input_sha256": str(row["input_sha256"]),
                "agent.configuration_set_sha256": (
                    str(row["configuration_set_sha256"])
                    if row["configuration_set_sha256"] is not None
                    else None
                ),
                "agent.role_configuration_sha256": (
                    str(row["role_configuration_sha256"])
                    if row["role_configuration_sha256"] is not None
                    else None
                ),
                "agent.generation_policy_sha256": (
                    str(row["generation_policy_sha256"])
                    if row["generation_policy_sha256"] is not None
                    else None
                ),
                "judge.calibration_id": (
                    str(row["judge_calibration_id"])
                    if row["judge_calibration_id"] is not None
                    else None
                ),
                "judge.calibration_state": (
                    str(row["judge_calibration_state"])
                    if row["judge_calibration_state"] is not None
                    else None
                ),
            },
            redactions,
        )
        langfuse_state = None
        if configured:
            try:
                langfuse_state = self.langfuse.start_agent(
                    trace_id=str(row["trace_id"]),
                    role=str(row["agent_role"]),
                    provider=str(row["provider"]),
                    model=str(row["model"]),
                    execution_mode=str(row["execution_mode"]),
                    version=str(row["configuration_version"]),
                    input_payload={"sha256": str(row["input_sha256"])},
                    metadata=metadata,
                    parent_observation_id=parent_observation_id,
                )
            except Exception:
                _logger.warning("Langfuse agent observation start failed")
                with contextlib.suppress(Exception), self.engine.begin() as connection:
                    connection.execute(
                        text(
                            "UPDATE agent_executions SET langfuse_status = 'error' "
                            "WHERE execution_id = :execution_id"
                        ),
                        {"execution_id": execution_id},
                    )
                return False
        if langfuse_state is not None:
            self._agent_observation_ids[execution_id] = langfuse_state[3]
            self._agent_campaign_ids[execution_id] = str(row["campaign_run_id"])
            self._agent_attempt_ids[execution_id] = (
                str(row["attempt_id"]) if row["attempt_id"] is not None else None
            )
            self._agent_roles[execution_id] = str(row["agent_role"])
        self._agent_handles[execution_id] = _AgentHandle(
            execution_id=execution_id,
            campaign_run_id=str(row["campaign_run_id"]),
            role=str(row["agent_role"]),
            trace_id=str(row["trace_id"]),
            redactions=redactions,
            metadata=dict(metadata),
            langfuse_state=langfuse_state,
        )
        return langfuse_state is not None

    def bind_agent_attempt(self, *, execution_id: str, attempt_id: str) -> None:
        """Update in-process projection metadata after durable Red Team attempt binding."""

        handle = self._agent_handles.get(execution_id)
        if handle is None:
            return
        handle.metadata["attempt_id"] = attempt_id
        if execution_id in self._agent_observation_ids:
            self._agent_attempt_ids[execution_id] = attempt_id

    def finish_agent(
        self,
        *,
        execution_id: str,
        output_payload: dict[str, Any],
        error_code: str | None = None,
    ) -> None:
        """Finish one agent observation from the already-terminal durable accounting row."""

        handle = self._agent_handles.get(execution_id)
        if handle is None:
            return
        if handle.langfuse_state is None:
            self._agent_handles.pop(execution_id, None)
            self._pending_agent_finishes.pop(execution_id, None)
            return
        safe_output = _sanitize(output_payload, handle.redactions)
        encoded_output = json.dumps(
            safe_output,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        pending = _PendingAgentFinish(
            error_code=(
                _sanitize_text(error_code, handle.redactions) if error_code is not None else None
            ),
            output_sha256=hashlib.sha256(encoded_output).hexdigest(),
            output_bytes=len(encoded_output),
        )
        if not self._complete_agent_finish(handle=handle, pending=pending):
            self._pending_agent_finishes[execution_id] = pending

    def _complete_agent_finish(
        self,
        *,
        handle: _AgentHandle,
        pending: _PendingAgentFinish,
    ) -> bool:
        """Complete an agent from its authoritative terminal row.

        ``False`` means only that the ledger read should be retried. Langfuse completion failures
        are terminal for this in-process handle and are reconciled as ``error`` instead.
        """

        execution_id = handle.execution_id
        try:
            with self.engine.connect() as connection:
                row = (
                    connection.execute(
                        text(
                            "SELECT status, duration_ms, input_tokens, output_tokens, "
                            "reasoning_tokens, measured_cost, currency, output_sha256, "
                            "returned_model, upstream_provider, provider_request_id, "
                            "physical_attempts, cost_measurement_state, provider_event_ids, "
                            "oracle_agreement, decision_authority "
                            "FROM agent_executions WHERE execution_id = :execution_id"
                        ),
                        {"execution_id": execution_id},
                    )
                    .mappings()
                    .one()
                )
        except Exception:
            _logger.warning("agent telemetry completion persistence read failed")
            return False
        if str(row["status"]) == "running" or row["output_sha256"] is None:
            _logger.warning("agent telemetry completion row is not terminal")
            return False
        metadata = {
            **handle.metadata,
            "agent.execution_id": execution_id,
            "agent.role": handle.role,
            "agent.status": str(row["status"]),
            "agent.duration_ms": (
                float(row["duration_ms"]) if row["duration_ms"] is not None else None
            ),
            "agent.output_sha256": str(row["output_sha256"]),
            "cost.usd": (float(row["measured_cost"]) if row["measured_cost"] is not None else None),
            "cost.measurement_state": str(row["cost_measurement_state"]),
            "agent.provider_event_ids": list(row["provider_event_ids"]),
            "currency": str(row["currency"]),
            "agent.returned_model": (
                str(row["returned_model"]) if row["returned_model"] is not None else None
            ),
            "agent.upstream_provider": (
                str(row["upstream_provider"]) if row["upstream_provider"] is not None else None
            ),
            "agent.provider_request_id": (
                str(row["provider_request_id"]) if row["provider_request_id"] is not None else None
            ),
            "agent.physical_attempts": row["physical_attempts"],
            "judge.oracle_agreement": row["oracle_agreement"],
            "judge.decision_authority": row["decision_authority"],
            "error_code": pending.error_code,
        }
        try:
            self.langfuse.finish_agent(
                handle.langfuse_state,
                output={"sha256": str(row["output_sha256"])},
                metadata=metadata,
                error_code=pending.error_code,
                status=str(row["status"]),
                input_tokens=row["input_tokens"],
                output_tokens=row["output_tokens"],
                reasoning_tokens=row["reasoning_tokens"],
                measured_cost=(
                    float(row["measured_cost"]) if row["measured_cost"] is not None else None
                ),
                cost_measurement_state=str(row["cost_measurement_state"]),
                provider_event_ids=list(row["provider_event_ids"]),
                returned_model=(
                    str(row["returned_model"]) if row["returned_model"] is not None else None
                ),
            )
        except Exception:
            _logger.warning("Langfuse agent observation completion failed")
            with contextlib.suppress(Exception), self.engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE agent_executions SET langfuse_status = 'error' "
                        "WHERE execution_id = :execution_id"
                    ),
                    {"execution_id": execution_id},
                )
            self._agent_handles.pop(execution_id, None)
            self._pending_agent_finishes.pop(execution_id, None)
            return True
        self._agent_handles.pop(execution_id, None)
        self._pending_agent_finishes.pop(execution_id, None)
        self._queued_agent_execution_ids.add(execution_id)
        return True

    def _drain_pending_agent_finishes(self) -> None:
        """Retry each pending ledger read at most once per flush checkpoint."""

        for execution_id, pending in tuple(self._pending_agent_finishes.items()):
            handle = self._agent_handles.get(execution_id)
            if handle is None or handle.langfuse_state is None:
                self._agent_handles.pop(execution_id, None)
                self._pending_agent_finishes.pop(execution_id, None)
                continue
            self._complete_agent_finish(handle=handle, pending=pending)

    def release_campaign(self, campaign_run_id: str) -> None:
        """Release terminal parent-observation IDs after a campaign checkpoint is flushed."""

        for execution_id, recorded_run_id in tuple(self._agent_campaign_ids.items()):
            if recorded_run_id != campaign_run_id or execution_id in self._agent_handles:
                continue
            self._agent_campaign_ids.pop(execution_id, None)
            self._agent_observation_ids.pop(execution_id, None)
            self._agent_attempt_ids.pop(execution_id, None)
            self._agent_roles.pop(execution_id, None)

    def flush(self) -> None:
        self._drain_pending_agent_finishes()
        request_ids = tuple(self._queued_request_ids)
        agent_execution_ids = tuple(self._queued_agent_execution_ids)
        if not request_ids and not agent_execution_ids:
            return
        try:
            self.langfuse.flush()
        except Exception:
            _logger.warning("Langfuse flush failed")
            try:
                with self.engine.begin() as connection:
                    if request_ids:
                        connection.execute(
                            text(
                                "UPDATE outbound_http_requests SET langfuse_status = 'error' "
                                "WHERE request_id = ANY(:request_ids) "
                                "AND langfuse_status = 'queued'"
                            ),
                            {"request_ids": list(request_ids)},
                        )
                    if agent_execution_ids:
                        connection.execute(
                            text(
                                "UPDATE agent_executions SET langfuse_status = 'error' "
                                "WHERE execution_id = ANY(:execution_ids) "
                                "AND langfuse_status = 'queued'"
                            ),
                            {"execution_ids": list(agent_execution_ids)},
                        )
            except Exception:
                # Retain the identifiers until the durable failure state can be reconciled.
                _logger.warning("Langfuse delivery failure persistence failed")
                return
        else:
            # A non-raising SDK flush is only a local checkpoint. Langfuse/OTel can report
            # exporter failures without raising here, so durable rows remain queued until the
            # exact remote observations are queried back and recorded by the verifier.
            _logger.debug("Langfuse flush completed; remote query-back verification is pending")
        self._queued_request_ids.difference_update(request_ids)
        self._queued_agent_execution_ids.difference_update(agent_execution_ids)

    def heartbeat(self, *, force_connection_check: bool = False) -> None:
        now = self.monotonic()
        self._upsert_component(
            component_id="runner",
            name="Campaign runner",
            kind="worker",
            availability="operational and evidenced",
            detail="private durable-queue worker heartbeat",
        )
        if not force_connection_check and now - self._last_connection_check < 300:
            return
        self._last_connection_check = now
        if not self.langfuse.configured():
            availability = "adapter integrated, execution deferred"
            detail = "Langfuse credentials are not configured"
        else:
            try:
                authenticated = self.langfuse.auth_check()
            except Exception:
                authenticated = False
            availability = (
                "operational and evidenced" if authenticated else "evaluated and rejected"
            )
            detail = (
                "Langfuse Cloud authentication verified"
                if authenticated
                else "Langfuse Cloud authentication rejected"
            )
        self._upsert_component(
            component_id="langfuse",
            name="Langfuse tracing",
            kind="telemetry",
            availability=availability,
            detail=detail,
        )

    def hosted_runtime_heartbeat(
        self,
        *,
        configuration_sha256: str,
        provider_bindings_verified: bool,
        langfuse_observation_ready: bool,
    ) -> None:
        """Publish Runner-only readiness for one exact content-addressed hosted configuration."""

        if (
            not isinstance(configuration_sha256, str)
            or len(configuration_sha256) != 64
            or any(character not in "0123456789abcdef" for character in configuration_sha256)
        ):
            raise ValueError("hosted configuration identity is invalid")
        self._upsert_component(
            component_id=configuration_sha256,
            name="OpenRouter hosted runtime",
            kind="model-runtime",
            availability=(
                "operational and evidenced"
                if provider_bindings_verified and langfuse_observation_ready
                else "blocked pending authorization"
            ),
            detail=(
                "four sealed provider bindings and Langfuse authentication verified by Runner"
                if provider_bindings_verified and langfuse_observation_ready
                else "Langfuse authentication is unavailable for mandatory hosted observations"
                if provider_bindings_verified
                else "one or more sealed provider bindings are unavailable"
            ),
        )

    def hosted_observability_ready(self) -> bool:
        """Return a fresh authenticated Langfuse gate for hosted provider calls."""

        if not self.langfuse.configured():
            return False
        try:
            return self.langfuse.auth_check() is True
        except Exception:
            return False

    def shutdown(self) -> None:
        self.flush()
        with contextlib.suppress(Exception):
            self.langfuse.shutdown()

    def _upsert_component(
        self,
        *,
        component_id: str,
        name: str,
        kind: str,
        availability: str,
        detail: str,
    ) -> None:
        if availability not in _STATUS_VALUES:
            raise ValueError("runtime component availability is invalid")
        with self.engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO runtime_component_status "
                    "(environment, component_id, name, kind, availability, detail) VALUES "
                    "(:environment, :component_id, :name, :kind, :availability, :detail) "
                    "ON CONFLICT (environment, component_id) DO UPDATE SET "
                    "name = EXCLUDED.name, kind = EXCLUDED.kind, "
                    "availability = EXCLUDED.availability, detail = EXCLUDED.detail, "
                    "heartbeat_at = clock_timestamp()"
                ),
                {
                    "environment": self.environment,
                    "component_id": component_id,
                    "name": name,
                    "kind": kind,
                    "availability": availability,
                    "detail": detail,
                },
            )
