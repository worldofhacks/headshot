"""Durable outbound HTTP telemetry with a fail-soft Langfuse exporter.

PostgreSQL is the authoritative request ledger.  Langfuse is an external projection: its SDK is
imported lazily only when complete credentials are present, and exporter failure never changes the
target response or causes a second target dispatch.  Request bodies deliberately contain the
credential-free :class:`TargetRequest` rather than the wire body, so session credentials cannot be
copied into either store.
"""

from __future__ import annotations

import contextlib
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
_STATUS_VALUES = {
    "operational and evidenced",
    "adapter integrated, execution deferred",
    "evaluated and rejected",
    "blocked pending authorization",
}


def _sanitize_text(value: str, redactions: tuple[str, ...]) -> str:
    safe = value
    for secret in redactions:
        if secret:
            safe = safe.replace(secret, "***REDACTED***")
    safe = _JWT.sub("***REDACTED***", safe)
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
        return all(
            os.environ.get(name, "").strip()
            for name in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_BASE_URL")
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
        base = urlsplit(os.environ.get("LANGFUSE_BASE_URL", ""))
        if base.scheme != "https" or not base.hostname or base.username or base.password:
            return False
        return bool(self._client().auth_check())

    def start(
        self,
        *,
        trace_id: str,
        request_payload: dict[str, Any],
        metadata: dict[str, Any],
        measured_cost: float,
    ) -> tuple[Any, Any] | None:
        if not self.configured():
            return None
        manager = self._client().start_as_current_observation(
            trace_context={"trace_id": trace_id},
            as_type="generation",
            name="target-http-request",
            model="openemr-clinical-copilot",
            input=request_payload,
            metadata=metadata,
            version="1",
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
    redactions: tuple[str, ...]
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
        try:
            with self.owner.engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE outbound_http_requests SET status = :status, "
                        "status_code = :status_code, error_code = :error_code, "
                        "response_payload = :response, response_bytes = :response_bytes, "
                        "duration_ms = :duration, langfuse_status = :langfuse_status, "
                        "finished_at = clock_timestamp() WHERE request_id = :request_id"
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
                )
        except Exception:
            # The target call already happened. Never turn a telemetry completion failure into a
            # retry that would send the adversarial request twice.
            _logger.warning("outbound telemetry completion persistence failed")

        metadata = {
            "http.status_code": status_code,
            "duration_ms": duration_ms,
            "request_id": self.request_id,
            "error_code": error_code,
        }
        try:
            self.owner.langfuse.finish(
                self.langfuse_state,
                output=sanitized_response,
                metadata=metadata,
                error_code=error_code,
                measured_cost=self.owner.per_request_cost_usd,
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


class OutboundHttpTelemetry:
    """Tracks every physical live-target request in PostgreSQL and Langfuse."""

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
        self._queued_trace_ids: set[str] = set()
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
        metadata = {str(key): str(value) for key, value in request.metadata.items()}
        organization_id = metadata.get("organization_id", "")
        campaign_run_id = metadata.get("campaign_run_id", "")
        attempt_id = metadata.get("attempt_id", "")
        if not organization_id or not campaign_run_id or not attempt_id:
            raise RuntimeError("outbound telemetry correlation context is incomplete")
        parsed = urlsplit(url)
        request_id = uuid.uuid4().hex
        trace_id = uuid.uuid4().hex
        payload = _sanitize({"turns": list(request.turns)}, redactions)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        configured = self.langfuse.configured()
        with self.engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO outbound_http_requests "
                    "(request_id, organization_id, campaign_run_id, attempt_id, trace_id, "
                    "operation, provider, method, destination_host, relative_path, "
                    "request_payload, request_bytes, measured_cost, langfuse_status) VALUES "
                    "(:request_id, :org, :run_id, :attempt_id, :trace_id, 'target.http', "
                    ":provider, :method, :host, :path, CAST(:payload AS JSONB), :request_bytes, "
                    ":cost, :langfuse_status)"
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
            )

        langfuse_state = None
        langfuse_status = "queued" if configured else "disabled"
        if configured:
            try:
                langfuse_state = self.langfuse.start(
                    trace_id=trace_id,
                    request_payload=payload,
                    metadata={
                        **metadata,
                        "http.method": method,
                        "server.address": parsed.hostname,
                        "url.path": parsed.path,
                    },
                    measured_cost=self.per_request_cost_usd,
                )
                self._queued_trace_ids.add(trace_id)
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
            redactions=redactions,
            langfuse_state=langfuse_state,
            langfuse_status=langfuse_status,
        )

    def flush(self) -> None:
        trace_ids = tuple(self._queued_trace_ids)
        if not trace_ids:
            return
        try:
            self.langfuse.flush()
        except Exception:
            _logger.warning("Langfuse flush failed")
            status = "error"
        else:
            status = "exported"
        with contextlib.suppress(Exception), self.engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE outbound_http_requests SET langfuse_status = :status "
                    "WHERE trace_id = ANY(:trace_ids) AND langfuse_status = 'queued'"
                ),
                {"status": status, "trace_ids": list(trace_ids)},
            )
        self._queued_trace_ids.difference_update(trace_ids)

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
