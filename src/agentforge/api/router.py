"""Default-deny `/api/v1` routes for the authenticated operator console."""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import AsyncIterator, Mapping
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from agentforge.api.backend import ApiBackend, ApiBackendUnavailable, ApiConflict
from agentforge.api.schemas import CommandResult, EventBatch, ResourceResult
from agentforge.auth.dependencies import require_permissions
from agentforge.auth.errors import AuthenticationUnavailableError, AuthorizationError
from agentforge.auth.permissions import (
    AUDIT_READ,
    CAMPAIGN_ABORT,
    CAMPAIGN_AUTHORIZE,
    CAMPAIGN_LAUNCH,
    CONFIG_MANAGE,
    CONSOLE_READ,
    EVIDENCE_READ,
    FINDINGS_APPROVE,
    FINDINGS_READ,
    FINDINGS_RESOLVE,
    TARGETS_MANAGE,
)
from agentforge.auth.principal import Principal

router = APIRouter(prefix="/api/v1")

ConsolePrincipal = Annotated[Principal, Depends(require_permissions(CONSOLE_READ))]
FindingPrincipal = Annotated[Principal, Depends(require_permissions(CONSOLE_READ, FINDINGS_READ))]
EvidencePrincipal = Annotated[Principal, Depends(require_permissions(CONSOLE_READ, EVIDENCE_READ))]
AuditPrincipal = Annotated[Principal, Depends(require_permissions(CONSOLE_READ, AUDIT_READ))]
LaunchPrincipal = Annotated[Principal, Depends(require_permissions(CAMPAIGN_LAUNCH))]
AuthorizePrincipal = Annotated[Principal, Depends(require_permissions(CAMPAIGN_AUTHORIZE))]
AbortPrincipal = Annotated[Principal, Depends(require_permissions(CAMPAIGN_ABORT))]
FindingApprovePrincipal = Annotated[Principal, Depends(require_permissions(FINDINGS_APPROVE))]
FindingResolvePrincipal = Annotated[Principal, Depends(require_permissions(FINDINGS_RESOLVE))]
TargetPrincipal = Annotated[Principal, Depends(require_permissions(TARGETS_MANAGE))]
ConfigPrincipal = Annotated[Principal, Depends(require_permissions(CONFIG_MANAGE))]

_IDEMPOTENCY_KEY = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{15,127}\Z")
_STREAM_REAUTHENTICATION_SECONDS = 30.0


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CapsInput(_StrictModel):
    budget_usd: float = Field(gt=0)
    max_attempts_per_run: int = Field(gt=0)
    target_requests_per_second: float = Field(gt=0)
    run_timeout_seconds: float = Field(gt=0)


class AuthorizationRequestInput(_StrictModel):
    target_id: str = Field(min_length=1, max_length=64)
    target_version: str = Field(min_length=1, max_length=32)
    surface_id: str = Field(min_length=1, max_length=64)
    surface_version: str = Field(min_length=1, max_length=32)
    corpus_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    corpus_id: str = Field(default="m11-seed-corpus-v1", min_length=1, max_length=64)
    execution_profile: Literal["synthetic", "live"] = "live"
    run_nonce: str = Field(min_length=16, max_length=128)
    caps: CapsInput
    expires_in_seconds: int = Field(default=900, ge=60, le=3600)


class AuthorizationDecisionInput(_StrictModel):
    decision: Literal["approved", "rejected"]


class CampaignLaunchInput(_StrictModel):
    authorization_request_id: str = Field(min_length=1, max_length=64)


class AbortInput(_StrictModel):
    reason: str = Field(min_length=1, max_length=256)


class FindingDecisionInput(_StrictModel):
    decision: Literal["approved", "rejected"]
    rationale: str = Field(min_length=1, max_length=2000)


class FindingResolveInput(_StrictModel):
    rationale: str = Field(min_length=1, max_length=2000)


class OwaspInput(_StrictModel):
    framework: Literal["OWASP Web", "OWASP LLM"]
    version: Literal["2021", "2025"]
    identifier: str = Field(min_length=3, max_length=8)
    name: str = Field(min_length=1, max_length=160)


class TargetInput(_StrictModel):
    target_id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=512)
    version: str = Field(min_length=1, max_length=32)
    adapter_kind: Literal["fake", "openemr"]
    environment: Literal["local", "staging", "production"]
    base_url: str = Field(min_length=1, max_length=2048)
    allowlisted_hosts: tuple[str, ...] = Field(min_length=1, max_length=32)
    auth_mode: Literal["none", "bearer", "session", "oauth"]
    credential_ref: str | None = Field(default=None, max_length=512)
    synthetic_data_only: Literal[True]
    synthetic_data_attestation_ref: str = Field(min_length=1, max_length=512)
    canary_refs: tuple[str, ...] = Field(default=(), max_length=32)
    oracle_refs: tuple[str, ...] = Field(default=(), max_length=32)
    safety_caps: CapsInput


class TargetLifecycleInput(_StrictModel):
    version: str = Field(min_length=1, max_length=32)
    lifecycle: Literal["validating", "ready", "disabled", "archived"]


class SurfaceInput(_StrictModel):
    surface_id: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=32)
    target_version: str = Field(min_length=1, max_length=32)
    kind: Literal[
        "chat",
        "completion",
        "responses",
        "messages",
        "tool",
        "rag",
        "memory",
        "file",
        "action",
        "custom",
    ]
    protocol: str = Field(min_length=1, max_length=32)
    method: str = Field(min_length=1, max_length=32)
    relative_path: str = Field(min_length=1, max_length=1024)
    trust_boundary: str = Field(min_length=1, max_length=64)
    authentication_required: bool
    risk: Literal["low", "medium", "high", "critical"]
    owasp_mappings: tuple[OwaspInput, ...] = Field(min_length=1, max_length=20)
    oracle_refs: tuple[str, ...] = Field(min_length=1, max_length=32)
    enabled: bool


class SurfaceStateInput(_StrictModel):
    version: str = Field(min_length=1, max_length=32)
    enabled: bool


class ConfigValidateInput(_StrictModel):
    agent_name: Literal["red_team", "recorder", "judge", "documentation", "orchestrator"]
    base_version: int = Field(ge=0)
    configuration: dict[str, Any]


class ConfigPublishInput(ConfigValidateInput):
    validation_id: str = Field(min_length=1, max_length=64)
    rationale: str = Field(min_length=1, max_length=2000)


def _backend(request: Request) -> ApiBackend:
    return request.app.state.api_backend


def _resource_response(result: ResourceResult) -> JSONResponse:
    payload = result.model_dump(exclude_none=True)
    payload.setdefault("data", None)
    return JSONResponse(payload, status_code=200)


def _command_response(result: CommandResult) -> JSONResponse:
    status_code = {
        "accepted": 202,
        "completed": 200,
        "unavailable": 503,
        "conflict": 409,
    }[result.status]
    return JSONResponse(result.model_dump(exclude_none=True), status_code=status_code)


def _read(
    request: Request,
    resource: str,
    principal: Principal,
    identifiers: Mapping[str, str] | None = None,
) -> JSONResponse:
    try:
        result = _backend(request).read(resource, principal, identifiers=identifiers)
    except ApiBackendUnavailable:
        result = ResourceResult.unavailable("control_plane_unavailable")
    except Exception:
        result = ResourceResult.error("read_failed")
    return _resource_response(result)


def _idempotency_key(value: str | None) -> str:
    if value is None or _IDEMPOTENCY_KEY.fullmatch(value) is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail="Valid Idempotency-Key required")
    return value


def _command(
    request: Request,
    command: str,
    principal: Principal,
    body: BaseModel,
    idempotency_key: str | None,
    identifiers: Mapping[str, str] | None = None,
) -> JSONResponse:
    key = _idempotency_key(idempotency_key)
    try:
        result = _backend(request).command(
            command,
            principal,
            body.model_dump(mode="json"),
            idempotency_key=key,
            identifiers=identifiers,
        )
    except AuthorizationError:
        # Preserve the generic 403 emitted by server-side organization and
        # separation-of-duty checks.  Never downgrade an authorization denial to
        # an availability response that a client could misinterpret and retry.
        raise
    except ApiConflict:
        result = CommandResult(status="conflict", reason_code="immutable_state_conflict")
    except ApiBackendUnavailable:
        result = CommandResult.unavailable("control_plane_unavailable")
    except Exception:
        result = CommandResult.unavailable("command_failed")
    return _command_response(result)


@router.get("/principal")
def principal(request: Request, principal: ConsolePrincipal) -> JSONResponse:
    return _read(request, "principal", principal)


@router.get("/campaigns")
def campaigns(request: Request, principal: ConsolePrincipal) -> JSONResponse:
    return _read(request, "campaigns", principal)


@router.get("/campaigns/{campaign_id}")
def campaign(request: Request, campaign_id: str, principal: ConsolePrincipal) -> JSONResponse:
    return _read(request, "campaign", principal, {"campaign_id": campaign_id})


@router.get("/campaigns/{campaign_id}/attempts")
def attempts(request: Request, campaign_id: str, principal: ConsolePrincipal) -> JSONResponse:
    return _read(request, "attempts", principal, {"campaign_id": campaign_id})


@router.get("/attempts/{attempt_id}/evidence")
def evidence(request: Request, attempt_id: str, principal: EvidencePrincipal) -> JSONResponse:
    return _read(request, "evidence", principal, {"attempt_id": attempt_id})


@router.get("/findings")
def findings(request: Request, principal: FindingPrincipal) -> JSONResponse:
    return _read(request, "findings", principal)


@router.get("/findings/{finding_id}")
def finding(request: Request, finding_id: str, principal: FindingPrincipal) -> JSONResponse:
    return _read(request, "finding", principal, {"finding_id": finding_id})


@router.get("/approvals")
def approvals(request: Request, principal: ConsolePrincipal) -> JSONResponse:
    return _read(request, "approvals", principal)


@router.get("/coverage")
def coverage(request: Request, principal: FindingPrincipal) -> JSONResponse:
    return _read(request, "coverage", principal)


@router.get("/resilience")
def resilience(request: Request, principal: FindingPrincipal) -> JSONResponse:
    return _read(request, "resilience", principal)


@router.get("/traces")
def traces(request: Request, principal: EvidencePrincipal) -> JSONResponse:
    return _read(request, "traces", principal)


@router.get("/costs")
def costs(request: Request, principal: ConsolePrincipal) -> JSONResponse:
    return _read(request, "costs", principal)


@router.get("/targets")
def targets(request: Request, principal: ConsolePrincipal) -> JSONResponse:
    return _read(request, "targets", principal)


@router.get("/targets/{target_id}")
def target(request: Request, target_id: str, principal: ConsolePrincipal) -> JSONResponse:
    return _read(request, "target", principal, {"target_id": target_id})


@router.get("/configuration")
def configuration(request: Request, principal: ConsolePrincipal) -> JSONResponse:
    return _read(request, "configuration", principal)


@router.get("/components")
def components(request: Request, principal: ConsolePrincipal) -> JSONResponse:
    return _read(request, "components", principal)


@router.get("/audit")
def audit(request: Request, principal: AuditPrincipal) -> JSONResponse:
    return _read(request, "audit", principal)


@router.post("/campaign-authorization-requests")
def request_authorization(
    request: Request,
    body: AuthorizationRequestInput,
    principal: LaunchPrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(request, "request_campaign_authorization", principal, body, idempotency_key)


@router.post("/campaign-authorization-requests/{request_id}/decisions")
def decide_authorization(
    request: Request,
    request_id: str,
    body: AuthorizationDecisionInput,
    principal: AuthorizePrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(
        request,
        "decide_campaign_authorization",
        principal,
        body,
        idempotency_key,
        {"request_id": request_id},
    )


@router.post("/campaigns")
def launch_campaign(
    request: Request,
    body: CampaignLaunchInput,
    principal: LaunchPrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(request, "launch_campaign", principal, body, idempotency_key)


@router.post("/campaigns/{campaign_id}/abort")
def abort_campaign(
    request: Request,
    campaign_id: str,
    body: AbortInput,
    principal: AbortPrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(
        request,
        "abort_campaign",
        principal,
        body,
        idempotency_key,
        {"campaign_id": campaign_id},
    )


@router.post("/findings/{finding_id}/decisions")
def decide_finding(
    request: Request,
    finding_id: str,
    body: FindingDecisionInput,
    principal: FindingApprovePrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(
        request,
        "decide_finding",
        principal,
        body,
        idempotency_key,
        {"finding_id": finding_id},
    )


@router.post("/findings/{finding_id}/resolve")
def resolve_finding(
    request: Request,
    finding_id: str,
    body: FindingResolveInput,
    principal: FindingResolvePrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(
        request,
        "resolve_finding",
        principal,
        body,
        idempotency_key,
        {"finding_id": finding_id},
    )


@router.post("/targets")
def create_target(
    request: Request,
    body: TargetInput,
    principal: TargetPrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(request, "create_target", principal, body, idempotency_key)


@router.post("/targets/{target_id}/versions")
def revise_target(
    request: Request,
    target_id: str,
    body: TargetInput,
    principal: TargetPrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(
        request, "revise_target", principal, body, idempotency_key, {"target_id": target_id}
    )


@router.post("/targets/{target_id}/lifecycle")
def change_target_lifecycle(
    request: Request,
    target_id: str,
    body: TargetLifecycleInput,
    principal: TargetPrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(
        request,
        "change_target_lifecycle",
        principal,
        body,
        idempotency_key,
        {"target_id": target_id},
    )


@router.post("/targets/{target_id}/surfaces")
def create_surface(
    request: Request,
    target_id: str,
    body: SurfaceInput,
    principal: TargetPrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(
        request, "create_surface", principal, body, idempotency_key, {"target_id": target_id}
    )


@router.post("/targets/{target_id}/surfaces/{surface_id}/versions")
def revise_surface(
    request: Request,
    target_id: str,
    surface_id: str,
    body: SurfaceInput,
    principal: TargetPrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(
        request,
        "revise_surface",
        principal,
        body,
        idempotency_key,
        {"target_id": target_id, "surface_id": surface_id},
    )


@router.post("/targets/{target_id}/surfaces/{surface_id}/state")
def set_surface_state(
    request: Request,
    target_id: str,
    surface_id: str,
    body: SurfaceStateInput,
    principal: TargetPrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(
        request,
        "set_surface_state",
        principal,
        body,
        idempotency_key,
        {"target_id": target_id, "surface_id": surface_id},
    )


@router.post("/live-probe-authorization-requests")
def request_live_probe(
    request: Request,
    body: AuthorizationRequestInput,
    principal: AuthorizePrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(request, "request_live_probe_authorization", principal, body, idempotency_key)


@router.post("/configuration/validate")
def validate_configuration(
    request: Request,
    body: ConfigValidateInput,
    principal: ConfigPrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(request, "validate_configuration", principal, body, idempotency_key)


@router.post("/configuration/publish")
def publish_configuration(
    request: Request,
    body: ConfigPublishInput,
    principal: ConfigPrincipal,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    return _command(request, "publish_configuration", principal, body, idempotency_key)


def _sse(event: str, data: Mapping[str, Any], *, cursor: int | None = None) -> bytes:
    lines = []
    if cursor is not None:
        lines.append(f"id: {cursor}")
    lines.append(f"event: {event}")
    lines.append(
        "data: "
        + json.dumps(
            data, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
        )
    )
    return ("\n".join(lines) + "\n\n").encode("utf-8")


def _validated_cursor(raw: str | None) -> int:
    if raw is None or raw == "":
        return 0
    if not raw.isdigit():
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail="Invalid event cursor")
    value = int(raw)
    if value < 0 or value > 2**63 - 1:
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail="Invalid event cursor")
    return value


def _stream_origin_is_allowed(request: Request) -> bool:
    """Validate browser provenance without requiring a header browsers may omit on GET.

    A supplied ``Origin`` must exactly match configuration.  For a same-origin GET where
    the browser omits ``Origin``, the forbidden Fetch Metadata header must say
    ``same-origin`` and the HTTP authority must exactly match an allowed origin.  This
    fallback does not weaken bearer authentication; it makes the browser behavior usable
    while continuing to reject cross-site and ambiguous non-browser requests.
    """

    allowed = request.app.state.security_config.allowed_origins
    origin = request.headers.get("origin")
    if origin is not None:
        return origin in allowed
    if request.headers.get("sec-fetch-site") != "same-origin":
        return False
    host = request.headers.get("host", "").lower()
    return bool(host) and host in {urlsplit(value).netloc.lower() for value in allowed}


def _stream_deadline(request: Request) -> float:
    """Bound stream lifetime by both token expiry and a short revocation-refresh window."""

    expires_at = getattr(request.state, "clerk_session_expires_at", None)
    if (
        isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or expires_at <= time.time()
    ):
        raise AuthenticationUnavailableError()
    remaining = expires_at - time.time()
    return time.monotonic() + min(remaining, _STREAM_REAUTHENTICATION_SECONDS)


@router.get("/events")
async def events(
    request: Request,
    principal: ConsolePrincipal,
    last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
) -> StreamingResponse:
    if not _stream_origin_is_allowed(request):
        raise AuthorizationError()
    deadline = _stream_deadline(request)
    cursor = _validated_cursor(last_event_id)
    try:
        first = _backend(request).events(principal, after_cursor=cursor, limit=100)
    except Exception as exc:
        raise ApiBackendUnavailable("event stream unavailable") from exc

    async def stream() -> AsyncIterator[bytes]:
        nonlocal cursor, first
        batch: EventBatch | None = first
        idle_seconds = 0
        if cursor == 0:
            # REST projections are the authoritative snapshot.  The stream starts by
            # instructing the client to reconcile those projections, then emits ordered
            # append-only audit deltas.  No fabricated screen payload is placed here.
            yield _sse("snapshot", {"after_cursor": 0, "action": "reconcile"})
        while time.monotonic() < deadline and not await request.is_disconnected():
            if batch is None:
                try:
                    batch = _backend(request).events(principal, after_cursor=cursor, limit=100)
                except Exception:
                    yield _sse("unavailable", {"reason_code": "event_stream_unavailable"})
                    return
            if batch.gap:
                yield _sse(
                    "gap",
                    {
                        "after_cursor": cursor,
                        "oldest_cursor": batch.oldest_cursor,
                        "action": "reconcile",
                    },
                )
                cursor = max(0, batch.oldest_cursor - 1)
            emitted = False
            for item in batch.events[:100]:
                event_cursor = item.get("cursor")
                event_type = item.get("type")
                payload = item.get("payload")
                if not isinstance(event_cursor, int) or event_cursor <= cursor:
                    continue
                if not isinstance(event_type, str) or not isinstance(payload, Mapping):
                    continue
                yield _sse(event_type, payload, cursor=event_cursor)
                cursor = event_cursor
                emitted = True
            cursor = max(cursor, batch.next_cursor)
            if batch.terminal:
                return
            batch = None
            if emitted:
                idle_seconds = 0
            else:
                idle_seconds += 1
                if idle_seconds >= 15:
                    yield _sse("heartbeat", {"cursor": cursor})
                    idle_seconds = 0
            remaining = deadline - time.monotonic()
            if remaining > 0:
                await asyncio.sleep(min(1, remaining))

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
