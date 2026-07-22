"""Stable v1 response envelopes and command acknowledgements.

The browser may add a transient ``loading`` state while a request is in flight. Server
responses use the remaining explicit states and never substitute sample data for a missing
projection.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ResourceState = Literal["ready", "empty", "unavailable", "stale", "degraded", "error"]


class ResourceResult(BaseModel):
    """One typed authoritative read result."""

    model_config = ConfigDict(extra="forbid")

    state: ResourceState
    data: Any | None = None
    reason_code: str | None = None
    detail: str | None = None
    as_of: str | None = None
    cursor: int | None = None

    @classmethod
    def ready(cls, data: Any, **metadata: Any) -> ResourceResult:
        return cls(state="ready", data=data, **metadata)

    @classmethod
    def empty(cls, **metadata: Any) -> ResourceResult:
        return cls(state="empty", data=[], **metadata)

    @classmethod
    def unavailable(cls, reason_code: str, *, detail: str | None = None) -> ResourceResult:
        return cls(state="unavailable", reason_code=reason_code, detail=detail)

    @classmethod
    def stale(cls, data: Any, reason_code: str, **metadata: Any) -> ResourceResult:
        return cls(state="stale", data=data, reason_code=reason_code, **metadata)

    @classmethod
    def degraded(cls, data: Any, reason_code: str, **metadata: Any) -> ResourceResult:
        return cls(state="degraded", data=data, reason_code=reason_code, **metadata)

    @classmethod
    def error(cls, reason_code: str) -> ResourceResult:
        return cls(state="error", reason_code=reason_code)


class CommandResult(BaseModel):
    """A server-owned acknowledgement; never an optimistic browser result."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["accepted", "completed", "unavailable", "conflict"]
    acknowledgement_id: str | None = None
    resource_id: str | None = None
    reason_code: str | None = None

    @classmethod
    def accepted(cls, acknowledgement_id: str, *, resource_id: str | None = None) -> CommandResult:
        return cls(
            status="accepted",
            acknowledgement_id=acknowledgement_id,
            resource_id=resource_id,
        )

    @classmethod
    def completed(cls, acknowledgement_id: str, *, resource_id: str | None = None) -> CommandResult:
        return cls(
            status="completed",
            acknowledgement_id=acknowledgement_id,
            resource_id=resource_id,
        )

    @classmethod
    def unavailable(cls, reason_code: str) -> CommandResult:
        return cls(status="unavailable", reason_code=reason_code)


class EventBatch(BaseModel):
    """A bounded ordered event page used by fetch-stream reconnects."""

    model_config = ConfigDict(extra="forbid")

    events: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    next_cursor: int
    oldest_cursor: int
    gap: bool
    terminal: bool = True
