"""Backend boundary for the HTTP API.

The router knows permissions and HTTP. Concrete backends own organization-scoped storage
lookups and business commands. This split also makes all API tests deterministic and offline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from agentforge.api.schemas import CommandResult, EventBatch, ResourceResult
from agentforge.auth.principal import Principal


class ApiBackendError(RuntimeError):
    """A sanitized backend failure suitable for fail-closed HTTP mapping."""


class ApiBackendUnavailable(ApiBackendError):
    """The authoritative dependency for an operation is unavailable."""


class ApiConflict(ApiBackendError):
    """An immutable/idempotency/business-state conflict."""


class ApiBackend(ABC):
    """Closed API/storage seam. No request, header, token, or cookie crosses it."""

    @abstractmethod
    def read(
        self,
        resource: str,
        principal: Principal,
        *,
        identifiers: Mapping[str, str] | None = None,
    ) -> ResourceResult:
        raise NotImplementedError

    @abstractmethod
    def command(
        self,
        command: str,
        principal: Principal,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str,
        identifiers: Mapping[str, str] | None = None,
    ) -> CommandResult:
        raise NotImplementedError

    @abstractmethod
    def events(
        self,
        principal: Principal,
        *,
        after_cursor: int,
        limit: int,
    ) -> EventBatch:
        raise NotImplementedError


class UnavailableApiBackend(ApiBackend):
    """Honest default when PostgreSQL/control-plane composition is absent."""

    def read(self, resource, principal, *, identifiers=None):
        if resource == "principal":
            return ResourceResult.ready(
                {
                    "user_id": principal.user_id,
                    "session_id": principal.session_id,
                    "organization_id": principal.organization_id,
                    "organization_role": principal.organization_role,
                    "organization_permissions": sorted(principal.organization_permissions),
                }
            )
        return ResourceResult.unavailable("control_plane_unavailable")

    def command(self, command, principal, payload, *, idempotency_key, identifiers=None):
        return CommandResult.unavailable("control_plane_unavailable")

    def events(self, principal, *, after_cursor, limit):
        return EventBatch(
            events=(),
            next_cursor=after_cursor,
            oldest_cursor=after_cursor,
            gap=False,
            terminal=True,
        )
