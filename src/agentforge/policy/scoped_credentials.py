"""Runner-only sealed environment credential resolver keyed by exact opaque references."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256

from agentforge.secrets import Secret

_ENV_NAME = re.compile(r"\A[A-Z][A-Z0-9_]{2,127}\Z")
_REF_PREFIX = "secretref://"
_GENERATION = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_SESSION_LEASES_ENV = "AGENTFORGE_SESSION_LEASES_JSON"


class CredentialResolutionError(RuntimeError):
    """A scoped credential reference is absent, mismatched, or unsafe."""

    code = "credential-resolution-failed"


class CredentialLeaseExpiredError(CredentialResolutionError):
    """A delegated target session cannot cover or has exceeded the campaign window."""

    code = "target-session-expired"


@dataclass(frozen=True, slots=True)
class SessionLeaseMetadata:
    """Non-secret lifecycle metadata for one versioned delegated target session."""

    generation: str
    expires_at: datetime
    value_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.generation, str) or _GENERATION.fullmatch(self.generation) is None:
            raise CredentialResolutionError("session generation metadata is invalid")
        if not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None:
            raise CredentialResolutionError("session expiry metadata must be timezone-aware")
        object.__setattr__(self, "expires_at", self.expires_at.astimezone(UTC))
        if not isinstance(self.value_sha256, str) or _SHA256.fullmatch(self.value_sha256) is None:
            raise CredentialResolutionError("session generation metadata hash is invalid")


class CampaignCredentialLease:
    """Pin one credential generation in memory for exactly one campaign.

    The underlying resolver is called at most once.  Subsequent attempts receive the same
    :class:`Secret`, so an environment mutation cannot silently switch patient/session context
    mid-run.  ``release`` drops both in-memory references; it cannot erase Python string storage,
    so process isolation and short Runner lifetime remain defense-in-depth controls.
    """

    __slots__ = (
        "_credential_ref",
        "_expires_at",
        "_expected_sha256",
        "_now",
        "_released",
        "_resolver",
        "_secret",
        "_resolution_count",
    )

    def __init__(
        self,
        *,
        credential_ref: str | None,
        resolver: Callable[[str | None], Secret | None],
        metadata: SessionLeaseMetadata | None,
        now: Callable[[], datetime],
    ) -> None:
        self._credential_ref = credential_ref
        self._resolver = resolver
        self._expires_at = metadata.expires_at if metadata is not None else None
        self._expected_sha256 = metadata.value_sha256 if metadata is not None else None
        self._now = now
        self._secret: Secret | None = None
        self._resolution_count = 0
        self._released = False

    @property
    def resolution_count(self) -> int:
        return self._resolution_count

    def resolve(self, reference: str | None) -> Secret | None:
        if self._released:
            raise CredentialResolutionError("campaign credential lease was released")
        if reference != self._credential_ref:
            raise CredentialResolutionError("campaign credential reference changed")
        if self._expires_at is not None and self._utc_now() >= self._expires_at:
            raise CredentialLeaseExpiredError("delegated target session expired")
        if self._resolution_count == 0:
            secret = self._resolver(reference)
            if secret is not None and not isinstance(secret, Secret):
                raise CredentialResolutionError("credential resolver returned an unsafe value")
            if secret is not None and self._expected_sha256 is not None:
                actual = sha256(secret.reveal().encode("utf-8")).hexdigest()
                if actual != self._expected_sha256:
                    raise CredentialResolutionError(
                        "credential value differs from its versioned generation metadata"
                    )
            self._secret = secret
            self._resolution_count = 1
        return self._secret

    def release(self) -> None:
        self._secret = None
        self._resolver = self._released_resolver
        self._released = True

    def _utc_now(self) -> datetime:
        value = self._now()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise CredentialResolutionError("campaign session clock is invalid")
        return value.astimezone(UTC)

    @staticmethod
    def _released_resolver(_reference: str | None) -> Secret | None:
        raise CredentialResolutionError("campaign credential lease was released")

    def __repr__(self) -> str:
        marker = (
            "no-auth"
            if self._credential_ref is None
            else sha256(self._credential_ref.encode("utf-8")).hexdigest()
        )
        return f"CampaignCredentialLease(ref_sha256={marker!r}, active={not self._released})"


class SealedEnvironmentCredentialResolver:
    """Resolve only preconfigured reference-to-variable bindings; never logs values."""

    def __init__(
        self,
        bindings: Mapping[str, str],
        *,
        environment: Mapping[str, str] | None = None,
        session_metadata: Mapping[str, SessionLeaseMetadata] | None = None,
    ):
        normalized: dict[str, str] = {}
        for reference, variable in bindings.items():
            if (
                not isinstance(reference, str)
                or not reference.startswith(_REF_PREFIX)
                or not isinstance(variable, str)
                or _ENV_NAME.fullmatch(variable) is None
            ):
                raise CredentialResolutionError("credential binding configuration is invalid")
            normalized[reference] = variable
        self._bindings = normalized
        self._environment = os.environ if environment is None else environment
        metadata = {} if session_metadata is None else dict(session_metadata)
        if any(
            reference not in normalized or not isinstance(value, SessionLeaseMetadata)
            for reference, value in metadata.items()
        ):
            raise CredentialResolutionError("session lease metadata configuration is invalid")
        self._session_metadata = metadata

    @classmethod
    def from_environment(cls) -> SealedEnvironmentCredentialResolver:
        raw = os.environ.get("AGENTFORGE_CREDENTIAL_BINDINGS_JSON", "{}")
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise CredentialResolutionError("credential binding configuration is invalid") from exc
        if not isinstance(payload, dict):
            raise CredentialResolutionError("credential binding configuration is invalid")
        metadata = cls._metadata_from_environment()
        return cls(payload, session_metadata=metadata)

    @staticmethod
    def _metadata_from_environment() -> dict[str, SessionLeaseMetadata]:
        raw = os.environ.get(_SESSION_LEASES_ENV, "{}").strip() or "{}"
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise CredentialResolutionError(
                "session lease metadata configuration is invalid"
            ) from exc
        if not isinstance(payload, dict):
            raise CredentialResolutionError("session lease metadata configuration is invalid")
        parsed: dict[str, SessionLeaseMetadata] = {}
        for reference, value in payload.items():
            if (
                not isinstance(reference, str)
                or not reference.startswith(_REF_PREFIX)
                or not isinstance(value, dict)
                or set(value) != {"generation", "expires_at", "value_sha256"}
            ):
                raise CredentialResolutionError("session lease metadata configuration is invalid")
            try:
                expires_at = datetime.fromisoformat(str(value["expires_at"]).replace("Z", "+00:00"))
                parsed[reference] = SessionLeaseMetadata(
                    generation=value["generation"],
                    expires_at=expires_at,
                    value_sha256=value["value_sha256"],
                )
            except (TypeError, ValueError) as exc:
                raise CredentialResolutionError(
                    "session lease metadata configuration is invalid"
                ) from exc
        return parsed

    def has(self, reference: str | None) -> bool:
        if reference is None:
            return True
        variable = self._bindings.get(reference)
        return bool(variable and self._environment.get(variable))

    def resolve(self, reference: str | None) -> Secret | None:
        if reference is None:
            return None
        variable = self._bindings.get(reference)
        if variable is None:
            raise CredentialResolutionError("credential reference is not bound for this Runner")
        value = self._environment.get(variable)
        if not isinstance(value, str) or not value:
            raise CredentialResolutionError("credential reference is unavailable to this Runner")
        return Secret(value)

    def session_ready(self, reference: str | None, *, required_until: datetime) -> bool:
        """Check non-secret metadata only; the raw session is still resolved at dispatch."""

        if (
            reference is None
            or not isinstance(required_until, datetime)
            or required_until.tzinfo is None
        ):
            return False
        metadata = self._session_metadata.get(reference)
        if metadata is None or not self.has(reference):
            return False
        if not reference.endswith(f"/{metadata.generation}"):
            return False
        return metadata.expires_at > required_until.astimezone(UTC)

    def lease(
        self,
        reference: str | None,
        *,
        required_until: datetime | None = None,
        now: Callable[[], datetime] | None = None,
        require_session_metadata: bool = False,
    ) -> CampaignCredentialLease:
        metadata = self._session_metadata.get(reference) if reference is not None else None
        if require_session_metadata and (
            required_until is None
            or not self.session_ready(reference, required_until=required_until)
        ):
            raise CredentialLeaseExpiredError(
                "delegated target session cannot cover the full campaign window"
            )
        return CampaignCredentialLease(
            credential_ref=reference,
            resolver=self.resolve,
            metadata=metadata,
            now=now or (lambda: datetime.now(UTC)),
        )


__all__ = [
    "CampaignCredentialLease",
    "CredentialLeaseExpiredError",
    "CredentialResolutionError",
    "SealedEnvironmentCredentialResolver",
    "SessionLeaseMetadata",
]
