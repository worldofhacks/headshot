"""Runner-only sealed environment credential resolver keyed by exact opaque references."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping

from agentforge.secrets import Secret

_ENV_NAME = re.compile(r"\A[A-Z][A-Z0-9_]{2,127}\Z")
_REF_PREFIX = "secretref://"


class CredentialResolutionError(RuntimeError):
    """A scoped credential reference is absent, mismatched, or unsafe."""


class SealedEnvironmentCredentialResolver:
    """Resolve only preconfigured reference-to-variable bindings; never logs values."""

    def __init__(
        self,
        bindings: Mapping[str, str],
        *,
        environment: Mapping[str, str] | None = None,
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

    @classmethod
    def from_environment(cls) -> SealedEnvironmentCredentialResolver:
        raw = os.environ.get("AGENTFORGE_CREDENTIAL_BINDINGS_JSON", "{}")
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise CredentialResolutionError("credential binding configuration is invalid") from exc
        if not isinstance(payload, dict):
            raise CredentialResolutionError("credential binding configuration is invalid")
        return cls(payload)

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


__all__ = ["CredentialResolutionError", "SealedEnvironmentCredentialResolver"]
