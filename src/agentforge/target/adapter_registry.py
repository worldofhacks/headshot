"""Trusted adapter-factory registry with no dynamic import or fallback path.

Factories and a target registry are supplied by the trusted composition root and retained at
construction. Resolution accepts only a canonical authorization scope, resolves it through that
trusted registry, and never accepts a caller-provided snapshot. An attack payload cannot provide an
authoritative adapter kind, host, credential reference, or endpoint to this API.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from types import MappingProxyType

from agentforge.target.base import TargetAdapter
from agentforge.target.registry import ResolvedTargetSurface, TargetRegistry
from agentforge.target.spec import AuthorizationScope

AdapterFactory = Callable[[ResolvedTargetSurface], TargetAdapter]
_KIND_RE = re.compile(r"\A[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z")
_FALLBACK_KEYS = frozenset({"*", "default", "fallback"})


class AdapterRegistryError(Exception):
    """Trusted adapter-factory configuration is invalid."""


class AdapterResolutionError(AdapterRegistryError):
    """An exact adapter factory could not be resolved safely."""


class AdapterRegistry:
    """An immutable exact-kind map of trusted adapter factories."""

    def __init__(
        self,
        target_registry: TargetRegistry,
        factories: Mapping[str, AdapterFactory],
    ) -> None:
        if not isinstance(target_registry, TargetRegistry):
            raise AdapterRegistryError("adapter registry requires a trusted TargetRegistry")
        if not isinstance(factories, Mapping):
            raise AdapterRegistryError("adapter factories must be a trusted mapping")
        copied: dict[str, AdapterFactory] = {}
        for kind, factory in factories.items():
            if (
                not isinstance(kind, str)
                or kind in _FALLBACK_KEYS
                or _KIND_RE.fullmatch(kind) is None
            ):
                raise AdapterRegistryError("adapter factory key must be an exact stable kind")
            if not callable(factory):
                raise AdapterRegistryError("adapter factory must be callable")
            if kind in copied:
                raise AdapterRegistryError("adapter factory kind is duplicated")
            copied[kind] = factory
        self._target_registry = target_registry
        self._factories = MappingProxyType(copied)

    @property
    def kinds(self) -> tuple[str, ...]:
        return tuple(sorted(self._factories))

    def resolve(self, scope: AuthorizationScope) -> TargetAdapter:
        """Resolve trusted definitions, then build their exact registered adapter."""

        if not isinstance(scope, AuthorizationScope):
            raise AdapterResolutionError(
                "adapter resolution requires a canonical authorization scope"
            )
        resolved = self._target_registry.resolve(scope)
        kind = resolved.target.adapter_kind
        factory = self._factories.get(kind)
        if factory is None:
            raise AdapterResolutionError(
                "adapter kind is not registered; there is no dynamic import or fallback"
            )
        try:
            adapter = factory(resolved)
        except Exception as exc:  # trusted plugin failure is still a typed fail-closed refusal
            raise AdapterResolutionError("registered adapter factory failed") from exc
        if not isinstance(adapter, TargetAdapter):
            raise AdapterResolutionError("registered factory did not return a TargetAdapter")
        if adapter.name != kind:
            raise AdapterResolutionError("registered factory returned a mismatched adapter kind")
        return adapter


__all__ = [
    "AdapterFactory",
    "AdapterRegistry",
    "AdapterRegistryError",
    "AdapterResolutionError",
]
