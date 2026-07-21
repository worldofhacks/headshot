"""In-memory target and attack-surface registry with fail-closed dispatch resolution.

The registry owns identity and version relationships; it does not own adapters, credentials,
network clients, or persistence.  Registration copies immutable definitions into versioned
histories.  Dispatch resolution accepts only a canonical :class:`AuthorizationScope` and returns
one frozen snapshot after rechecking readiness and every trusted routing field.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from threading import RLock

from agentforge.target.spec import (
    AttackSurfaceDefinition,
    AuthMode,
    AuthorizationScope,
    TargetDefinition,
    TargetLifecycle,
)


class TargetRegistryError(Exception):
    """Base class for typed registry refusals."""


class RegistrationError(TargetRegistryError):
    """A definition cannot be registered without weakening identity or version rules."""


class TargetNotFoundError(TargetRegistryError):
    """A target or surface identifier is unknown."""


class VersionMismatchError(TargetRegistryError):
    """A requested target or surface version is not registered."""


class TargetNotReadyError(TargetRegistryError):
    """A draft or validating target cannot dispatch."""


class TargetUnavailableError(TargetRegistryError):
    """A disabled or archived target cannot dispatch."""


class SurfaceUnavailableError(TargetRegistryError):
    """A disabled attack surface cannot dispatch."""


class AuthorizationScopeMismatch(TargetRegistryError):
    """The authorization scope differs from trusted registry configuration."""


@dataclass(frozen=True, slots=True)
class ResolvedTargetSurface:
    """One immutable target/surface/scope binding admitted for adapter resolution."""

    target: TargetDefinition
    surface: AttackSurfaceDefinition
    authorization_scope: AuthorizationScope


def _version_key(version: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in version.split("."))  # type: ignore[return-value]


class TargetRegistry:
    """Dynamic, versioned registry whose dispatch path is exact and deny-by-default."""

    def __init__(self) -> None:
        self._targets: dict[str, dict[str, TargetDefinition]] = {}
        self._latest_targets: dict[str, str] = {}
        self._target_lifecycles: dict[tuple[str, str], TargetLifecycle] = {}
        self._target_lifecycle_events: dict[tuple[str, str], list[TargetLifecycle]] = {}
        self._surfaces: dict[tuple[str, str], dict[str, AttackSurfaceDefinition]] = {}
        self._latest_surfaces: dict[tuple[str, str], str] = {}
        self._surface_owners: dict[str, str] = {}
        self._lock = RLock()

    def register_target(self, target: TargetDefinition) -> TargetDefinition:
        if not isinstance(target, TargetDefinition):
            raise RegistrationError("target registration requires a TargetDefinition snapshot")
        if target.lifecycle is not TargetLifecycle.DRAFT:
            raise RegistrationError("a newly registered target version must begin in draft")
        with self._lock:
            versions = self._targets.setdefault(target.target_id, {})
            if target.version in versions:
                raise RegistrationError("target id/version is already registered and immutable")
            latest = self._latest_targets.get(target.target_id)
            if latest is not None and _version_key(target.version) <= _version_key(latest):
                raise RegistrationError("target versions must increase monotonically")
            versions[target.version] = target
            self._latest_targets[target.target_id] = target.version
            key = (target.target_id, target.version)
            self._target_lifecycles[key] = target.lifecycle
            self._target_lifecycle_events[key] = [target.lifecycle]
        return target

    def register_surface(self, surface: AttackSurfaceDefinition) -> AttackSurfaceDefinition:
        if not isinstance(surface, AttackSurfaceDefinition):
            raise RegistrationError(
                "surface registration requires an AttackSurfaceDefinition snapshot"
            )
        with self._lock:
            target = self._get_target_locked(surface.target_id, surface.target_version)
            if target.lifecycle is not TargetLifecycle.DRAFT:
                raise RegistrationError(
                    "a surface must be registered while its target version is in draft"
                )
            expected_authentication = target.auth_mode is not AuthMode.NONE
            if surface.authentication_required is not expected_authentication:
                raise RegistrationError(
                    "surface authentication requirement must match the target auth mode"
                )
            owner = self._surface_owners.get(surface.surface_id)
            if owner is not None and owner != surface.target_id:
                raise RegistrationError("surface id has an immutable target owner")
            key = (surface.target_id, surface.surface_id)
            versions = self._surfaces.setdefault(key, {})
            if surface.version in versions:
                raise RegistrationError("surface id/version is already registered and immutable")
            latest = self._latest_surfaces.get(key)
            if latest is not None and _version_key(surface.version) <= _version_key(latest):
                raise RegistrationError("surface versions must increase monotonically")
            versions[surface.version] = surface
            self._latest_surfaces[key] = surface.version
            self._surface_owners.setdefault(surface.surface_id, surface.target_id)
        return surface

    def transition_target(
        self,
        target_id: str,
        version: str,
        lifecycle: TargetLifecycle,
    ) -> TargetDefinition:
        with self._lock:
            current = self._get_target_locked(target_id, version)
            transitioned = current.transition(lifecycle)
            key = (target_id, version)
            self._target_lifecycles[key] = transitioned.lifecycle
            self._target_lifecycle_events[key].append(transitioned.lifecycle)
            return transitioned

    def get_target(self, target_id: str, version: str | None = None) -> TargetDefinition:
        with self._lock:
            selected_version = version or self._latest_targets.get(target_id)
            if selected_version is None:
                raise TargetNotFoundError("target id is not registered")
            return self._get_target_locked(target_id, selected_version)

    def get_surface(
        self,
        target_id: str,
        surface_id: str,
        version: str | None = None,
    ) -> AttackSurfaceDefinition:
        with self._lock:
            owner = self._surface_owners.get(surface_id)
            if owner is None:
                raise TargetNotFoundError("surface id is not registered")
            if owner != target_id:
                raise AuthorizationScopeMismatch("surface belongs to a different target")
            key = (target_id, surface_id)
            selected_version = version or self._latest_surfaces.get(key)
            if selected_version is None:
                raise TargetNotFoundError("surface id is not registered for target")
            return self._get_surface_locked(target_id, surface_id, selected_version)

    def target_history(self, target_id: str) -> tuple[TargetDefinition, ...]:
        with self._lock:
            versions = self._targets.get(target_id)
            if versions is None:
                raise TargetNotFoundError("target id is not registered")
            return tuple(versions[key] for key in sorted(versions, key=_version_key))

    def target_lifecycle_history(self, target_id: str, version: str) -> tuple[TargetLifecycle, ...]:
        with self._lock:
            self._get_target_locked(target_id, version)
            return tuple(self._target_lifecycle_events[(target_id, version)])

    def surface_history(
        self, target_id: str, surface_id: str
    ) -> tuple[AttackSurfaceDefinition, ...]:
        with self._lock:
            owner = self._surface_owners.get(surface_id)
            if owner is None:
                raise TargetNotFoundError("surface id is not registered")
            if owner != target_id:
                raise AuthorizationScopeMismatch("surface belongs to a different target")
            versions = self._surfaces[(target_id, surface_id)]
            return tuple(versions[key] for key in sorted(versions, key=_version_key))

    def resolve(self, scope: AuthorizationScope) -> ResolvedTargetSurface:
        """Resolve an exact authorized scope or raise before adapter construction."""

        if not isinstance(scope, AuthorizationScope):
            raise AuthorizationScopeMismatch("dispatch requires a canonical authorization scope")
        with self._lock:
            target = self._get_target_locked(scope.target_id, scope.target_version)
            if target.lifecycle in {TargetLifecycle.DRAFT, TargetLifecycle.VALIDATING}:
                raise TargetNotReadyError("target is not ready for dispatch")
            if target.lifecycle in {TargetLifecycle.DISABLED, TargetLifecycle.ARCHIVED}:
                raise TargetUnavailableError("target is disabled or archived")

            surface = self._get_surface_locked(
                scope.target_id,
                scope.surface_id,
                scope.surface_version,
            )
            if surface.target_id != target.target_id:
                raise AuthorizationScopeMismatch("surface target identity does not match")
            if surface.target_version != target.version:
                raise VersionMismatchError("surface target version does not match target version")
            if not surface.enabled:
                raise SurfaceUnavailableError("surface is disabled")

            expected: tuple[tuple[str, object, object], ...] = (
                ("adapter_kind", scope.adapter_kind, target.adapter_kind),
                ("environment", scope.environment, target.environment),
                ("exact_host", scope.exact_host, target.exact_host),
                ("auth_mode", scope.auth_mode, target.auth_mode),
                ("credential_ref", scope.credential_ref, target.credential_ref),
                ("explicit_no_auth", scope.explicit_no_auth, target.explicit_no_auth),
                ("surface target_id", scope.target_id, surface.target_id),
                ("surface target_version", scope.target_version, surface.target_version),
                ("protocol", scope.protocol, surface.protocol),
                ("method", scope.method, surface.method),
                ("relative_path", scope.relative_path, surface.relative_path),
            )
            for field, supplied, trusted in expected:
                if supplied != trusted:
                    raise AuthorizationScopeMismatch(
                        f"authorization scope {field} differs from trusted registry configuration"
                    )
            if not scope.caps.is_within(target.safety_caps):
                raise AuthorizationScopeMismatch(
                    "authorization scope caps exceed the target safety maxima"
                )
            return ResolvedTargetSurface(
                target=target,
                surface=surface,
                authorization_scope=scope,
            )

    def _get_target_locked(self, target_id: str, version: str) -> TargetDefinition:
        versions = self._targets.get(target_id)
        if versions is None:
            raise TargetNotFoundError("target id is not registered")
        try:
            definition = versions[version]
        except KeyError as exc:
            raise VersionMismatchError("target version is not registered") from exc
        lifecycle = self._target_lifecycles[(target_id, version)]
        if lifecycle is definition.lifecycle:
            return definition
        return replace(definition, lifecycle=lifecycle)

    def _get_surface_locked(
        self,
        target_id: str,
        surface_id: str,
        version: str,
    ) -> AttackSurfaceDefinition:
        owner = self._surface_owners.get(surface_id)
        if owner is None:
            raise TargetNotFoundError("surface id is not registered")
        if owner != target_id:
            raise AuthorizationScopeMismatch("surface belongs to a different target")
        versions = self._surfaces.get((target_id, surface_id))
        if versions is None:
            raise TargetNotFoundError("surface id is not registered for target")
        try:
            return versions[version]
        except KeyError as exc:
            raise VersionMismatchError("surface version is not registered") from exc


__all__ = [
    "AuthorizationScopeMismatch",
    "RegistrationError",
    "ResolvedTargetSurface",
    "SurfaceUnavailableError",
    "TargetNotFoundError",
    "TargetNotReadyError",
    "TargetRegistry",
    "TargetRegistryError",
    "TargetUnavailableError",
    "VersionMismatchError",
]
