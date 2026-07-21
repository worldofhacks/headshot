"""Typed, credential-free control-plane refusals."""


class ControlPlaneError(RuntimeError):
    """Base class for fail-closed control-plane failures."""


class AuthorizationDeniedError(ControlPlaneError):
    """The verified actor or persisted workflow state does not authorize an action."""


class RecordNotFoundError(ControlPlaneError):
    """No organization-scoped record exists for the supplied opaque identity."""


class RecordConflictError(ControlPlaneError):
    """An immutable identity already exists or a state transition conflicts."""


class IdempotencyConflictError(ControlPlaneError):
    """An idempotency key already names different immutable command input."""


class InvalidControlPlaneInput(ControlPlaneError, ValueError):
    """A command input cannot be represented safely."""
