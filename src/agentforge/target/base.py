"""Framework-neutral TargetAdapter interface + typed target-error taxonomy.

A ``TargetAdapter`` is the ONLY component that talks to a target, and it is invoked
exclusively through the trusted Policy Gateway (ARCHITECTURE.md §2/§5) — never directly by an
agent. This module imports nothing beyond the stdlib and encodes no target-specific behavior,
so a second target only needs a new adapter, not a change here (DECISIONS.md D10/D14).

The error classes mirror the typed error taxonomy published in ``contracts/v1/errors`` so the
gateway can translate an adapter failure into a contract-level typed error (backoff → queue →
abort) rather than a silent 200.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field


class AdapterError(Exception):
    """Base of the typed adapter-error taxonomy. ``code`` matches the contract error id."""

    code: str = "adapter-error"
    retryable: bool = True


class TargetUnreachableError(AdapterError):
    code = "target-unreachable"


class RateLimitedError(AdapterError):
    code = "rate-limited"

    def __init__(self, message: str = "", retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class TargetSessionExpiredError(AdapterError):
    """The target rejected an opaque delegated session that requires human relaunch."""

    code = "target-session-expired"
    retryable = False


@dataclass(frozen=True)
class TargetRequest:
    """A single request the gateway asks the adapter to deliver.

    ``turns`` is the ordered input sequence (multi-turn attacks are first-class). Kept frozen so
    a request is a stable key for deterministic replay and for the run-nonce identity.
    """

    turns: tuple[str, ...]
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class TargetResponse:
    """A single target response plus adapter-observed metadata."""

    output: str
    status: int = 200
    metadata: Mapping[str, str] = field(default_factory=dict)


class TargetAdapter(ABC):
    """Generic interface every target adapter implements — no target-specific assumptions."""

    name: str = "abstract"

    @abstractmethod
    def send(self, request: TargetRequest) -> TargetResponse:
        """Deliver ``request`` to the target and return its response, or raise a typed
        :class:`AdapterError` subclass.

        Implementations MUST NOT swallow an error into a synthetic success — a failure has to
        surface as a typed error so the gateway can apply backoff/queue/abort.
        """
        raise NotImplementedError
