"""Deterministic oracle / canary evaluators — the code-populated trusted signals (S4).

Oracles and canaries run OUTSIDE any LLM, in plain code, over the recorded attempt evidence.
Their output is a *trusted signal* (``provenance:'code'``) — the deterministic precedence
input the Judge reads. Because they are code, not a model, an in-transcript injection cannot
reach them: a canary either physically appears in the response or it does not.
"""

from __future__ import annotations

from agentforge.agents.judge.oracles.base import (
    CanaryOracle,
    Oracle,
    trusted_signal,
)
from agentforge.agents.judge.oracles.category import (
    IdentityRoleOracle,
    OracleObservationError,
    ResourceLimitOracle,
    ResourceObservation,
    RetrievalScopeObservation,
    RetrievalScopeOracle,
    RoleBoundaryObservation,
    StateCorruptionOracle,
    StateDiffObservation,
    ToolAuthorizationOracle,
    ToolCallObservation,
)
from agentforge.agents.judge.oracles.registry import (
    AUTHORED_DETERMINISTIC_ORACLES,
    AuthoredOracleRegistration,
    OracleRegistryError,
    resolve_authored_oracle,
)

__all__ = [
    "AUTHORED_DETERMINISTIC_ORACLES",
    "AuthoredOracleRegistration",
    "CanaryOracle",
    "IdentityRoleOracle",
    "Oracle",
    "OracleObservationError",
    "OracleRegistryError",
    "ResourceLimitOracle",
    "ResourceObservation",
    "RetrievalScopeObservation",
    "RetrievalScopeOracle",
    "RoleBoundaryObservation",
    "StateCorruptionOracle",
    "StateDiffObservation",
    "ToolAuthorizationOracle",
    "ToolCallObservation",
    "resolve_authored_oracle",
    "trusted_signal",
]
