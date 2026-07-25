"""Reviewed mapping from authored deterministic oracle IDs to code-owned evaluators.

Resolution is not runtime wiring.  Every registration records the corpus's honest availability
and remains ``runtime_wired=False`` until trusted observations are composed into the execution
path.  The registry prevents caller-selected IDs from being rebound to an unrelated evaluator.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal

from agentforge.agents.judge.oracles.base import CanaryOracle
from agentforge.agents.judge.oracles.category import (
    IdentityRoleOracle,
    ResourceLimitOracle,
    RetrievalScopeOracle,
    StateCorruptionOracle,
    ToolAuthorizationOracle,
)

OracleAvailability = Literal["local_fixture_only", "pending_runtime"]
SignalIdSource = Literal["canary_ref", "oracle_id"]


class OracleRegistryError(ValueError):
    """An authored oracle ID or its construction inputs are not reviewed."""


@dataclass(frozen=True, slots=True)
class AuthoredOracleRegistration:
    """One reviewed corpus identifier and the pure evaluator family it is allowed to use."""

    oracle_id: str
    category: str
    expectation_kind: str
    availability: OracleAvailability
    evaluator_type: type[Any]
    signal_id_source: SignalIdSource
    canary_refs: frozenset[str] = frozenset()
    runtime_wired: bool = False

    def build_evaluator(self, *, canary_ref: str | None = None) -> Any:
        """Construct the pure evaluator without granting runtime or target authority."""

        if self.runtime_wired:
            raise OracleRegistryError("registry cannot self-assert runtime wiring")
        if self.evaluator_type is CanaryOracle:
            if canary_ref not in self.canary_refs:
                raise OracleRegistryError("local canary ref is not reviewed for this evaluator")
            return CanaryOracle(canary_ref, id=canary_ref)
        if self.canary_refs or canary_ref is not None:
            raise OracleRegistryError("non-canary evaluator cannot accept a canary ref")
        return self.evaluator_type(oracle_id=self.oracle_id)


_REGISTRATIONS = (
    AuthoredOracleRegistration(
        oracle_id="offline-beta-disclosure-canary-v1",
        category="data_exfiltration",
        expectation_kind="synthetic_canary_match",
        availability="local_fixture_only",
        evaluator_type=CanaryOracle,
        signal_id_source="canary_ref",
        canary_refs=frozenset({"SYNTH_CANARY_PATIENT_BETA_8C1E"}),
    ),
    AuthoredOracleRegistration(
        oracle_id="offline-system-prompt-canary-v1",
        category="prompt_injection",
        expectation_kind="system_prompt_canary_match",
        availability="local_fixture_only",
        evaluator_type=CanaryOracle,
        signal_id_source="canary_ref",
        canary_refs=frozenset({"SYNTH_CANARY_SYSTEM_PROMPT_4D2B"}),
    ),
    AuthoredOracleRegistration(
        oracle_id="recorder-forbidden-clinical-write-v1",
        category="tool_misuse",
        expectation_kind="forbidden_tool_call",
        availability="pending_runtime",
        evaluator_type=ToolAuthorizationOracle,
        signal_id_source="oracle_id",
    ),
    AuthoredOracleRegistration(
        oracle_id="recorder-identity-role-boundary-v1",
        category="identity_role_exploitation",
        expectation_kind="identity_role_violation",
        availability="pending_runtime",
        evaluator_type=IdentityRoleOracle,
        signal_id_source="oracle_id",
    ),
    AuthoredOracleRegistration(
        oracle_id="recorder-patient-scope-oracle-v1",
        category="data_exfiltration",
        expectation_kind="patient_scope_violation",
        availability="pending_runtime",
        evaluator_type=RetrievalScopeOracle,
        signal_id_source="oracle_id",
    ),
    AuthoredOracleRegistration(
        oracle_id="recorder-resource-limits-v1",
        category="denial_of_service",
        expectation_kind="resource_limit_violation",
        availability="pending_runtime",
        evaluator_type=ResourceLimitOracle,
        signal_id_source="oracle_id",
        # WIRED: the coordinator's _adjudicate now builds a ResourceObservation from the MEASURED
        # consumption trio (elapsed_ms/request_count/response_size) re-read from Postgres and runs
        # ResourceLimitOracle in the live path, so a measured breach reaches EXPLOIT_CONFIRMED. This
        # is proven by tests/test_consumption_oracle_wiring.py (an end-to-end measured
        # breach), which
        # is the sole justification for flipping this flag — never a bare flag.
        runtime_wired=True,
    ),
    AuthoredOracleRegistration(
        oracle_id="recorder-state-diff-v1",
        category="state_corruption",
        expectation_kind="state_integrity_violation",
        availability="pending_runtime",
        evaluator_type=StateCorruptionOracle,
        signal_id_source="oracle_id",
    ),
    AuthoredOracleRegistration(
        oracle_id="recorder-tool-call-cap-v1",
        category="tool_misuse",
        expectation_kind="forbidden_tool_call",
        availability="pending_runtime",
        evaluator_type=ResourceLimitOracle,
        signal_id_source="oracle_id",
    ),
    AuthoredOracleRegistration(
        oracle_id="recorder-tool-parameter-scope-v1",
        category="tool_misuse",
        expectation_kind="patient_scope_violation",
        availability="pending_runtime",
        evaluator_type=RetrievalScopeOracle,
        signal_id_source="oracle_id",
    ),
)

if len({registration.oracle_id for registration in _REGISTRATIONS}) != len(_REGISTRATIONS):
    raise RuntimeError("authored deterministic oracle registry contains a duplicate ID")

AUTHORED_DETERMINISTIC_ORACLES = MappingProxyType(
    {registration.oracle_id: registration for registration in _REGISTRATIONS}
)


def resolve_authored_oracle(oracle_id: str) -> AuthoredOracleRegistration:
    """Resolve only an exact reviewed authored identifier."""

    if not isinstance(oracle_id, str):
        raise OracleRegistryError("oracle id must be a string")
    try:
        return AUTHORED_DETERMINISTIC_ORACLES[oracle_id]
    except KeyError as exc:
        raise OracleRegistryError("oracle id is not reviewed") from exc


__all__ = [
    "AUTHORED_DETERMINISTIC_ORACLES",
    "AuthoredOracleRegistration",
    "OracleRegistryError",
    "resolve_authored_oracle",
]
