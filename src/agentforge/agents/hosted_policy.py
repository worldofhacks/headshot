"""Server-owned generation-policy registry for the four-role hosted runtime.

The campaign authorization contains only a SHA-256 identity.  The private Runner resolves that
identity through this closed registry before it constructs an OpenRouter transport.  A caller can
therefore never turn an opaque digest into arbitrary token, timeout, retry, or role-call bounds.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from agentforge.agents.hosted_runtime import HostedCallBounds
from agentforge.agents.runtime import AGENT_ROLES, AgentRole

HOSTED_GENERATION_POLICY_SCHEMA_VERSION = "1"
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_ROLE_ORDER = {role: index for index, role in enumerate(AGENT_ROLES)}


class HostedGenerationPolicyError(ValueError):
    """An authorization named an unknown or internally inconsistent generation policy."""


@dataclass(frozen=True, slots=True)
class HostedRoleCallPolicy:
    """One role's exact provider-call envelope and execution trigger."""

    role: AgentRole
    bounds: HostedCallBounds
    invocation_trigger: str

    def __post_init__(self) -> None:
        if self.role not in AGENT_ROLES:
            raise HostedGenerationPolicyError("generation policy contains an unknown role")
        if not isinstance(self.bounds, HostedCallBounds):
            raise HostedGenerationPolicyError("generation policy bounds are invalid")
        if self.invocation_trigger not in {
            "each_selection_cycle",
            "each_generation_cycle",
            "each_evaluated_case",
            "each_confirmed_finding",
        }:
            raise HostedGenerationPolicyError("generation policy trigger is invalid")

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "invocation_trigger": self.invocation_trigger,
            "input_tokens": self.bounds.input_tokens,
            "output_tokens": self.bounds.output_tokens,
            "reasoning_tokens": self.bounds.reasoning_tokens,
            "timeout_seconds": float(self.bounds.timeout_seconds),
        }


@dataclass(frozen=True, slots=True)
class HostedGenerationPolicy:
    """Exact role-call bounds resolved by one authorization-bound SHA-256 digest."""

    roles: tuple[HostedRoleCallPolicy, ...]
    schema_version: str = HOSTED_GENERATION_POLICY_SCHEMA_VERSION
    policy_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if self.schema_version != HOSTED_GENERATION_POLICY_SCHEMA_VERSION:
            raise HostedGenerationPolicyError("generation policy schema version is unsupported")
        if (
            not isinstance(self.roles, tuple)
            or len(self.roles) != len(AGENT_ROLES)
            or {item.role for item in self.roles} != set(AGENT_ROLES)
        ):
            raise HostedGenerationPolicyError(
                "generation policy must cover each hosted role exactly once"
            )
        ordered = tuple(sorted(self.roles, key=lambda item: _ROLE_ORDER[item.role]))
        object.__setattr__(self, "roles", ordered)
        object.__setattr__(
            self,
            "policy_sha256",
            hashlib.sha256(self.canonical_bytes()).hexdigest(),
        )

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "roles": [item.canonical_payload() for item in self.roles],
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.canonical_payload(),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @property
    def call_bounds(self) -> dict[AgentRole, HostedCallBounds]:
        return {item.role: item.bounds for item in self.roles}

    def required_logical_calls(
        self,
        *,
        case_count: int,
        confirmed_finding_limit: int | None = None,
    ) -> dict[AgentRole, int]:
        """Return conservative logical-call requirements for one authorized workload.

        Report writing is triggered only by a trusted confirmed finding, but preflight reserves
        enough call authority for every case to be confirmed unless an even tighter trusted limit
        is supplied.  Provider retries remain inside the separately authorized physical-call cap.

        """

        if isinstance(case_count, bool) or not isinstance(case_count, int) or case_count < 1:
            raise HostedGenerationPolicyError("case count must be a positive integer")
        finding_limit = case_count if confirmed_finding_limit is None else confirmed_finding_limit
        if (
            isinstance(finding_limit, bool)
            or not isinstance(finding_limit, int)
            or finding_limit < 0
            or finding_limit > case_count
        ):
            raise HostedGenerationPolicyError(
                "confirmed-finding call limit must be between zero and the case count"
            )
        return {
            "orchestrator": case_count,
            "red_team": case_count,
            "judge": case_count,
            "documentation": finding_limit,
        }


# Model-facing evidence is compacted before every role call. These are hard per-call ceilings, not
# estimates; OpenRouterTransport independently checks the exact encoded message bytes and refuses
# usage beyond the configured ledger. Keeping these bounds aligned with the target-free four-role
# acceptance policy makes the governed 34-case staging batch fit inside the platform's closed
# $10 / 136-call envelope without weakening physical-call accounting or enabling retries.
DEFAULT_HOSTED_GENERATION_POLICY = HostedGenerationPolicy(
    roles=(
        HostedRoleCallPolicy(
            role="orchestrator",
            bounds=HostedCallBounds(
                input_tokens=8_192,
                output_tokens=512,
                reasoning_tokens=1_024,
                timeout_seconds=120.0,
            ),
            invocation_trigger="each_selection_cycle",
        ),
        HostedRoleCallPolicy(
            role="red_team",
            bounds=HostedCallBounds(
                input_tokens=4_096,
                # DigitalOcean's Qwen endpoint may consume more reasoning tokens than the
                # requested reasoning sub-cap. Reserve enough total completion capacity for
                # both its hidden reasoning and the small, strict selection object.
                output_tokens=2_048,
                reasoning_tokens=8_192,
                timeout_seconds=180.0,
            ),
            invocation_trigger="each_generation_cycle",
        ),
        HostedRoleCallPolicy(
            role="judge",
            bounds=HostedCallBounds(
                input_tokens=8_192,
                output_tokens=512,
                reasoning_tokens=1_024,
                timeout_seconds=180.0,
            ),
            invocation_trigger="each_evaluated_case",
        ),
        HostedRoleCallPolicy(
            role="documentation",
            bounds=HostedCallBounds(
                input_tokens=8_192,
                output_tokens=512,
                reasoning_tokens=1_024,
                timeout_seconds=120.0,
            ),
            invocation_trigger="each_confirmed_finding",
        ),
    )
)

_POLICIES = {
    DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256: DEFAULT_HOSTED_GENERATION_POLICY,
}


def resolve_hosted_generation_policy(policy_sha256: str) -> HostedGenerationPolicy:
    """Resolve one exact server-owned policy or fail closed without provider I/O."""

    if not isinstance(policy_sha256, str) or _HEX64.fullmatch(policy_sha256) is None:
        raise HostedGenerationPolicyError("generation policy identity is invalid")
    try:
        return _POLICIES[policy_sha256]
    except KeyError as exc:
        raise HostedGenerationPolicyError(
            "generation policy is not registered by this release"
        ) from exc


__all__ = [
    "DEFAULT_HOSTED_GENERATION_POLICY",
    "HOSTED_GENERATION_POLICY_SCHEMA_VERSION",
    "HostedGenerationPolicy",
    "HostedGenerationPolicyError",
    "HostedRoleCallPolicy",
    "resolve_hosted_generation_policy",
]
