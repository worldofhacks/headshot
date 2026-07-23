"""The INDEPENDENT, UNTRUSTED Red Team generator (M8).

ARCHITECTURE.md §3/§8/§16 (trust split F2, live-campaign gate F7, S1/S3), DECISIONS.md D14;
PRD-14/17.

The Red Team *proposes* adversarial inputs and NOTHING else. It selects cases
(coverage-aware), sequences multi-turn attempts, mutates a partial success into lineage-tagged
variants, and dispatches each attempt EXCLUSIVELY through the trusted M4 ``PolicyGateway.execute``
— the gateway is the SOLE path to any target. The Red Team holds NO adapter, NO credential, and
NO outbound path of its own; it emits ONLY a credential-free ``AttackAttempt`` and never mints
evidence (no ``content_hash``, no verdict). The gateway owns the budget/rate/timeout caps and the
HARD ABORT; the Red Team respects them and never enforces, owns, or bypasses them.

Framework-neutral (D10): this package imports contracts / policy(gateway) / evals — never a web
framework. Any hosted-provider SDK import is LAZY, inside the hosted provider's call path only,
and is never reached in a test.
"""

from agentforge.agents.red_team.handoff import RedTeamProposalError, SeedReplayRedTeam
from agentforge.agents.red_team.mutation import mutate
from agentforge.agents.red_team.providers import (
    CassetteProvider,
    FakeProvider,
    HostedProvider,
    HostedProviderConfig,
    PreflightResult,
    ProviderAuthorizationError,
    ProviderExhaustedError,
    ProviderPreflightError,
    RedTeamProvider,
    preflight_hosted_provider,
)
from agentforge.agents.red_team.red_team import RedTeam
from agentforge.agents.red_team.seed_replay import load_seed_attempts, seed_to_attempt
from agentforge.agents.red_team.selection import least_covered_category, select_cases

__all__ = [
    "RedTeam",
    "SeedReplayRedTeam",
    "RedTeamProposalError",
    "mutate",
    "select_cases",
    "least_covered_category",
    "load_seed_attempts",
    "seed_to_attempt",
    "RedTeamProvider",
    "FakeProvider",
    "CassetteProvider",
    "HostedProvider",
    "HostedProviderConfig",
    "PreflightResult",
    "preflight_hosted_provider",
    "ProviderPreflightError",
    "ProviderAuthorizationError",
    "ProviderExhaustedError",
]
