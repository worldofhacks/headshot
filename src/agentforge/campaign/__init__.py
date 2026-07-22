"""agentforge.campaign — the minimal SECURE live-path coordinator + authorized bounded-run CLI.

M11-coordinator. This package binds the landed platform components (M4 PolicyGateway +
ExecutionRecorder, M5 OpenEmrAdapter, M8 seed_replay, M9 Judge / EvidenceEnvelope / CanaryOracle,
M6a reconcile) into ONE fail-closed live-campaign coordinator, gated behind a persisted,
expiring, scoped :class:`~agentforge.campaign.authorization.RunAuthorization`.

Every gate — authorization, target binding, run caps — is verified BEFORE any dispatch reaches
the target. There is NO live-to-fake fallback: a blocked live path raises, it never substitutes
the P9 :class:`~agentforge.target.fake_adapter.FakeTargetAdapter`. Hosted Red Team generation is
SKIPPED for MVP: the nine authored seed cases are replayed deterministically via M8 seed_replay.

**No network is ever opened from this package's own code.** The only outbound path is the
injected :class:`~agentforge.target.base.TargetAdapter`, whose HTTP client is lazy/injected —
never imported at package import time, never constructed under test. Credentials resolve to a
:class:`~agentforge.secrets.Secret` ONLY at the verified dispatch boundary, via
:meth:`~agentforge.config.Settings.resolve_target_credential` (O1). Manifests are immutable,
content-hashed, and redacted.
"""

from __future__ import annotations

from agentforge.campaign.authorization import (
    AuthorizationError,
    RunAuthorization,
    operation_hash,
)
from agentforge.campaign.binding import BindingError, TargetBinding
from agentforge.campaign.caps import CapError, RunCaps
from agentforge.campaign.coordinator import (
    CampaignAbort,
    CampaignOutcome,
    RunConfig,
    SecureCampaignCoordinator,
)
from agentforge.campaign.manifest import ManifestImmutableError, ManifestStore

__all__ = [
    "AuthorizationError",
    "BindingError",
    "CampaignAbort",
    "CampaignOutcome",
    "CapError",
    "ManifestImmutableError",
    "ManifestStore",
    "RunAuthorization",
    "RunCaps",
    "RunConfig",
    "SecureCampaignCoordinator",
    "TargetBinding",
    "operation_hash",
]
