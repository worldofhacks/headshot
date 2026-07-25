"""Closed campaign-window policy tests with no database, target, or provider I/O."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentforge.api.router import (
    AuthorizationRequestInput,
    LiveProbeAuthorizationRequestInput,
)
from agentforge.platform_limits import (
    CampaignWindowOperation,
    CampaignWindowPolicyError,
    campaign_authorization_expiry_seconds,
    campaign_window_template,
)


def _request_payload() -> dict[str, object]:
    return {
        "target_id": "target-1",
        "target_version": "1.0.0",
        "surface_id": "chat",
        "surface_version": "1.0.0",
        "corpus_id": "reviewed-corpus",
        "corpus_hash": "c" * 64,
        "execution_profile": "live",
        "run_nonce": "reviewed-run-nonce-0001",
        "caps": {
            "budget_usd": 1,
            "max_attempts_per_run": 100,
            "target_requests_per_second": 0.5,
            "run_timeout_seconds": 900,
        },
    }


def test_standard_profile_preserves_3600_second_ceiling_and_is_default() -> None:
    assert (
        campaign_authorization_expiry_seconds(
            3_299.9,
            environment="staging",
        )
        == 3_600
    )
    with pytest.raises(CampaignWindowPolicyError):
        campaign_authorization_expiry_seconds(
            3_300,
            environment="staging",
        )

    request = AuthorizationRequestInput.model_validate(_request_payload())
    assert request.window_profile == "standard"
    assert request.expires_in_seconds is None


def test_staging_extended_profile_is_exactly_bounded_to_four_hours() -> None:
    assert (
        campaign_authorization_expiry_seconds(
            14_400,
            profile="staging_extended",
            environment="staging",
            submitted_expiry_seconds=14_701,
        )
        == 14_701
    )
    with pytest.raises(CampaignWindowPolicyError):
        campaign_authorization_expiry_seconds(
            14_400.01,
            profile="staging_extended",
            environment="staging",
        )


@pytest.mark.parametrize(
    ("environment", "operation"),
    [
        ("local", "campaign"),
        ("production", "campaign"),
        ("staging", "live_probe"),
    ],
)
def test_staging_extended_profile_is_denied_outside_staging_campaigns(
    environment: str,
    operation: CampaignWindowOperation,
) -> None:
    with pytest.raises(CampaignWindowPolicyError):
        campaign_authorization_expiry_seconds(
            3_600,
            profile="staging_extended",
            environment=environment,
            operation=operation,
        )


def test_live_probe_schema_rejects_extended_profile_before_backend_dispatch() -> None:
    with pytest.raises(ValidationError):
        LiveProbeAuthorizationRequestInput.model_validate(
            {
                **_request_payload(),
                "window_profile": "staging_extended",
                "expires_in_seconds": 3_901,
            }
        )


def test_browser_expiry_echo_must_match_server_derivation() -> None:
    with pytest.raises(CampaignWindowPolicyError):
        campaign_authorization_expiry_seconds(
            900,
            environment="staging",
            submitted_expiry_seconds=1_202,
        )
    assert (
        campaign_authorization_expiry_seconds(
            900,
            environment="staging",
            submitted_expiry_seconds=1_201,
        )
        == 1_201
    )


def test_template_keeps_short_default_when_target_allows_four_hours() -> None:
    staging = campaign_window_template(
        environment="staging",
        target_max_run_timeout_seconds=14_400,
    )
    assert staging == {
        "default_profile": "standard",
        "default_run_timeout_seconds": 1_800.0,
        "execution_margin_seconds": 300,
        "standard_max_grant_seconds": 3_600,
        "staging_extended_max_run_timeout_seconds": 14_400.0,
        "staging_extended_max_grant_seconds": 14_701,
    }

    production = campaign_window_template(
        environment="production",
        target_max_run_timeout_seconds=14_400,
    )
    assert production["default_run_timeout_seconds"] == 1_800.0
    assert production["staging_extended_max_run_timeout_seconds"] is None
    assert production["staging_extended_max_grant_seconds"] is None
