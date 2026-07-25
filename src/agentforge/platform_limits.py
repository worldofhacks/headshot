"""Closed platform ceilings shared by independent validation layers."""

from __future__ import annotations

import math
from typing import Literal

HOSTED_MAX_PHYSICAL_CALLS = 400

CampaignWindowProfile = Literal["standard", "staging_extended"]
CampaignWindowOperation = Literal["campaign", "live_probe"]

CAMPAIGN_AUTHORIZATION_EXECUTION_MARGIN_SECONDS = 300
STANDARD_CAMPAIGN_AUTHORIZATION_MAX_SECONDS = 3_600
STANDARD_CAMPAIGN_DEFAULT_RUN_TIMEOUT_SECONDS = 1_800.0
STAGING_EXTENDED_CAMPAIGN_MAX_RUN_TIMEOUT_SECONDS = 14_400.0
STAGING_EXTENDED_CAMPAIGN_AUTHORIZATION_MAX_SECONDS = 14_701


class CampaignWindowPolicyError(ValueError):
    """A requested authorization window is outside the server-owned policy."""


def campaign_authorization_expiry_seconds(
    run_timeout_seconds: float,
    *,
    profile: CampaignWindowProfile = "standard",
    environment: str,
    operation: CampaignWindowOperation = "campaign",
    submitted_expiry_seconds: int | None = None,
) -> int:
    """Derive one exact grant duration from the selected timeout and closed profile.

    The browser may echo the derived value so the operator can review it. It never becomes
    authority: a supplied value must match this server computation exactly.
    """

    if (
        isinstance(run_timeout_seconds, bool)
        or not isinstance(run_timeout_seconds, (int, float))
        or not math.isfinite(float(run_timeout_seconds))
        or run_timeout_seconds <= 0
    ):
        raise CampaignWindowPolicyError("campaign run timeout is invalid")
    if profile not in {"standard", "staging_extended"}:
        raise CampaignWindowPolicyError("campaign window profile is invalid")
    if operation not in {"campaign", "live_probe"}:
        raise CampaignWindowPolicyError("campaign window operation is invalid")

    if profile == "staging_extended":
        if environment != "staging" or operation != "campaign":
            raise CampaignWindowPolicyError(
                "staging extended campaign window is unavailable for this operation"
            )
        if run_timeout_seconds > STAGING_EXTENDED_CAMPAIGN_MAX_RUN_TIMEOUT_SECONDS:
            raise CampaignWindowPolicyError("staging extended campaign timeout exceeds four hours")
        maximum_expiry = STAGING_EXTENDED_CAMPAIGN_AUTHORIZATION_MAX_SECONDS
    else:
        maximum_expiry = STANDARD_CAMPAIGN_AUTHORIZATION_MAX_SECONDS

    derived = (
        math.floor(float(run_timeout_seconds)) + CAMPAIGN_AUTHORIZATION_EXECUTION_MARGIN_SECONDS + 1
    )
    if derived > maximum_expiry:
        raise CampaignWindowPolicyError(
            "campaign timeout cannot retain the required execution margin"
        )
    if submitted_expiry_seconds is not None and (
        isinstance(submitted_expiry_seconds, bool)
        or not isinstance(submitted_expiry_seconds, int)
        or submitted_expiry_seconds != derived
    ):
        raise CampaignWindowPolicyError("submitted authorization expiry differs from server policy")
    return derived


def campaign_window_template(
    *,
    environment: str,
    target_max_run_timeout_seconds: float,
) -> dict[str, object]:
    """Return non-secret server-owned window metadata for one campaign template."""

    if (
        isinstance(target_max_run_timeout_seconds, bool)
        or not isinstance(target_max_run_timeout_seconds, (int, float))
        or not math.isfinite(float(target_max_run_timeout_seconds))
        or target_max_run_timeout_seconds <= 0
    ):
        raise CampaignWindowPolicyError("target campaign timeout ceiling is invalid")
    default_timeout = min(
        float(target_max_run_timeout_seconds),
        STANDARD_CAMPAIGN_DEFAULT_RUN_TIMEOUT_SECONDS,
    )
    standard_grant_for_target_ceiling = (
        math.floor(float(target_max_run_timeout_seconds))
        + CAMPAIGN_AUTHORIZATION_EXECUTION_MARGIN_SECONDS
        + 1
    )
    extended_available = (
        environment == "staging"
        and standard_grant_for_target_ceiling > STANDARD_CAMPAIGN_AUTHORIZATION_MAX_SECONDS
    )
    return {
        "default_profile": "standard",
        "default_run_timeout_seconds": default_timeout,
        "execution_margin_seconds": CAMPAIGN_AUTHORIZATION_EXECUTION_MARGIN_SECONDS,
        "standard_max_grant_seconds": (STANDARD_CAMPAIGN_AUTHORIZATION_MAX_SECONDS),
        "staging_extended_max_run_timeout_seconds": (
            min(
                float(target_max_run_timeout_seconds),
                STAGING_EXTENDED_CAMPAIGN_MAX_RUN_TIMEOUT_SECONDS,
            )
            if extended_available
            else None
        ),
        "staging_extended_max_grant_seconds": (
            STAGING_EXTENDED_CAMPAIGN_AUTHORIZATION_MAX_SECONDS if extended_available else None
        ),
    }


__all__ = [
    "CAMPAIGN_AUTHORIZATION_EXECUTION_MARGIN_SECONDS",
    "CampaignWindowOperation",
    "CampaignWindowPolicyError",
    "CampaignWindowProfile",
    "HOSTED_MAX_PHYSICAL_CALLS",
    "STAGING_EXTENDED_CAMPAIGN_AUTHORIZATION_MAX_SECONDS",
    "STAGING_EXTENDED_CAMPAIGN_MAX_RUN_TIMEOUT_SECONDS",
    "STANDARD_CAMPAIGN_AUTHORIZATION_MAX_SECONDS",
    "STANDARD_CAMPAIGN_DEFAULT_RUN_TIMEOUT_SECONDS",
    "campaign_authorization_expiry_seconds",
    "campaign_window_template",
]
