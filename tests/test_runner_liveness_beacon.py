"""The launch-gate liveness beacon must not be starved by the work it reports on.

Staging incident, 2026-07-27. Operators could not start a campaign, receiving either "Runner has
not verified all four hosted provider bindings" or "The private Runner is not ready to accept this
campaign" — from a Runner that was healthy, idle, and holding valid credentials for every role.

The cause was cadence, not readiness. Both status rows were published once per main-loop iteration,
and that iteration's duration is unbounded: ~50 minutes while a 34-case campaign runs, and ~56s
even while idle because the loop performs Langfuse I/O. The Web launch gate bounds the runner row
at 30s and each per-configuration row at 90s, so the beacon lapsed and the gate reported a healthy
worker as unverified. Measured on staging, the runner row oscillated 0 -> 56s against its 30s gate,
leaving the launch button live roughly half the time.

These tests pin the two properties that fix it: the beacon out-paces the gate it feeds, and it
carries nothing that could make it block or mutate campaign state.
"""

from __future__ import annotations

from agentforge.api.postgres import (
    _HOSTED_RUNTIME_HEARTBEAT_FRESHNESS_SECONDS,
    _RUNNER_HEARTBEAT_FRESHNESS_SECONDS,
)
from agentforge.runner import _HEARTBEAT_BEACON_SECONDS, DurableCampaignRunner


def test_the_beacon_out_paces_both_launch_gates() -> None:
    """The gap between two publishes is exactly what the gate measures, so it must stay under it.

    The tighter of the two bounds is what actually failed in staging: the per-configuration rows
    (90s) survived a slow iteration, while the runner row (30s) did not, which is why one operator
    attempt reported unverified bindings and the next reported an unready Runner. Both are read
    from the same publish, so both are pinned here.
    """

    assert _HEARTBEAT_BEACON_SECONDS < _RUNNER_HEARTBEAT_FRESHNESS_SECONDS
    assert _HEARTBEAT_BEACON_SECONDS < _HOSTED_RUNTIME_HEARTBEAT_FRESHNESS_SECONDS

    # Margin, not merely inequality: a beacon that only just beats the gate would flap under any
    # scheduling jitter or a single slow publish, which is the failure being fixed.
    assert _HEARTBEAT_BEACON_SECONDS * 3 <= _RUNNER_HEARTBEAT_FRESHNESS_SECONDS

    # publish_runtime_status throttles the per-configuration rows to 30s internally, so that
    # interval -- not the beacon's -- is what the 90s gate actually sees.
    assert _HOSTED_RUNTIME_HEARTBEAT_FRESHNESS_SECONDS >= 30.0 * 3


def test_the_beacon_publishes_status_and_never_mutates_campaign_state() -> None:
    """It runs on its own thread, so anything it touches races the worker that owns the campaign.

    recover_interrupted_provider_calls closes bounded crash reservations and must therefore stay on
    the main loop: a reservation closed concurrently with the work that owns it would be data loss,
    not a glitch. Asserting against the compiled method rather than the source text so a rename or
    a reformat cannot quietly void the guard.
    """

    published = DurableCampaignRunner.publish_runtime_status.__code__.co_names
    assert "recover_interrupted_provider_calls" not in published
    assert "run_once" not in published
    assert "execute_claimed" not in published
    assert "claim" not in published

    # The recovery duty is not dropped -- it moved to the main-loop path, which is single-threaded
    # and already owns the lease.
    maintained = DurableCampaignRunner.maintain_provider_recovery.__code__.co_names
    assert "recover_interrupted_provider_calls" in maintained

    # And the combined entry point still performs both, so --once and every existing caller keep
    # the behaviour they had before the split.
    combined = DurableCampaignRunner.heartbeat_runtime.__code__.co_names
    assert "maintain_provider_recovery" in combined
    assert "publish_runtime_status" in combined
