"""A scan authorization must carry the exact execution caps, not only the legacy ceiling four.

The console composed an authorization request from ``campaign_template``, which published the
target's four editable ceiling caps and nothing else. That scope is accepted at request time and
approved normally — and then refused at launch, because ``record_physical_work_unit`` requires the
authorized scope to carry a durable ``physical_request_limit`` and ``target_retries_per_turn``
before it will record a single physical work unit. The operator saw only an unexplained 403.

The suite batches never hit this: they publish ``physical_request_count`` and their
``maximum_caps`` already carry the exact three, so the console spreads them verbatim. The
single-corpus template published neither.

These tests pin the missing half of that contract: the count is derived exactly the way the Runner
derives it, every template publishes it, and the caps built from a template satisfy the control
plane's durability requirement.
"""

from __future__ import annotations

import pytest

from agentforge.api.postgres import _corpus_physical_request_count
from agentforge.campaign.corpus import (
    FULL_SCAN_CORPUS_ID,
    LIVE_100_BATCH_SPECS,
    resolve_workload,
)


def _runner_derivation(corpus) -> int:
    """The Runner's own exact-manifest derivation, restated here as the oracle.

    ``runner.py`` computes ``sum(len(payload["input_sequence"]))`` over the verified payloads. If
    the projection ever diverges from this, an exact-manifest workload authorized from the console
    would be refused with ``exact_request_caps_mismatch``.
    """

    return sum(len(case.payload["input_sequence"]) for case in corpus.cases)


# ---------------------------------------------------------------------------------------
# The derivation itself.
# ---------------------------------------------------------------------------------------


def test_the_scan_corpus_physical_count_is_sigma_turns_not_case_count() -> None:
    """14 cases span 17 turns. Sending the case count as the physical limit would under-size it."""

    corpus = resolve_workload(FULL_SCAN_CORPUS_ID)

    assert len(corpus.cases) == 14
    assert _corpus_physical_request_count(corpus) == 17
    assert _corpus_physical_request_count(corpus) > len(corpus.cases), "multi-turn cases exist"


def test_the_projection_matches_the_runner_derivation_for_every_trusted_workload() -> None:
    """One derivation, two consumers. Divergence is an exact_request_caps_mismatch at dispatch."""

    for workload_id in (FULL_SCAN_CORPUS_ID, *LIVE_100_BATCH_SPECS):
        corpus = resolve_workload(workload_id)
        assert _corpus_physical_request_count(corpus) == _runner_derivation(corpus), workload_id


def test_each_live_suite_batch_matches_its_pinned_manifest_count() -> None:
    """The batches already publish a pinned physical count; the shared helper must agree with it."""

    for batch_id, spec in LIVE_100_BATCH_SPECS.items():
        corpus = resolve_workload(batch_id)
        assert _corpus_physical_request_count(corpus) == spec["physical"], batch_id
        assert len(corpus.cases) == spec["case_count"], batch_id


def test_an_empty_corpus_counts_zero_rather_than_raising() -> None:
    """The read model rejects a zero count; the helper must not mask that with an exception."""

    class _Empty:
        cases: tuple = ()

    assert _corpus_physical_request_count(_Empty()) == 0


# ---------------------------------------------------------------------------------------
# The read model requires the count on every template, not just batches.
# ---------------------------------------------------------------------------------------


def test_a_template_without_a_physical_request_count_is_rejected() -> None:
    """This is the shape the projection used to emit, and it must no longer validate."""

    from pydantic import ValidationError

    from agentforge.api.read_models import CampaignTemplateReadModel

    legacy = {
        "target_id": "clinical-copilot-week1",
        "target_version": "1.0.1",
        "surface_id": "week1-chat",
        "surface_version": "1.0.1",
        "corpus_id": FULL_SCAN_CORPUS_ID,
        "corpus_hash": "a" * 64,
        "case_count": 14,
        "tool_sources": (),
        "execution_profile": "live",
        "maximum_caps": {
            "budget_usd": "5",
            "max_attempts_per_run": 14,
            "target_requests_per_second": 0.5,
            "run_timeout_seconds": 7200.0,
        },
        "hosted_run": None,
    }

    with pytest.raises(ValidationError):
        CampaignTemplateReadModel.model_validate(legacy)

    CampaignTemplateReadModel.model_validate({**legacy, "physical_request_count": 17})


# ---------------------------------------------------------------------------------------
# Caps composed from a template satisfy the control plane.
# ---------------------------------------------------------------------------------------


def _console_caps(corpus) -> dict:
    """Exactly what the console now composes from a campaign_template."""

    return {
        "budget_usd": 5.0,
        "max_attempts_per_run": len(corpus.cases),
        "target_requests_per_second": 0.5,
        "run_timeout_seconds": 7200.0,
        "logical_case_limit": len(corpus.cases),
        "physical_request_limit": _corpus_physical_request_count(corpus),
        "target_retries_per_turn": 0,
    }


def test_caps_built_from_the_template_carry_every_cap_the_control_plane_requires() -> None:
    """``record_physical_work_unit`` refuses a scope missing either durable execution cap."""

    from agentforge.campaign.caps import RunCaps

    corpus = resolve_workload(FULL_SCAN_CORPUS_ID)
    policy = RunCaps.parse(_console_caps(corpus))

    # The two the store dereferences before it will record any physical work unit.
    assert policy.physical_request_limit is not None
    assert policy.target_retries_per_turn is not None
    # Zero, not absent: a retried turn would replay a live attack against the target.
    assert policy.target_retries_per_turn == 0
    assert policy.physical_request_limit == 17
    assert policy.logical_case_limit == 14


def test_the_legacy_four_cap_scope_is_refused_by_the_parser() -> None:
    """Pins the defect: the caps the console used to send do not parse into a launchable policy."""

    from agentforge.campaign.caps import CapError, RunCaps

    legacy = {
        "budget_usd": 5.0,
        "max_attempts_per_run": 14,
        "target_requests_per_second": 0.5,
        "run_timeout_seconds": 7200.0,
    }

    with pytest.raises(CapError):
        RunCaps.parse(legacy)
