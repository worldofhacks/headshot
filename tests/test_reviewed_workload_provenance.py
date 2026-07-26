"""The reviewed live-100 workload is admissible, and its provenance is truthful.

Two defects made ``headshot-live-100-v1`` unusable and both are covered here.

Category. The workload is authored across six categories while the control plane accepted three,
so every ``state_corruption`` / ``denial_of_service`` / ``identity_role_exploitation`` case was
rejected the instant an attempt was created — and because one rejection aborts the whole campaign,
the workload could never complete. Widening the ACCEPT-LIST must not move the MVP coverage FLOOR,
so both properties are asserted together.

Provenance. ``source_tool`` was being populated with the producer kind ``hosted_red_team``, which
is not a security tool, while the nine hand-authored seed cases carried a ``source_technique``
with no tool at all. These tests pin the exact truthful split — 9 / 5 / 86 by producer and
Garak 1 / Promptfoo 1 / PyRIT 3 / null 95 by tool — so a future change cannot quietly re-inflate
tool coverage.

Nothing here asserts that the 100 cases have EXECUTED. They remain NOT_EXECUTED; these tests only
prove they would be admitted.
"""

from __future__ import annotations

from collections import Counter

import pytest

from agentforge.campaign.corpus import (
    LIVE_100_BATCH_IDS,
    MVP_CATEGORIES,
    AuthoredCase,
    CorpusUnavailable,
    _restore_reviewed_tool_lineage,
    load_full_scan_corpus,
    load_live_100_corpus,
    load_mvp_corpus,
    resolve_workload,
    verified_case_payload,
)
from agentforge.case_taxonomy import (
    MVP_REQUIRED_CATEGORIES,
    REVIEWED_WORKLOAD_SOURCE_KINDS,
    SUPPORTED_CASE_CATEGORIES,
)
from agentforge.security_tools.catalog import SECURITY_TOOL_CATALOG

LIVE_100_MANIFEST_SHA256 = "07d649d482dd1f59a70e2b7238506e59eacddb8f39b56c419ccc6aab52ca252d"

#: The reviewed category balance. Pinned literally: if the workload is ever re-authored these
#: numbers must be updated deliberately, not absorbed silently.
EXPECTED_CATEGORY_COUNTS = {
    "prompt_injection": 20,
    "data_exfiltration": 18,
    "tool_misuse": 18,
    "state_corruption": 15,
    "denial_of_service": 14,
    "identity_role_exploitation": 15,
}

EXPECTED_SOURCE_KIND_COUNTS = {
    "m11_seed": 9,
    "reviewed_full_scan": 5,
    "hosted_red_team": 86,
}

#: 95 cases have NO tool: 9 hand-authored seeds + 86 hosted variants. Only the five reviewed
#: full-scan cases name a real scanner.
EXPECTED_TOOL_COUNTS = {None: 95, "garak": 1, "promptfoo": 1, "pyrit": 3}


@pytest.fixture(scope="module")
def live_100():
    return load_live_100_corpus(expected_manifest_sha256=LIVE_100_MANIFEST_SHA256)


# --------------------------------------------------------------------------------------
# Taxonomy: the accept-list widened, the coverage floor did not.
# --------------------------------------------------------------------------------------


def test_supported_categories_are_exactly_the_six_reviewed_categories() -> None:
    assert set(EXPECTED_CATEGORY_COUNTS) == SUPPORTED_CASE_CATEGORIES


def test_mvp_floor_is_unchanged_and_is_a_strict_subset_of_supported() -> None:
    assert {"prompt_injection", "data_exfiltration", "tool_misuse"} == MVP_REQUIRED_CATEGORIES
    # The corpus-level MVP identity check is a separate constant and must not have moved.
    assert MVP_CATEGORIES == MVP_REQUIRED_CATEGORIES
    assert MVP_REQUIRED_CATEGORIES < SUPPORTED_CASE_CATEGORIES


def test_a_six_category_run_satisfies_the_three_category_floor() -> None:
    """The floor is a MINIMUM. Equality would fail a run precisely for covering more ground."""

    six = set(EXPECTED_CATEGORY_COUNTS)
    assert MVP_REQUIRED_CATEGORIES.issubset(six)
    assert six != MVP_REQUIRED_CATEGORIES


def test_a_legacy_three_category_run_still_satisfies_the_floor() -> None:
    legacy = {"prompt_injection", "data_exfiltration", "tool_misuse"}
    assert MVP_REQUIRED_CATEGORIES.issubset(legacy)


def test_hosted_red_team_is_a_source_kind_and_never_a_security_tool() -> None:
    catalog_ids = {tool.tool_id for tool in SECURITY_TOOL_CATALOG}
    assert "hosted_red_team" in REVIEWED_WORKLOAD_SOURCE_KINDS
    assert "hosted_red_team" not in catalog_ids


# --------------------------------------------------------------------------------------
# The immutable workload: shape, provenance, and hash stability.
# --------------------------------------------------------------------------------------


def test_live_100_manifest_hash_is_unchanged(live_100) -> None:
    assert live_100.content_hash == LIVE_100_MANIFEST_SHA256
    assert len(live_100.cases) == 100


def test_every_case_content_hash_still_verifies(live_100) -> None:
    """``verified_case_payload`` re-hashes the payload and refuses on any drift."""

    for case in live_100.cases:
        assert verified_case_payload(case)["case_id"]


def test_category_distribution_is_unchanged(live_100) -> None:
    counts = Counter(verified_case_payload(case)["category"] for case in live_100.cases)
    assert dict(counts) == EXPECTED_CATEGORY_COUNTS


def test_source_kind_counts_are_exactly_nine_five_and_eighty_six(live_100) -> None:
    counts = Counter(case.source_kind for case in live_100.cases)
    assert dict(counts) == EXPECTED_SOURCE_KIND_COUNTS


def test_tool_provenance_is_exactly_garak_one_promptfoo_one_pyrit_three(live_100) -> None:
    counts = Counter(case.source_tool for case in live_100.cases)
    assert dict(counts) == EXPECTED_TOOL_COUNTS


def test_no_hosted_case_is_counted_as_a_security_tool_case(live_100) -> None:
    for case in live_100.cases:
        if case.source_kind == "hosted_red_team":
            assert case.source_tool is None
            assert case.source_technique is None


def test_seed_cases_carry_no_tool_lineage(live_100) -> None:
    seeds = [case for case in live_100.cases if case.source_kind == "m11_seed"]
    assert len(seeds) == 9
    for case in seeds:
        assert case.source_tool is None
        assert case.source_technique is None


def test_tool_lineage_is_always_a_complete_pair(live_100) -> None:
    for case in live_100.cases:
        assert (case.source_tool is None) == (case.source_technique is None)


def test_only_catalog_tools_appear_as_source_tool(live_100) -> None:
    catalog_ids = {tool.tool_id for tool in SECURITY_TOOL_CATALOG}
    for case in live_100.cases:
        if case.source_tool is not None:
            assert case.source_tool in catalog_ids


def test_tool_sources_exclude_the_producer_kind(live_100) -> None:
    assert live_100.tool_sources == ("garak", "promptfoo", "pyrit")
    assert "hosted_red_team" not in live_100.tool_sources


def test_each_tool_case_keeps_its_exact_technique_from_the_pinned_baseline(live_100) -> None:
    """Tool identity is joined from the hash-verified baseline, never inferred from case names."""

    baseline = {
        case.payload["case_id"]: (case.content_hash, case.source_tool, case.source_technique)
        for case in load_full_scan_corpus().cases
        if case.source_tool is not None
    }
    assert len(baseline) == 5
    matched = 0
    for case in live_100.cases:
        if case.source_kind != "reviewed_full_scan":
            continue
        expected_hash, expected_tool, expected_technique = baseline[case.payload["case_id"]]
        assert case.content_hash == expected_hash
        assert case.source_tool == expected_tool
        assert case.source_technique == expected_technique
        matched += 1
    assert matched == 5


def test_reviewed_lineage_tuple_is_complete_for_every_case(live_100) -> None:
    for case in live_100.cases:
        assert case.source_kind in REVIEWED_WORKLOAD_SOURCE_KINDS
        assert isinstance(case.instance_id, str) and case.instance_id
        assert isinstance(case.review_record_sha256, str) and len(case.review_record_sha256) == 64
        assert (
            isinstance(case.source_generation_sha256, str)
            and len(case.source_generation_sha256) == 64
        )


# --------------------------------------------------------------------------------------
# Batches inherit identical provenance.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("batch_id", LIVE_100_BATCH_IDS)
def test_batches_carry_the_same_truthful_provenance(batch_id: str) -> None:
    batch = resolve_workload(batch_id)
    for case in batch.cases:
        assert case.source_kind in REVIEWED_WORKLOAD_SOURCE_KINDS
        assert (case.source_tool is None) == (case.source_technique is None)
        if case.source_kind != "reviewed_full_scan":
            assert case.source_tool is None
    assert "hosted_red_team" not in batch.tool_sources


def test_batches_together_reproduce_the_whole_workload_provenance() -> None:
    kinds: Counter[str] = Counter()
    tools: Counter[str | None] = Counter()
    for batch_id in LIVE_100_BATCH_IDS:
        for case in resolve_workload(batch_id).cases:
            kinds[case.source_kind] += 1
            tools[case.source_tool] += 1
    assert dict(kinds) == EXPECTED_SOURCE_KIND_COUNTS
    assert dict(tools) == EXPECTED_TOOL_COUNTS


# --------------------------------------------------------------------------------------
# Legacy corpora are untouched.
# --------------------------------------------------------------------------------------


def test_legacy_nine_case_corpus_is_unchanged() -> None:
    corpus = load_mvp_corpus()
    assert len(corpus.cases) == 9
    assert corpus.categories == MVP_CATEGORIES
    for case in corpus.cases:
        assert case.source_kind is None
        assert case.source_tool is None


def test_legacy_fourteen_case_corpus_is_unchanged() -> None:
    corpus = load_full_scan_corpus()
    assert len(corpus.cases) == 14
    assert corpus.tool_sources == ("garak", "promptfoo", "pyrit")
    assert Counter(case.source_tool for case in corpus.cases) == {
        None: 9,
        "garak": 1,
        "promptfoo": 1,
        "pyrit": 3,
    }
    # The full-scan corpus predates reviewed workloads and carries no producer lineage.
    for case in corpus.cases:
        assert case.source_kind is None


# --------------------------------------------------------------------------------------
# The lineage join fails closed.
# --------------------------------------------------------------------------------------


def _case(**overrides) -> AuthoredCase:
    base = {
        "payload": {"case_id": "AF-TEST-001"},
        "content_hash": "a" * 64,
        "source_kind": "hosted_red_team",
    }
    base.update(overrides)
    return AuthoredCase(**base)


def test_join_refuses_a_reviewed_case_absent_from_the_baseline() -> None:
    baseline = load_full_scan_corpus()
    orphan = _case(source_kind="reviewed_full_scan")
    with pytest.raises(CorpusUnavailable):
        _restore_reviewed_tool_lineage([orphan], baseline)


def test_join_refuses_a_reviewed_case_whose_content_hash_differs() -> None:
    baseline = load_full_scan_corpus()
    tool_case = next(case for case in baseline.cases if case.source_tool is not None)
    tampered = _case(
        payload=dict(tool_case.payload),
        content_hash="b" * 64,
        source_kind="reviewed_full_scan",
    )
    with pytest.raises(CorpusUnavailable):
        _restore_reviewed_tool_lineage([tampered], baseline)


def test_join_refuses_tool_lineage_on_a_non_tool_source_kind() -> None:
    """A hosted or seed case may not arrive already carrying a tool identity."""

    baseline = load_full_scan_corpus()
    smuggled = _case(source_kind="hosted_red_team", source_tool="garak", source_technique="dan")
    with pytest.raises(CorpusUnavailable):
        _restore_reviewed_tool_lineage([smuggled], baseline)
