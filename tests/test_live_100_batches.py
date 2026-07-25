"""RED tests — the frozen 100-case / 121-physical live corpus, split into 3 authorized batches.

WHY THESE TESTS EXIST
---------------------
``HOSTED_MAX_PHYSICAL_CALLS`` is 56 and the runner does NOT chunk a campaign: it passes the whole
corpus size as one ``case_count`` (``runner.py:~1190``) to ``_require_hosted_workload_capacity``,
which fails closed (``hosted_role_cap_incompatible``) when ``required`` exceeds a role's max_calls
(<= 56). A single 100-case / 121-physical hosted invocation therefore CANNOT run. The authorized
answer (see ``docs/RTG_CORPUS_LANE_HANDOFF.md`` and ``evals/workloads/live-100-batches.json``) is to
submit the SAME frozen corpus as 3 separately-authorized sub-workloads that AGGREGATE EXACTLY to the
100-case / 121-physical whole — with NO cap raise (each batch's per-target physical Sigma(turns) <=
56) and authored/reviewed content ONLY (no synthesis, no mutation).

These tests describe the desired batch-loading behavior and are RED until an implementer:
  * registers ``headshot-live-100-batch-01`` / ``-02`` / ``-03`` in ``TRUSTED_WORKLOAD_IDS`` and
  * teaches ``resolve_workload`` to return each batch as an :class:`AuthoredCorpus` that is a strict
    subset of the frozen ``headshot-live-100-v1`` corpus per ``evals/workloads/live-100-batches.json``.

INVARIANTS THESE TESTS GUARD
----------------------------
1. Each batch resolves to exactly its declared active-case count (34 / 33 / 33), every case is
   schema-valid, and every batch carries >= 1 guaranteed-confirm canary case
   (``oracle_expectation.kind in {synthetic_canary_match, system_prompt_canary_match}`` with a
   non-empty ``canary_ref`` AND ``deterministic is True``). Canary/oracle/human are the ONLY CONFIRM
   authority; the LLM Judge is never CONFIRM.
2. The union of the 3 batches' case ids equals EXACTLY the 100 case ids of ``headshot-live-100-v1``
   — no overlap, no omission (a perfect partition of the frozen corpus).
3. Each batch's Sigma(input_sequence turns) equals the physical count declared in
   ``live-100-batches.json`` AND is <= 56 (``HOSTED_MAX_PHYSICAL_CALLS``, unchanged).
4. Each batch id is a member of ``TRUSTED_WORKLOAD_IDS`` (closed registry).
5. REGRESSION: ``load_live_100_corpus`` still loads exactly 100 cases at the pinned manifest sha
   ``07d649...252d`` — the frozen, shipped whole is untouched by the batch feature.

NO NETWORK / NO TARGET / NO HOSTED CALL. Everything below reads local authored JSON only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agentforge.campaign.corpus import (
    LIVE_100_CASE_COUNT,
    LIVE_100_CORPUS_ID,
    TRUSTED_WORKLOAD_IDS,
    AuthoredCorpus,
    CorpusUnavailable,
    corpus_root,
    load_live_100_corpus,
    resolve_workload,
    reviewed_bundle_root,
)
from agentforge.evals.validation import load_fixture_registry, validate_attack_case

# --------------------------------------------------------------------------------------------
# Frozen, authored constants — mirror the shipped corpus and batch plan on disk.
# --------------------------------------------------------------------------------------------

#: The byte-pinned reviewed manifest digest of the frozen 100-case corpus (see the corpus handoff).
LIVE_100_MANIFEST_SHA256 = "07d649d482dd1f59a70e2b7238506e59eacddb8f39b56c419ccc6aab52ca252d"

#: HOSTED_MAX_PHYSICAL_CALLS — the per-batch physical ceiling that must NOT be raised.
HOSTED_MAX_PHYSICAL_CALLS = 56

#: The three separately-authorized batch workload identities, with their expected active-case count.
BATCH_WORKLOAD_IDS: tuple[str, ...] = (
    "headshot-live-100-batch-01",
    "headshot-live-100-batch-02",
    "headshot-live-100-batch-03",
)
BATCH_EXPECTED_CASE_COUNT = {
    "headshot-live-100-batch-01": 34,
    "headshot-live-100-batch-02": 33,
    "headshot-live-100-batch-03": 33,
}

#: A guaranteed-confirm canary case, per the batch plan's own definition.
_CANARY_KINDS = frozenset({"synthetic_canary_match", "system_prompt_canary_match"})


# --------------------------------------------------------------------------------------------
# Helpers — read the authored batch plan + frozen manifest straight off disk (no network).
# --------------------------------------------------------------------------------------------
def _eval_root() -> Path:
    return corpus_root()


def _batch_plan() -> dict:
    plan_path = _eval_root() / "workloads" / "live-100-batches.json"
    return json.loads(plan_path.read_text(encoding="utf-8"))


def _batch_plan_by_workload_id() -> dict[str, dict]:
    """Map the requested batch WORKLOAD id (``headshot-live-100-batch-01``) to its plan record.

    The authored plan file keys each batch by ``batch_id`` (``live-100-batch-01``); the resolvable
    workload identity carries the corpus's ``headshot-`` namespace. They differ only by that prefix.
    """
    mapping: dict[str, dict] = {}
    for batch in _batch_plan()["batches"]:
        mapping[f"headshot-{batch['batch_id']}"] = batch
    return mapping


def _frozen_instance_id_to_payload() -> dict[str, dict]:
    """The frozen ``headshot-live-100-v1`` corpus keyed by manifest ``instance_id`` (the join key).

    The batch plan lists cases by their ``instance_id`` (``BASE-000`` / ``HOSTED-001`` ...), which is
    the immutable identity carried on :class:`AuthoredCase.instance_id` for a resolved live-100 case.
    """
    manifest_path = _eval_root() / "workloads" / f"{LIVE_100_CORPUS_ID}.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    by_instance: dict[str, dict] = {}
    for entry in manifest["cases"]:
        payload = json.loads((_eval_root() / entry["case_path"]).read_text(encoding="utf-8"))
        by_instance[entry["instance_id"]] = payload
    return by_instance


def _case_instance_ids(corpus: AuthoredCorpus) -> list[str]:
    """The batch-plan join identity for every case in a resolved batch corpus."""
    return [case.instance_id for case in corpus.cases]


def _is_guaranteed_confirm_canary(payload: dict) -> bool:
    oracle = payload.get("oracle_expectation")
    if not isinstance(oracle, dict):
        return False
    return (
        oracle.get("kind") in _CANARY_KINDS
        and isinstance(oracle.get("canary_ref"), str)
        and bool(oracle.get("canary_ref"))
        and oracle.get("deterministic") is True
    )


def _resolve_batch(workload_id: str) -> AuthoredCorpus:
    return resolve_workload(
        workload_id,
        root=corpus_root(),
        bundle_root=reviewed_bundle_root(),
    )


# ============================================================================================
# (4) Each batch id is a member of the closed TRUSTED_WORKLOAD_IDS registry.
# ============================================================================================
@pytest.mark.parametrize("workload_id", BATCH_WORKLOAD_IDS)
def test_batch_id_is_a_trusted_workload_identity(workload_id: str) -> None:
    assert workload_id in TRUSTED_WORKLOAD_IDS, (
        f"{workload_id} must be an admitted, separately-authorized sub-workload identity"
    )


def test_frozen_and_batch_identities_coexist_in_the_closed_registry() -> None:
    # The batch feature ADDS the 3 sub-workloads; it never drops the frozen whole from the registry.
    assert LIVE_100_CORPUS_ID in TRUSTED_WORKLOAD_IDS
    for workload_id in BATCH_WORKLOAD_IDS:
        assert workload_id in TRUSTED_WORKLOAD_IDS


# ============================================================================================
# (1) Each batch resolves to its exact active-case count, all schema-valid, >=1 confirm canary.
# ============================================================================================
@pytest.mark.parametrize("workload_id", BATCH_WORKLOAD_IDS)
def test_batch_resolves_to_its_exact_active_case_count(workload_id: str) -> None:
    corpus = _resolve_batch(workload_id)

    assert isinstance(corpus, AuthoredCorpus)
    assert corpus.corpus_id == workload_id
    assert len(corpus.cases) == BATCH_EXPECTED_CASE_COUNT[workload_id], (
        f"{workload_id} must resolve to exactly {BATCH_EXPECTED_CASE_COUNT[workload_id]} active cases"
    )
    # No duplicated identity inside a batch.
    instance_ids = _case_instance_ids(corpus)
    assert len(set(instance_ids)) == len(instance_ids), f"{workload_id} has a duplicated case identity"


@pytest.mark.parametrize("workload_id", BATCH_WORKLOAD_IDS)
def test_every_batch_case_is_schema_valid(workload_id: str) -> None:
    corpus = _resolve_batch(workload_id)
    fixtures = load_fixture_registry(corpus_root() / "fixtures")

    for case in corpus.cases:
        # A schema-invalid case must raise; a clean return proves schema validity.
        validate_attack_case(
            case.payload,
            source=case.instance_id or case.payload.get("case_id", "<batch-case>"),
            fixture_ids=fixtures.fixture_ids,
            fixture_canaries=fixtures.canaries_by_fixture,
            fixture_versions=fixtures.versions_by_fixture,
            fixture_sources=fixtures.sources_by_fixture,
        )


@pytest.mark.parametrize("workload_id", BATCH_WORKLOAD_IDS)
def test_every_batch_carries_at_least_one_guaranteed_confirm_canary(workload_id: str) -> None:
    corpus = _resolve_batch(workload_id)

    canary_cases = [case for case in corpus.cases if _is_guaranteed_confirm_canary(case.payload)]
    assert len(canary_cases) >= 1, (
        f"{workload_id} must carry >= 1 guaranteed-confirm canary case "
        "(kind in {synthetic_canary_match, system_prompt_canary_match} + canary_ref + deterministic)"
    )


@pytest.mark.parametrize("workload_id", BATCH_WORKLOAD_IDS)
def test_batch_membership_matches_the_authored_batch_plan(workload_id: str) -> None:
    corpus = _resolve_batch(workload_id)
    plan = _batch_plan_by_workload_id()[workload_id]

    assert set(_case_instance_ids(corpus)) == set(plan["case_ids"]), (
        f"{workload_id} membership must equal exactly the authored plan's case_ids"
    )


@pytest.mark.parametrize("workload_id", BATCH_WORKLOAD_IDS)
def test_batch_declared_confirm_canaries_are_present_and_actually_canaries(workload_id: str) -> None:
    corpus = _resolve_batch(workload_id)
    plan = _batch_plan_by_workload_id()[workload_id]
    by_instance = {case.instance_id: case for case in corpus.cases}
    declared = plan["guaranteed_confirm_canary_case_ids"]

    assert declared, f"{workload_id} plan declares no guaranteed-confirm canaries"
    for instance_id in declared:
        assert instance_id in by_instance, (
            f"{workload_id} declared canary {instance_id} is not in the resolved batch"
        )
        assert _is_guaranteed_confirm_canary(by_instance[instance_id].payload), (
            f"{workload_id} declared canary {instance_id} is not actually a guaranteed-confirm canary"
        )


# ============================================================================================
# (2) The union of the 3 batches equals EXACTLY the 100 case ids — no overlap, no omission.
# ============================================================================================
def test_three_batches_partition_the_frozen_100_exactly() -> None:
    frozen_instance_ids = set(_frozen_instance_id_to_payload())
    assert len(frozen_instance_ids) == LIVE_100_CASE_COUNT

    per_batch_ids: list[list[str]] = []
    for workload_id in BATCH_WORKLOAD_IDS:
        corpus = _resolve_batch(workload_id)
        per_batch_ids.append(_case_instance_ids(corpus))

    flattened = [instance_id for batch_ids in per_batch_ids for instance_id in batch_ids]
    union = set(flattened)

    # No omission: the union covers every frozen case.
    assert union == frozen_instance_ids, "the 3 batches must cover EXACTLY the frozen 100 case ids"
    # No overlap: no case appears in two batches (union size == flattened count).
    assert len(flattened) == LIVE_100_CASE_COUNT, "the 3 batches must not overlap or omit any case"
    assert len(union) == len(flattened), "a case id appears in more than one batch"


def test_batch_case_ids_are_a_subset_of_the_frozen_corpus() -> None:
    frozen_instance_ids = set(_frozen_instance_id_to_payload())
    for workload_id in BATCH_WORKLOAD_IDS:
        corpus = _resolve_batch(workload_id)
        assert set(_case_instance_ids(corpus)) <= frozen_instance_ids, (
            f"{workload_id} must contain only cases drawn from the frozen headshot-live-100-v1 corpus"
        )


def test_batch_case_content_matches_the_frozen_corpus_byte_for_byte() -> None:
    """A batch case is the SAME authored case as in the frozen corpus — not a mutated copy."""
    frozen = _frozen_instance_id_to_payload()

    def _canonical_sha256(payload: dict) -> str:
        raw = json.dumps(
            payload, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    for workload_id in BATCH_WORKLOAD_IDS:
        corpus = _resolve_batch(workload_id)
        for case in corpus.cases:
            frozen_payload = frozen[case.instance_id]
            assert case.content_hash == _canonical_sha256(frozen_payload), (
                f"{workload_id}:{case.instance_id} content differs from the frozen corpus case"
            )


# ============================================================================================
# (3) Each batch's Sigma(input_sequence turns) equals the plan's physical count AND is <= 56.
# ============================================================================================
@pytest.mark.parametrize("workload_id", BATCH_WORKLOAD_IDS)
def test_batch_physical_turns_match_plan_and_respect_the_cap(workload_id: str) -> None:
    corpus = _resolve_batch(workload_id)
    plan = _batch_plan_by_workload_id()[workload_id]

    physical_turns = sum(len(case.payload["input_sequence"]) for case in corpus.cases)
    assert physical_turns == plan["physical"], (
        f"{workload_id} Sigma(turns)={physical_turns} must equal the plan's physical={plan['physical']}"
    )
    assert physical_turns <= HOSTED_MAX_PHYSICAL_CALLS, (
        f"{workload_id} physical={physical_turns} must not exceed HOSTED_MAX_PHYSICAL_CALLS "
        f"({HOSTED_MAX_PHYSICAL_CALLS}) — the cap is NOT raised"
    )


def test_three_batches_aggregate_to_the_frozen_121_physical() -> None:
    total_physical = 0
    total_cases = 0
    for workload_id in BATCH_WORKLOAD_IDS:
        corpus = _resolve_batch(workload_id)
        total_physical += sum(len(case.payload["input_sequence"]) for case in corpus.cases)
        total_cases += len(corpus.cases)

    assert total_cases == LIVE_100_CASE_COUNT, "the 3 batches must aggregate to exactly 100 cases"
    assert total_physical == 121, "the 3 batches must aggregate to exactly 121 physical turns"


# ============================================================================================
# expected_content_hash — a batch admits only its own pinned content hash (round-trip + reject).
# ============================================================================================
@pytest.mark.parametrize("workload_id", BATCH_WORKLOAD_IDS)
def test_batch_pins_its_own_content_hash(workload_id: str) -> None:
    corpus = _resolve_batch(workload_id)
    pinned = corpus.content_hash

    # Re-resolving under the pinned content hash succeeds and is byte-stable.
    repinned = resolve_workload(
        workload_id,
        root=corpus_root(),
        bundle_root=reviewed_bundle_root(),
        expected_content_hash=pinned,
    )
    assert repinned.content_hash == pinned
    assert _case_instance_ids(repinned) == _case_instance_ids(corpus)

    # A wrong pin is rejected — the batch is content-addressed like every trusted workload.
    with pytest.raises(CorpusUnavailable, match="expected content hash"):
        resolve_workload(
            workload_id,
            root=corpus_root(),
            bundle_root=reviewed_bundle_root(),
            expected_content_hash="0" * 64,
        )


# ============================================================================================
# (5) REGRESSION — the frozen whole is untouched: 100 cases at the pinned manifest sha.
# ============================================================================================
def test_regression_load_live_100_corpus_still_loads_100_at_the_pinned_sha() -> None:
    corpus = load_live_100_corpus(
        corpus_root(),
        expected_manifest_sha256=LIVE_100_MANIFEST_SHA256,
        bundle_root=reviewed_bundle_root(),
    )

    assert corpus.corpus_id == LIVE_100_CORPUS_ID
    assert len(corpus.cases) == LIVE_100_CASE_COUNT == 100
    assert corpus.content_hash == LIVE_100_MANIFEST_SHA256, (
        "the frozen live-100 manifest digest must remain 07d649...252d, unchanged by the batch feature"
    )
    assert sum(len(case.payload["input_sequence"]) for case in corpus.cases) == 121


def test_regression_resolve_workload_still_loads_the_frozen_live_100_whole() -> None:
    corpus = resolve_workload(
        LIVE_100_CORPUS_ID,
        root=corpus_root(),
        bundle_root=reviewed_bundle_root(),
        expected_content_hash=LIVE_100_MANIFEST_SHA256,
    )
    assert corpus.corpus_id == LIVE_100_CORPUS_ID
    assert len(corpus.cases) == 100
    assert corpus.content_hash == LIVE_100_MANIFEST_SHA256
