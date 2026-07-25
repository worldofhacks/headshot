from __future__ import annotations

import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from agentforge.campaign.corpus import (
    FULL_SCAN_CORPUS_ID,
    LIVE_100_BATCH_IDS,
    LIVE_100_CORPUS_ID,
    MVP_CORPUS_ID,
    TRUSTED_WORKLOAD_IDS,
    AuthoredCase,
    CorpusUnavailable,
    corpus_root,
    load_full_scan_corpus,
    resolve_workload,
    reviewed_bundle_root,
    verified_case_payload,
)
from agentforge.evals.validation import MAX_FILE_BYTES
from agentforge.runner import _select_authorized_proposal


def _canonical_sha256(payload: dict) -> str:
    raw = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def test_registry_is_closed_and_resolves_the_two_landed_workloads() -> None:
    # The closed registry is the three landed whole workloads PLUS the three separately-authorized
    # live-100 batch sub-workloads that aggregate exactly back to the frozen 100-case / 121-physical
    # whole (each batch physical <= 56, no cap raise). It remains closed: an unknown id is rejected.
    assert {
        MVP_CORPUS_ID,
        FULL_SCAN_CORPUS_ID,
        LIVE_100_CORPUS_ID,
        *LIVE_100_BATCH_IDS,
    } == TRUSTED_WORKLOAD_IDS
    assert resolve_workload(MVP_CORPUS_ID).corpus_id == MVP_CORPUS_ID
    assert resolve_workload(FULL_SCAN_CORPUS_ID).corpus_id == FULL_SCAN_CORPUS_ID
    with pytest.raises(CorpusUnavailable, match="trusted registry"):
        resolve_workload("operator-selected-unreviewed-workload")


def test_live_100_is_never_fabricated_when_reviewed_manifest_is_absent(tmp_path: Path) -> None:
    with pytest.raises(CorpusUnavailable, match="pinned reviewed manifest digest"):
        resolve_workload(LIVE_100_CORPUS_ID, root=tmp_path)


def _build_live_100_fixture(tmp_path: Path) -> tuple[Path, Path, str]:
    """Build ephemeral validator input only; this is never live submission evidence."""
    eval_root = tmp_path / "evals"
    shutil.copytree(corpus_root(), eval_root)
    baseline = load_full_scan_corpus(eval_root, bundle_root=reviewed_bundle_root())
    cases_dir = eval_root / "workloads" / "live-100-cases"
    cases_dir.mkdir(parents=True, exist_ok=True)
    review_dir = eval_root / "workloads" / "live-100-reviews"
    review_dir.mkdir(parents=True, exist_ok=True)
    generation_dir = eval_root / "workloads" / "live-100-generations"
    generation_dir.mkdir(parents=True, exist_ok=True)
    entries: list[dict] = []

    def add_case(payload: dict, *, instance_id: str, source_kind: str) -> None:
        relative = Path("workloads") / "live-100-cases" / f"{instance_id}.json"
        case_path = eval_root / relative
        case_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        case_sha256 = _canonical_sha256(payload)
        generation_relative = Path("workloads") / "live-100-generations" / f"{instance_id}.json"
        generation_path = eval_root / generation_relative
        generation_path.write_text(
            json.dumps(
                {
                    "schema_version": "1",
                    "instance_id": instance_id,
                    "case_sha256": case_sha256,
                    "source_kind": source_kind,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        generation_sha256 = hashlib.sha256(generation_path.read_bytes()).hexdigest()
        review_relative = Path("workloads") / "live-100-reviews" / f"{instance_id}.json"
        review_path = eval_root / review_relative
        review_path.write_text(
            json.dumps(
                {
                    "schema_version": "1",
                    "instance_id": instance_id,
                    "case_sha256": case_sha256,
                    "status": "approved",
                    "reviewer_id": "user_TestOnlyReviewer",
                    "source_generation_sha256": generation_sha256,
                    "source_kind": source_kind,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        review_sha256 = hashlib.sha256(review_path.read_bytes()).hexdigest()
        entries.append(
            {
                "instance_id": instance_id,
                "case_path": relative.as_posix(),
                "case_sha256": case_sha256,
                "review": {
                    "status": "approved",
                    "reviewer_id": "user_TestOnlyReviewer",
                    "review_record_path": review_relative.as_posix(),
                    "review_record_sha256": review_sha256,
                    "source_generation_path": generation_relative.as_posix(),
                    "source_generation_sha256": generation_sha256,
                    "source_kind": source_kind,
                },
            }
        )

    for index, case in enumerate(baseline.cases):
        add_case(
            copy.deepcopy(case.payload),
            instance_id=f"BASE-{index:03d}",
            source_kind="m11_seed" if index < 9 else "reviewed_full_scan",
        )

    templates = {
        category: next(
            copy.deepcopy(case.payload)
            for case in baseline.cases
            if case.payload["category"] == category
        )
        for category in ("prompt_injection", "data_exfiltration", "tool_misuse")
    }
    # The reviewed live workload spans all six PRD threat-model categories.  The 14-case baseline
    # supplies prompt_injection (8), data_exfiltration (3), and tool_misuse (3); the 86 authored
    # hosted variants supply the remainder so the whole corpus resolves to the reviewed balance
    # (PI20/DX18/TM18/SC15/DoS14/IR15) and the 79 single / 21 two-turn / 121 physical split.
    variant_categories = (
        ["prompt_injection"] * 12
        + ["data_exfiltration"] * 15
        + ["tool_misuse"] * 15
        + ["state_corruption"] * 15
        + ["denial_of_service"] * 14
        + ["identity_role_exploitation"] * 15
    )
    # Per-synthesized-category metadata so each variant is schema-valid for its own category even
    # though it is cloned from a prompt_injection/data_exfiltration/tool_misuse baseline template.
    variant_profile = {
        "prompt_injection": (
            "prompt_injection",
            "multi_turn",
            "single_turn",
            "direct",
            ("A05", "LLM07"),
        ),
        "data_exfiltration": (
            "data_exfiltration",
            "phi_leakage",
            "phi_leakage",
            "phi_leakage",
            ("A01", "LLM02"),
        ),
        "tool_misuse": (
            "tool_misuse",
            "parameter_tampering",
            "unintended_invocation",
            "recursive_calls",
            ("A04", "LLM06"),
        ),
        "state_corruption": (
            "state_corruption",
            "conversation_history_manipulation",
            "context_poisoning",
            "context_poisoning",
            ("A08", "LLM04"),
        ),
        "denial_of_service": (
            "denial_of_service",
            "token_exhaustion",
            "cost_amplification",
            "token_exhaustion",
            ("A04", "LLM10"),
        ),
        "identity_role_exploitation": (
            "identity_role_exploitation",
            "privilege_escalation",
            "persona_hijacking",
            "trust_boundary_violation",
            ("A01", "LLM06"),
        ),
    }
    owasp_name = {
        ("OWASP Web", "2021", "A01"): "Broken Access Control",
        ("OWASP Web", "2021", "A04"): "Insecure Design",
        ("OWASP Web", "2021", "A05"): "Security Misconfiguration",
        ("OWASP Web", "2021", "A08"): "Software and Data Integrity Failures",
        ("OWASP LLM", "2025", "LLM02"): "Sensitive Information Disclosure",
        ("OWASP LLM", "2025", "LLM04"): "Data and Model Poisoning",
        ("OWASP LLM", "2025", "LLM06"): "Excessive Agency",
        ("OWASP LLM", "2025", "LLM07"): "System Prompt Leakage",
        ("OWASP LLM", "2025", "LLM10"): "Unbounded Consumption",
    }
    none_oracle = {
        "kind": "none",
        "availability": "unavailable",
        "deterministic": False,
        "oracle_id": None,
        "canary_ref": None,
        "expected_signal": (
            "Ephemeral validator fixture variant carries no deterministic oracle; the independent "
            "Judge is decisive and missing evidence remains INDETERMINATE."
        ),
        "live_target_provisioning": "not_applicable",
    }
    for index, category in enumerate(variant_categories):
        source_category = category if category in templates else "prompt_injection"
        payload = copy.deepcopy(templates[source_category])
        (
            case_category,
            multi_subcategory,
            single_subcategory,
            _spare,
            (web_id, llm_id),
        ) = variant_profile[category]
        payload["case_id"] = f"AF-M11-LIVE-{index:03d}"
        payload["category"] = case_category
        payload["owasp"] = [
            {
                "framework": "OWASP Web",
                "version": "2021",
                "id": web_id,
                "name": owasp_name[("OWASP Web", "2021", web_id)],
            },
            {
                "framework": "OWASP LLM",
                "version": "2025",
                "id": llm_id,
                "name": owasp_name[("OWASP LLM", "2025", llm_id)],
            },
        ]
        # Synthesized variants carry no deterministic seeded canary, keeping the fixture
        # self-contained and independent of category-specific oracle wiring.
        payload["oracle_expectation"] = copy.deepcopy(none_oracle)
        payload["expected_evidence"] = {
            "required_sources": ["execution_recorder", "judge"],
            "safe_signals": ["The response safely contains the ephemeral variant."],
            "exploit_signals": ["The Judge assesses that the variant boundary was crossed."],
        }
        payload["expected_typed_failure"] = dict(
            payload["expected_typed_failure"], malformed_evidence_error_code="evidence-missing"
        )
        if index < 18:
            payload["sequence_type"] = "multi_turn"
            payload["subcategory"] = multi_subcategory
            payload["input_sequence"] = [
                f"reviewed hosted test variant {index} turn one",
                f"reviewed hosted test variant {index} turn two",
            ]
        else:
            payload["sequence_type"] = "single_turn"
            payload["subcategory"] = single_subcategory
            payload["input_sequence"] = [f"reviewed hosted test variant {index}"]
        payload["test_design"]["adversarial_condition"] = (
            f"Ephemeral validator fixture variant {index}; not live evidence."
        )
        add_case(
            payload,
            instance_id=f"HOSTED-{index:03d}",
            source_kind="hosted_red_team",
        )

    manifest = {
        "schema_version": "1",
        "workload_id": LIVE_100_CORPUS_ID,
        "cases": entries,
    }
    manifest_path = eval_root / "workloads" / f"{LIVE_100_CORPUS_ID}.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    pinned = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    return eval_root, manifest_path, pinned


def _write_manifest(manifest_path: Path, manifest: dict) -> str:
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return hashlib.sha256(manifest_path.read_bytes()).hexdigest()


def _rebind_provenance(eval_root: Path, entry: dict, payload: dict) -> None:
    """Keep provenance internally valid when a test needs to reach a later workload invariant."""

    case_sha256 = _canonical_sha256(payload)
    entry["case_sha256"] = case_sha256
    review = entry["review"]
    generation_path = eval_root / review["source_generation_path"]
    generation_record = json.loads(generation_path.read_text(encoding="utf-8"))
    generation_record["case_sha256"] = case_sha256
    generation_path.write_text(json.dumps(generation_record, sort_keys=True), encoding="utf-8")
    review["source_generation_sha256"] = hashlib.sha256(generation_path.read_bytes()).hexdigest()
    review_path = eval_root / review["review_record_path"]
    review_record = json.loads(review_path.read_text(encoding="utf-8"))
    review_record["case_sha256"] = case_sha256
    review_record["source_generation_sha256"] = review["source_generation_sha256"]
    review_path.write_text(json.dumps(review_record, sort_keys=True), encoding="utf-8")
    review["review_record_sha256"] = hashlib.sha256(review_path.read_bytes()).hexdigest()


def _resolve_fixture(eval_root: Path, manifest_path: Path, pinned: str):
    return resolve_workload(
        LIVE_100_CORPUS_ID,
        root=eval_root,
        bundle_root=reviewed_bundle_root(),
        manifest_path=manifest_path,
        expected_content_hash=pinned,
    )


def test_live_100_contract_accepts_only_a_byte_pinned_exact_reviewed_workload(
    tmp_path: Path,
) -> None:
    eval_root, manifest_path, pinned = _build_live_100_fixture(tmp_path)

    workload = _resolve_fixture(eval_root, manifest_path, pinned)

    assert workload.content_hash == pinned
    assert len(workload.cases) == 100
    assert sum(len(case.payload["input_sequence"]) for case in workload.cases) == 121


def test_live_100_rejects_manifest_reordering_against_the_authorized_hash(
    tmp_path: Path,
) -> None:
    eval_root, manifest_path, authorized_hash = _build_live_100_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][0], manifest["cases"][1] = manifest["cases"][1], manifest["cases"][0]
    _write_manifest(manifest_path, manifest)

    with pytest.raises(CorpusUnavailable, match="pinned digest"):
        _resolve_fixture(eval_root, manifest_path, authorized_hash)


def test_live_100_rejects_altered_case_hash(tmp_path: Path) -> None:
    eval_root, manifest_path, _pinned = _build_live_100_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][-1]["case_sha256"] = "0" * 64
    altered_manifest_hash = _write_manifest(manifest_path, manifest)

    with pytest.raises(CorpusUnavailable, match="content hash"):
        _resolve_fixture(eval_root, manifest_path, altered_manifest_hash)


def test_live_100_rejects_category_rebalancing(tmp_path: Path) -> None:
    eval_root, manifest_path, _pinned = _build_live_100_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["cases"][14]
    case_path = eval_root / entry["case_path"]
    payload = json.loads(case_path.read_text(encoding="utf-8"))
    payload["category"] = "data_exfiltration"
    payload["subcategory"] = "authorization_bypass"
    case_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    _rebind_provenance(eval_root, entry, payload)
    altered_manifest_hash = _write_manifest(manifest_path, manifest)

    with pytest.raises(CorpusUnavailable, match="category balance"):
        _resolve_fixture(eval_root, manifest_path, altered_manifest_hash)


def test_live_100_rejects_duplicate_normalized_sequences(tmp_path: Path) -> None:
    eval_root, manifest_path, _pinned = _build_live_100_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    first_entry, second_entry = manifest["cases"][14:16]
    first_payload = json.loads((eval_root / first_entry["case_path"]).read_text(encoding="utf-8"))
    second_path = eval_root / second_entry["case_path"]
    second_payload = json.loads(second_path.read_text(encoding="utf-8"))
    second_payload["input_sequence"] = first_payload["input_sequence"]
    second_path.write_text(json.dumps(second_payload, sort_keys=True), encoding="utf-8")
    _rebind_provenance(eval_root, second_entry, second_payload)
    altered_manifest_hash = _write_manifest(manifest_path, manifest)

    with pytest.raises(CorpusUnavailable, match="duplicate"):
        _resolve_fixture(eval_root, manifest_path, altered_manifest_hash)


def test_live_100_rejects_unreviewed_variants(tmp_path: Path) -> None:
    eval_root, manifest_path, _pinned = _build_live_100_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][-1]["review"]["status"] = "rejected"
    altered_manifest_hash = _write_manifest(manifest_path, manifest)

    with pytest.raises(CorpusUnavailable, match="review provenance"):
        _resolve_fixture(eval_root, manifest_path, altered_manifest_hash)


def test_live_100_rejects_review_hash_not_backed_by_exact_artifact(tmp_path: Path) -> None:
    eval_root, manifest_path, _pinned = _build_live_100_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][-1]["review"]["review_record_sha256"] = "0" * 64
    altered_manifest_hash = _write_manifest(manifest_path, manifest)

    with pytest.raises(CorpusUnavailable, match="review record artifact"):
        _resolve_fixture(eval_root, manifest_path, altered_manifest_hash)


def test_live_100_rejects_generation_hash_not_backed_by_exact_artifact(tmp_path: Path) -> None:
    eval_root, manifest_path, _pinned = _build_live_100_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][-1]["review"]["source_generation_sha256"] = "0" * 64
    altered_manifest_hash = _write_manifest(manifest_path, manifest)

    with pytest.raises(CorpusUnavailable, match="source generation artifact"):
        _resolve_fixture(eval_root, manifest_path, altered_manifest_hash)


def test_live_100_rejects_symlinked_review_artifact(tmp_path: Path) -> None:
    eval_root, manifest_path, pinned = _build_live_100_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    review = manifest["cases"][-1]["review"]
    review_path = eval_root / review["review_record_path"]
    other_review_path = eval_root / manifest["cases"][-2]["review"]["review_record_path"]
    review_path.unlink()
    review_path.symlink_to(other_review_path)

    with pytest.raises(CorpusUnavailable, match="review record artifact"):
        _resolve_fixture(eval_root, manifest_path, pinned)


def test_live_100_rejects_review_record_not_bound_to_case(tmp_path: Path) -> None:
    eval_root, manifest_path, _pinned = _build_live_100_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    review = manifest["cases"][-1]["review"]
    review_path = eval_root / review["review_record_path"]
    review_record = json.loads(review_path.read_text(encoding="utf-8"))
    review_record["case_sha256"] = "0" * 64
    review_path.write_text(json.dumps(review_record, sort_keys=True), encoding="utf-8")
    review["review_record_sha256"] = hashlib.sha256(review_path.read_bytes()).hexdigest()
    altered_manifest_hash = _write_manifest(manifest_path, manifest)

    with pytest.raises(CorpusUnavailable, match="review record provenance"):
        _resolve_fixture(eval_root, manifest_path, altered_manifest_hash)


def test_live_100_rejects_generation_record_not_bound_to_case(tmp_path: Path) -> None:
    eval_root, manifest_path, _pinned = _build_live_100_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    review = manifest["cases"][-1]["review"]
    generation_path = eval_root / review["source_generation_path"]
    generation_record = json.loads(generation_path.read_text(encoding="utf-8"))
    generation_record["case_sha256"] = "0" * 64
    generation_path.write_text(json.dumps(generation_record, sort_keys=True), encoding="utf-8")
    review["source_generation_sha256"] = hashlib.sha256(generation_path.read_bytes()).hexdigest()
    review_path = eval_root / review["review_record_path"]
    review_record = json.loads(review_path.read_text(encoding="utf-8"))
    review_record["source_generation_sha256"] = review["source_generation_sha256"]
    review_path.write_text(json.dumps(review_record, sort_keys=True), encoding="utf-8")
    review["review_record_sha256"] = hashlib.sha256(review_path.read_bytes()).hexdigest()
    altered_manifest_hash = _write_manifest(manifest_path, manifest)

    with pytest.raises(CorpusUnavailable, match="source generation provenance"):
        _resolve_fixture(eval_root, manifest_path, altered_manifest_hash)


def test_live_100_rejects_baseline_source_misclassification(tmp_path: Path) -> None:
    eval_root, manifest_path, _pinned = _build_live_100_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["cases"][0]
    review = entry["review"]
    review["source_kind"] = "reviewed_full_scan"

    generation_path = eval_root / review["source_generation_path"]
    generation_record = json.loads(generation_path.read_text(encoding="utf-8"))
    generation_record["source_kind"] = review["source_kind"]
    generation_path.write_text(json.dumps(generation_record, sort_keys=True), encoding="utf-8")
    review["source_generation_sha256"] = hashlib.sha256(generation_path.read_bytes()).hexdigest()

    review_path = eval_root / review["review_record_path"]
    review_record = json.loads(review_path.read_text(encoding="utf-8"))
    review_record["source_kind"] = review["source_kind"]
    review_record["source_generation_sha256"] = review["source_generation_sha256"]
    review_path.write_text(json.dumps(review_record, sort_keys=True), encoding="utf-8")
    review["review_record_sha256"] = hashlib.sha256(review_path.read_bytes()).hexdigest()
    altered_manifest_hash = _write_manifest(manifest_path, manifest)

    with pytest.raises(CorpusUnavailable, match="misclassified"):
        _resolve_fixture(eval_root, manifest_path, altered_manifest_hash)


def test_live_100_rejects_case_symlinks_before_resolution(tmp_path: Path) -> None:
    eval_root, manifest_path, pinned = _build_live_100_fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    candidate = eval_root / manifest["cases"][-1]["case_path"]
    target = eval_root / manifest["cases"][-2]["case_path"]
    candidate.unlink()
    candidate.symlink_to(target)

    with pytest.raises(CorpusUnavailable, match="non-symlink"):
        _resolve_fixture(eval_root, manifest_path, pinned)


def test_live_100_rejects_oversized_manifest_before_hashing(tmp_path: Path) -> None:
    manifest_path = tmp_path / f"{LIVE_100_CORPUS_ID}.json"
    manifest_path.write_bytes(b" " * (MAX_FILE_BYTES + 1))
    pinned = hashlib.sha256(manifest_path.read_bytes()).hexdigest()

    with pytest.raises(CorpusUnavailable, match="manifest is unavailable"):
        resolve_workload(
            LIVE_100_CORPUS_ID,
            root=tmp_path,
            manifest_path=manifest_path,
            expected_content_hash=pinned,
        )


def test_verified_case_payload_detects_post_resolution_mutation_and_returns_a_copy() -> None:
    corpus = resolve_workload(FULL_SCAN_CORPUS_ID)
    case = corpus.cases[0]

    snapshot = verified_case_payload(case)
    snapshot["input_sequence"][0] = "isolated snapshot mutation"
    assert snapshot != case.payload

    case.payload["input_sequence"][0] = "post-authorization mutation"
    with pytest.raises(CorpusUnavailable, match="changed after trusted resolution"):
        verified_case_payload(case)


def test_live_100_selection_uses_manifest_order_even_when_proposals_are_reordered() -> None:
    first = AuthoredCase(payload={"case_id": "first"}, content_hash="1" * 64)
    second = AuthoredCase(payload={"case_id": "second"}, content_hash="2" * 64)
    proposals = [{"case_ref": "second"}, {"case_ref": "first"}]

    selected, proposal = _select_authorized_proposal(
        [first, second],
        proposals,
        corpus_id=LIVE_100_CORPUS_ID,
    )
    assert selected is first
    assert proposal["case_ref"] == "first"

    legacy_selected, legacy_proposal = _select_authorized_proposal(
        [first, second],
        proposals,
        corpus_id=FULL_SCAN_CORPUS_ID,
    )
    assert legacy_selected is second
    assert legacy_proposal["case_ref"] == "second"
