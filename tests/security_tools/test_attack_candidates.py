from __future__ import annotations

import copy
import hashlib
import json

import pytest

from agentforge.agents.red_team.mutation import mutate
from agentforge.campaign.corpus import load_mvp_corpus
from agentforge.campaign.tool_profile import build_reviewed_tool_corpus
from agentforge.security_tools.candidates import (
    MAX_CANDIDATE_TURN_BYTES,
    ToolAttackProvider,
    build_tool_attack_bundle,
    candidate_id,
    checked_candidate,
    parse_tool_attack_bundle,
)

HEX64 = "a" * 64


def candidate(*, text: str = "synthetic candidate"):
    source_ref = "native:record:1"
    return checked_candidate(
        candidate_id_value=candidate_id("garak", source_ref, [text]),
        tool_name="garak",
        tool_version="0.15.1",
        technique="dan.Dan_11_0",
        category="prompt_injection",
        input_sequence=[text],
        owasp_mappings=["LLM01:2025"],
        source_ref=source_ref,
        source_artifact_sha256=HEX64,
        deterministic=True,
    )


def bundle(candidates):
    return build_tool_attack_bundle(
        bundle_id="offline-garak",
        tool_name="garak",
        tool_version="0.15.1",
        configuration_sha256="b" * 64,
        generated_at="2026-07-22T12:00:00Z",
        artifact_sha256=HEX64,
        candidates=candidates,
    )


def test_bundle_round_trip_recomputes_provenance_and_rejects_tampering() -> None:
    payload = bundle([candidate()])
    raw = json.dumps(payload).encode()
    _, parsed = parse_tool_attack_bundle(raw)
    assert parsed[0].provenance_sha256 == payload["candidates"][0]["provenance_sha256"]

    tampered = copy.deepcopy(payload)
    tampered["candidates"][0]["input_sequence"] = ["changed after review"]
    with pytest.raises(ValueError, match="does not match"):
        parse_tool_attack_bundle(json.dumps(tampered).encode())


def test_bundle_rejects_duplicate_content_and_utf8_byte_overflow() -> None:
    duplicate = candidate()
    with pytest.raises(ValueError, match="duplicate candidate content"):
        bundle([duplicate, duplicate])
    with pytest.raises(ValueError, match="invalid turn"):
        candidate(text="é" * (MAX_CANDIDATE_TURN_BYTES // 2 + 1))


def test_bundle_hash_and_candidate_identity_are_deterministic() -> None:
    first = json.dumps(bundle([candidate()]), sort_keys=True, separators=(",", ":")).encode()
    second = json.dumps(bundle([candidate()]), sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(first).digest() == hashlib.sha256(second).digest()


def test_tool_provider_flows_provenance_into_mutation_lineage() -> None:
    value = candidate()
    provider = ToolAttackProvider((value,))
    variants = mutate(
        {"case_ref": "seed", "input_sequence": ["original"]},
        coverage={"prompt_injection": 0},
        count=1,
        provider=provider,
    )
    assert variants[0]["mutation_lineage"][-1] == (
        f"tool:{value.candidate_id}:{value.provenance_sha256}"
    )


def test_reviewed_tool_profile_never_expands_the_approved_nine_case_identity() -> None:
    base = load_mvp_corpus()
    value = candidate()
    profile = build_reviewed_tool_corpus(
        base,
        [value],
        reviewed_candidate_ids=[value.candidate_id],
    )
    assert len(base.cases) == 9
    assert len(profile.attempts) == 10
    assert profile.base_corpus_hash == base.content_hash
    assert profile.content_hash != base.content_hash
    assert profile.fresh_authorization_required is True


def test_reviewed_tool_profile_requires_explicit_known_selection() -> None:
    base = load_mvp_corpus()
    with pytest.raises(ValueError, match="at least one"):
        build_reviewed_tool_corpus(base, [candidate()], reviewed_candidate_ids=[])
    with pytest.raises(ValueError, match="unknown"):
        build_reviewed_tool_corpus(base, [candidate()], reviewed_candidate_ids=["garak:unknown"])
