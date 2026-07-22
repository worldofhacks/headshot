"""Contract-validated attack candidates produced by external LLM security tools.

Candidates are untrusted proposed input.  They contain no credential, target URL, evidence,
verdict, or authorization.  A :class:`ToolAttackProvider` may feed them to the Red Team mutation
interface, after which the normal PolicyGateway remains the only target exit.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from agentforge.contracts import validate

MAX_TOOL_CANDIDATES = 200
MAX_CANDIDATE_TURNS = 32
MAX_CANDIDATE_TURN_BYTES = 20_000
MAX_TOOL_BUNDLE_BYTES = 10 * 1024 * 1024
_CATEGORIES = {
    "prompt_injection",
    "data_exfiltration",
    "state_corruption",
    "tool_misuse",
    "denial_of_service",
    "identity_role_exploitation",
}


@dataclass(frozen=True, slots=True)
class ToolAttackCandidate:
    candidate_id: str
    tool_name: str
    tool_version: str
    technique: str
    category: str
    input_sequence: tuple[str, ...]
    owasp_mappings: tuple[str, ...]
    source_ref: str
    source_artifact_sha256: str
    provenance_sha256: str
    deterministic: bool

    def as_record(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "technique": self.technique,
            "category": self.category,
            "input_sequence": list(self.input_sequence),
            "owasp_mappings": list(self.owasp_mappings),
            "source_ref": self.source_ref,
            "source_artifact_sha256": self.source_artifact_sha256,
            "provenance_sha256": self.provenance_sha256,
            "deterministic": self.deterministic,
        }


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def candidate_id(tool_name: str, source_identity: str, input_sequence: Iterable[str]) -> str:
    digest = _canonical_sha256(
        {"source_identity": source_identity, "input_sequence": list(input_sequence)}
    )[:24]
    return f"{tool_name}:{digest}"


def candidate_provenance_sha256(
    *,
    tool_name: str,
    tool_version: str,
    technique: str,
    category: str,
    input_sequence: Iterable[str],
    owasp_mappings: Iterable[str],
    source_ref: str,
    source_artifact_sha256: str,
    deterministic: bool,
) -> str:
    """Hash every field that gives a proposed input its meaning and origin."""

    return _canonical_sha256(
        {
            "tool_name": tool_name,
            "tool_version": tool_version,
            "technique": technique,
            "category": category,
            "input_sequence": list(input_sequence),
            "owasp_mappings": sorted(set(owasp_mappings)),
            "source_ref": source_ref,
            "source_artifact_sha256": source_artifact_sha256,
            "deterministic": deterministic,
        }
    )


def checked_candidate(
    *,
    candidate_id_value: str,
    tool_name: str,
    tool_version: str,
    technique: str,
    category: str,
    input_sequence: Iterable[str],
    owasp_mappings: Iterable[str],
    source_ref: str,
    source_artifact_sha256: str,
    provenance_sha256: str | None = None,
    deterministic: bool,
) -> ToolAttackCandidate:
    turns = tuple(input_sequence)
    mappings = tuple(sorted(set(owasp_mappings)))
    if not candidate_id_value or len(candidate_id_value) > 160:
        raise ValueError("tool attack candidate has an invalid id")
    if not tool_name or len(tool_name) > 64 or not tool_version or len(tool_version) > 64:
        raise ValueError("tool attack candidate has invalid tool identity")
    if not technique or len(technique) > 200:
        raise ValueError("tool attack candidate has an invalid technique")
    if category not in _CATEGORIES:
        raise ValueError("tool attack candidate has an invalid category")
    if not 1 <= len(turns) <= MAX_CANDIDATE_TURNS:
        raise ValueError("tool attack candidate has an invalid turn count")
    if any(
        not isinstance(turn, str)
        or not turn
        or len(turn.encode("utf-8")) > MAX_CANDIDATE_TURN_BYTES
        for turn in turns
    ):
        raise ValueError("tool attack candidate contains an invalid turn")
    if not mappings:
        raise ValueError("tool attack candidate has no OWASP mapping")
    if not source_ref or len(source_ref) > 500:
        raise ValueError("tool attack candidate has an invalid source reference")
    if len(source_artifact_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in source_artifact_sha256
    ):
        raise ValueError("tool attack candidate has an invalid source artifact hash")
    if not isinstance(deterministic, bool):
        raise ValueError("tool attack candidate deterministic flag must be boolean")
    expected_candidate_id = candidate_id(tool_name, source_ref, turns)
    if candidate_id_value != expected_candidate_id:
        raise ValueError("tool attack candidate id does not match its source and content")
    expected_provenance = candidate_provenance_sha256(
        tool_name=tool_name,
        tool_version=tool_version,
        technique=technique,
        category=category,
        input_sequence=turns,
        owasp_mappings=mappings,
        source_ref=source_ref,
        source_artifact_sha256=source_artifact_sha256,
        deterministic=deterministic,
    )
    if provenance_sha256 is not None and provenance_sha256 != expected_provenance:
        raise ValueError("tool attack candidate provenance hash does not match its content")
    return ToolAttackCandidate(
        candidate_id=candidate_id_value,
        tool_name=tool_name,
        tool_version=tool_version,
        technique=technique,
        category=category,
        input_sequence=turns,
        owasp_mappings=mappings,
        source_ref=source_ref,
        source_artifact_sha256=source_artifact_sha256,
        provenance_sha256=expected_provenance,
        deterministic=deterministic,
    )


def build_tool_attack_bundle(
    *,
    bundle_id: str,
    tool_name: str,
    tool_version: str,
    configuration_sha256: str,
    generated_at: str,
    artifact_sha256: str,
    candidates: Iterable[ToolAttackCandidate],
) -> dict[str, Any]:
    candidate_values = tuple(candidates)
    for candidate in candidate_values:
        checked_candidate(
            candidate_id_value=candidate.candidate_id,
            tool_name=candidate.tool_name,
            tool_version=candidate.tool_version,
            technique=candidate.technique,
            category=candidate.category,
            input_sequence=candidate.input_sequence,
            owasp_mappings=candidate.owasp_mappings,
            source_ref=candidate.source_ref,
            source_artifact_sha256=candidate.source_artifact_sha256,
            provenance_sha256=candidate.provenance_sha256,
            deterministic=candidate.deterministic,
        )
    records = [candidate.as_record() for candidate in candidate_values]
    if not records or len(records) > MAX_TOOL_CANDIDATES:
        raise ValueError("tool attack bundle has an invalid candidate count")
    if any(
        candidate.tool_name != tool_name
        or candidate.tool_version != tool_version
        or candidate.source_artifact_sha256 != artifact_sha256
        for candidate in candidate_values
    ):
        raise ValueError("tool attack bundle candidate provenance does not match the bundle")
    identities = {(candidate.category, candidate.input_sequence) for candidate in candidate_values}
    if len(identities) != len(records):
        raise ValueError("tool attack bundle contains duplicate candidate content")
    payload = {
        "schema_version": "1",
        "bundle_id": bundle_id,
        "tool_name": tool_name,
        "tool_version": tool_version,
        "configuration_sha256": configuration_sha256,
        "generated_at": generated_at,
        "artifact_sha256": artifact_sha256,
        "source_kind": "security_tool",
        "candidate_provenance": "tool_generated",
        "target_access": "policy_gateway_only",
        "candidates": records,
    }
    validate("tool_attack_bundle", payload)
    return payload


def parse_tool_attack_bundle(raw: bytes) -> tuple[dict[str, Any], tuple[ToolAttackCandidate, ...]]:
    if len(raw) > MAX_TOOL_BUNDLE_BYTES:
        raise ValueError("tool attack bundle exceeds the byte cap")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed tool attack bundle") from exc
    validate("tool_attack_bundle", payload)
    candidates = tuple(
        checked_candidate(
            candidate_id_value=record["candidate_id"],
            tool_name=record["tool_name"],
            tool_version=record["tool_version"],
            technique=record["technique"],
            category=record["category"],
            input_sequence=record["input_sequence"],
            owasp_mappings=record["owasp_mappings"],
            source_ref=record["source_ref"],
            source_artifact_sha256=record["source_artifact_sha256"],
            provenance_sha256=record["provenance_sha256"],
            deterministic=record["deterministic"],
        )
        for record in payload["candidates"]
    )
    if len({candidate.candidate_id for candidate in candidates}) != len(candidates):
        raise ValueError("tool attack bundle contains duplicate candidate ids")
    if not candidates:
        raise ValueError("tool attack bundle contains no candidates")
    if any(
        candidate.tool_name != payload["tool_name"]
        or candidate.tool_version != payload["tool_version"]
        or candidate.source_artifact_sha256 != payload["artifact_sha256"]
        for candidate in candidates
    ):
        raise ValueError("tool attack bundle candidate provenance does not match the bundle")
    if len({(candidate.category, candidate.input_sequence) for candidate in candidates}) != len(
        candidates
    ):
        raise ValueError("tool attack bundle contains duplicate candidate content")
    return payload, candidates


@dataclass(frozen=True, slots=True)
class ToolAttackProvider:
    """Deterministic RedTeamProvider backed by a reviewed, content-hashed tool bundle."""

    candidates: tuple[ToolAttackCandidate, ...]

    def generate(self, seed: dict[str, Any], *, count: int, category: str) -> list[dict[str, Any]]:
        if count <= 0:
            raise ValueError("tool attack provider count must be positive")
        eligible = tuple(
            candidate for candidate in self.candidates if candidate.category == category
        )
        if len(eligible) < count:
            raise ValueError(
                f"tool attack bundle has {len(eligible)} candidate(s) for {category}; "
                f"{count} required"
            )
        original = list(seed.get("input_sequence", []))
        return [
            {
                "input_sequence": [*original, *candidate.input_sequence],
                "source_ref": candidate.candidate_id,
                "technique": candidate.technique,
                "mutation_lineage_ref": (
                    f"tool:{candidate.candidate_id}:{candidate.provenance_sha256}"
                ),
            }
            for candidate in eligible[:count]
        ]


__all__ = [
    "MAX_CANDIDATE_TURN_BYTES",
    "MAX_CANDIDATE_TURNS",
    "MAX_TOOL_CANDIDATES",
    "MAX_TOOL_BUNDLE_BYTES",
    "ToolAttackCandidate",
    "ToolAttackProvider",
    "build_tool_attack_bundle",
    "candidate_id",
    "candidate_provenance_sha256",
    "checked_candidate",
    "parse_tool_attack_bundle",
]
