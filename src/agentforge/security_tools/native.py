"""Bounded parsers for native, offline LLM-security tool artifacts.

These parsers extract proposed inputs and advisory scan observations only. They intentionally
discard target/model responses, credentials, URLs, scores as verdicts, and authorization state.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from agentforge.security_tools.candidates import (
    MAX_TOOL_CANDIDATES,
    ToolAttackCandidate,
    candidate_id,
    checked_candidate,
)
from agentforge.security_tools.normalization import (
    NormalizationContext,
    normalize_fixture_findings,
)

MAX_NATIVE_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_NATIVE_RECORDS = 2_000
MAX_NATIVE_FINDINGS = 500


@dataclass(frozen=True, slots=True)
class ToolImportResult:
    artifact_sha256: str
    records_seen: int
    candidates: tuple[ToolAttackCandidate, ...]
    findings: tuple[dict[str, Any], ...]


def _digest(raw: bytes) -> str:
    if len(raw) > MAX_NATIVE_ARTIFACT_BYTES:
        raise ValueError("native security-tool artifact exceeds the byte cap")
    return hashlib.sha256(raw).hexdigest()


def _load_object(raw: bytes) -> tuple[dict[str, Any], str]:
    digest = _digest(raw)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed native security-tool artifact") from exc
    if not isinstance(payload, dict):
        raise ValueError("native security-tool artifact must be an object")
    return payload, digest


def _normalize_advisories(
    records: list[dict[str, Any]], raw: bytes, context: NormalizationContext, digest: str
) -> tuple[dict[str, Any], ...]:
    if len(records) > MAX_NATIVE_FINDINGS:
        raise ValueError("native security-tool artifact exceeds the finding cap")
    fixture = json.dumps({"findings": records}, separators=(",", ":")).encode()
    return tuple(
        normalize_fixture_findings(
            fixture,
            context,
            raw_artifact_sha256=digest,
        )
    )


def _candidate(
    *,
    context: NormalizationContext,
    artifact_sha256: str,
    source_ref: str,
    technique: str,
    category: str,
    turns: Iterable[str],
    mappings: Iterable[str],
    deterministic: bool,
) -> ToolAttackCandidate:
    sequence = tuple(turns)
    return checked_candidate(
        candidate_id_value=candidate_id(context.tool_name, source_ref, sequence),
        tool_name=context.tool_name,
        tool_version=context.tool_version,
        technique=technique,
        category=category,
        input_sequence=sequence,
        owasp_mappings=mappings,
        source_ref=source_ref,
        source_artifact_sha256=artifact_sha256,
        deterministic=deterministic,
    )


def _dedupe(candidates: Iterable[ToolAttackCandidate]) -> tuple[ToolAttackCandidate, ...]:
    result: list[ToolAttackCandidate] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for candidate in candidates:
        identity = (candidate.category, candidate.input_sequence)
        if identity in seen:
            continue
        seen.add(identity)
        result.append(candidate)
        if len(result) > MAX_TOOL_CANDIDATES:
            raise ValueError("native security-tool artifact exceeds the candidate cap")
    return tuple(result)


def _garak_turns(record: dict[str, Any]) -> tuple[str, ...]:
    prompt = record.get("prompt")
    if not isinstance(prompt, dict) or not isinstance(prompt.get("turns"), list):
        return ()
    turns: list[str] = []
    for turn in prompt["turns"]:
        if not isinstance(turn, dict):
            continue
        content = turn.get("content")
        text = content.get("text") if isinstance(content, dict) else content
        if isinstance(text, str) and text:
            turns.append(text)
    return tuple(turns)


class GarakAdapter:
    name = "garak"
    interface_version = "2"

    def import_artifact(self, raw: bytes, context: NormalizationContext) -> ToolImportResult:
        if context.tool_name != self.name:
            raise ValueError("garak adapter received the wrong tool context")
        digest = _digest(raw)
        try:
            lines = raw.decode().splitlines()
        except UnicodeDecodeError as exc:
            raise ValueError("malformed garak JSONL artifact") from exc
        if len(lines) > MAX_NATIVE_RECORDS:
            raise ValueError("garak artifact exceeds the record cap")
        records: list[dict[str, Any]] = []
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed garak JSONL record {index}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"garak JSONL record {index} must be an object")
            records.append(record)

        candidates: list[ToolAttackCandidate] = []
        advisories: list[dict[str, Any]] = []
        for index, record in enumerate(records):
            entry_type = record.get("entry_type")
            if entry_type == "attempt" and record.get("status") == 2:
                turns = _garak_turns(record)
                if not turns:
                    continue
                probe = str(record.get("probe_classname") or record.get("probe") or "unknown")
                sequence_number = record.get("seq")
                if not isinstance(sequence_number, int) or isinstance(sequence_number, bool):
                    sequence_number = index
                source = f"garak-jsonl:attempt:{probe}:{sequence_number}"
                candidates.append(
                    _candidate(
                        context=context,
                        artifact_sha256=digest,
                        source_ref=source,
                        technique=probe[:200],
                        category="data_exfiltration"
                        if "leak" in probe.lower()
                        else "prompt_injection",
                        turns=turns,
                        mappings=("LLM02:2025",) if "leak" in probe.lower() else ("LLM01:2025",),
                        deterministic=True,
                    )
                )
            elif entry_type == "eval":
                total = record.get("total_evaluated")
                passed = record.get("passed")
                if (
                    isinstance(total, int)
                    and not isinstance(total, bool)
                    and isinstance(passed, int)
                    and not isinstance(passed, bool)
                    and total > passed
                ):
                    probe = str(record.get("probe") or "unknown")
                    detector = str(record.get("detector") or "unknown")
                    advisories.append(
                        {
                            "id": f"eval:{index}:{probe}:{detector}"[:160],
                            "severity": "medium",
                            "confidence": max(0.0, min(1.0, (total - passed) / total)),
                            "owasp_mappings": ["LLM01:2025"],
                            "summary": (
                                f"Garak advisory: {total - passed} of {total} evaluations did "
                                "not pass "
                                f"for {probe} / {detector}. This is not a Judge verdict."
                            ),
                        }
                    )
        return ToolImportResult(
            digest,
            len(records),
            _dedupe(candidates),
            _normalize_advisories(advisories, raw, context, digest),
        )

    def parse(self, raw: bytes, context: NormalizationContext) -> list[dict[str, Any]]:
        return list(self.import_artifact(raw, context).findings)


class PyritAdapter:
    name = "pyrit"
    interface_version = "2"

    def import_artifact(self, raw: bytes, context: NormalizationContext) -> ToolImportResult:
        if context.tool_name != self.name:
            raise ValueError("pyrit adapter received the wrong tool context")
        payload, digest = _load_object(raw)
        conversions = payload.get("converters", [])
        if not isinstance(conversions, list) or len(conversions) > MAX_NATIVE_RECORDS:
            raise ValueError("PyRIT converters must be a bounded array")
        candidates: list[ToolAttackCandidate] = []
        for index, conversion in enumerate(conversions):
            if not isinstance(conversion, dict):
                raise ValueError(f"PyRIT converter {index} must be an object")
            name = conversion.get("name")
            result = conversion.get("result")
            output = result.get("output_text") if isinstance(result, dict) else None
            if not isinstance(name, str) or not isinstance(output, str) or not output:
                raise ValueError(f"PyRIT converter {index} has no native output")
            candidates.append(
                _candidate(
                    context=context,
                    artifact_sha256=digest,
                    source_ref=f"pyrit-json:converter:{index}:{name}"[:500],
                    technique=name[:200],
                    category="prompt_injection",
                    turns=(output,),
                    mappings=("LLM01:2025",),
                    deterministic=True,
                )
            )

        advisories: list[dict[str, Any]] = []
        attack_result = payload.get("attack_result")
        if attack_result is not None and not isinstance(attack_result, dict):
            raise ValueError("PyRIT AttackResult must be an object")
        if isinstance(attack_result, dict) and attack_result.get("outcome") == "success":
            result_id = str(attack_result.get("attack_result_id") or "unknown")
            advisories.append(
                {
                    "id": f"attack-result:{result_id}"[:160],
                    "severity": "medium",
                    "confidence": 0.5,
                    "owasp_mappings": ["LLM01:2025"],
                    "summary": (
                        "PyRIT reported advisory success; the independent Judge must revalidate it."
                    ),
                }
            )
        findings = _normalize_advisories(advisories, raw, context, digest)
        return ToolImportResult(
            digest, len(conversions) + int(attack_result is not None), _dedupe(candidates), findings
        )

    def parse(self, raw: bytes, context: NormalizationContext) -> list[dict[str, Any]]:
        return list(self.import_artifact(raw, context).findings)


def _giskard_mapping(tags: object) -> tuple[str, ...]:
    if not isinstance(tags, list):
        return ("LLM01:2025",)
    mappings: list[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        marker = "owasp:llm-top-10-2025:"
        if tag.lower().startswith(marker):
            mappings.append(f"{tag[len(marker) :].upper()}:2025")
    return tuple(mappings) or ("LLM01:2025",)


class GiskardAdapter:
    name = "giskard"
    interface_version = "2"

    def import_artifact(self, raw: bytes, context: NormalizationContext) -> ToolImportResult:
        if context.tool_name != self.name:
            raise ValueError("giskard adapter received the wrong tool context")
        payload, digest = _load_object(raw)
        scenarios = payload.get("scenarios", [])
        if not isinstance(scenarios, list) or len(scenarios) > MAX_NATIVE_RECORDS:
            raise ValueError("Giskard scenarios must be a bounded array")
        candidates: list[ToolAttackCandidate] = []
        for scenario_index, scenario in enumerate(scenarios):
            if not isinstance(scenario, dict):
                raise ValueError(f"Giskard scenario {scenario_index} must be an object")
            name = str(scenario.get("name") or f"scenario-{scenario_index}")
            mappings = _giskard_mapping(scenario.get("tags"))
            steps = scenario.get("steps", [])
            if not isinstance(steps, list):
                raise ValueError(f"Giskard scenario {scenario_index} steps must be an array")
            for step_index, step in enumerate(steps):
                interacts = step.get("interacts", []) if isinstance(step, dict) else []
                if not isinstance(interacts, list):
                    raise ValueError("Giskard interactions must be an array")
                turns: list[str] = []
                for interaction in interacts:
                    if not isinstance(interaction, dict):
                        continue
                    inputs = interaction.get("inputs")
                    if isinstance(inputs, str) and inputs:
                        turns.append(inputs)
                    elif isinstance(inputs, dict):
                        prompt = inputs.get("prompt") or inputs.get("message")
                        if isinstance(prompt, str) and prompt:
                            turns.append(prompt)
                if turns:
                    candidates.append(
                        _candidate(
                            context=context,
                            artifact_sha256=digest,
                            source_ref=f"giskard-json:scenario:{scenario_index}:step:{step_index}",
                            technique=name[:200],
                            category="prompt_injection",
                            turns=turns,
                            mappings=mappings,
                            deterministic=True,
                        )
                    )

        advisories: list[dict[str, Any]] = []
        scan_results = payload.get("scan_results", [])
        if not isinstance(scan_results, list) or len(scan_results) > MAX_NATIVE_FINDINGS:
            raise ValueError("Giskard scan results must be a bounded array")
        for index, result in enumerate(scan_results):
            if not isinstance(result, dict):
                raise ValueError(f"Giskard scan result {index} must be an object")
            if result.get("passed") is False or result.get("vulnerable") is True:
                advisories.append(
                    {
                        "id": f"scan-result:{result.get('id') or index}"[:160],
                        "severity": "medium",
                        "confidence": 0.5,
                        "owasp_mappings": list(_giskard_mapping(result.get("tags"))),
                        "summary": (
                            "Giskard reported a scenario failure; the independent Judge must "
                            "revalidate it."
                        ),
                    }
                )
        return ToolImportResult(
            digest,
            len(scenarios) + len(scan_results),
            _dedupe(candidates),
            _normalize_advisories(advisories, raw, context, digest),
        )

    def parse(self, raw: bytes, context: NormalizationContext) -> list[dict[str, Any]]:
        return list(self.import_artifact(raw, context).findings)


class PromptfooAdapter:
    name = "promptfoo"
    interface_version = "2"

    def import_artifact(self, raw: bytes, context: NormalizationContext) -> ToolImportResult:
        if context.tool_name != self.name:
            raise ValueError("Promptfoo adapter received the wrong tool context")
        payload, digest = _load_object(raw)
        results_container = payload.get("results")
        results = (
            results_container.get("results", []) if isinstance(results_container, dict) else []
        )
        if not isinstance(results, list) or len(results) > MAX_NATIVE_RECORDS:
            raise ValueError("Promptfoo results must be a bounded array")
        candidates: list[ToolAttackCandidate] = []
        advisories: list[dict[str, Any]] = []
        for index, result in enumerate(results):
            if not isinstance(result, dict):
                raise ValueError(f"Promptfoo result {index} must be an object")
            test_case = result.get("testCase")
            metadata = test_case.get("metadata", {}) if isinstance(test_case, dict) else {}
            variables = test_case.get("vars", {}) if isinstance(test_case, dict) else {}
            prompt = variables.get("prompt") if isinstance(variables, dict) else None
            if not isinstance(prompt, str) or not prompt:
                result_variables = result.get("vars", {})
                prompt = (
                    result_variables.get("prompt") if isinstance(result_variables, dict) else None
                )
            if isinstance(prompt, str) and prompt:
                technique = metadata.get("technique") if isinstance(metadata, dict) else None
                category = metadata.get("category") if isinstance(metadata, dict) else None
                mappings = metadata.get("owasp_mappings") if isinstance(metadata, dict) else None
                candidates.append(
                    _candidate(
                        context=context,
                        artifact_sha256=digest,
                        source_ref=f"promptfoo-json:result:{index}",
                        technique=str(technique or "pre-authored Promptfoo evaluation")[:200],
                        category=category
                        if category
                        in {
                            "prompt_injection",
                            "data_exfiltration",
                            "state_corruption",
                            "tool_misuse",
                            "denial_of_service",
                            "identity_role_exploitation",
                        }
                        else "prompt_injection",
                        turns=(prompt,),
                        mappings=mappings if isinstance(mappings, list) else ("LLM01:2025",),
                        deterministic=True,
                    )
                )
            grading = result.get("gradingResult")
            failed = result.get("success") is False or (
                isinstance(grading, dict) and grading.get("pass") is False
            )
            if failed:
                advisories.append(
                    {
                        "id": f"result:{index}",
                        "severity": "medium",
                        "confidence": 0.5,
                        "owasp_mappings": ["LLM01:2025"],
                        "summary": (
                            "Promptfoo assertion failed; this is advisory until the Judge "
                            "revalidates it."
                        ),
                    }
                )
        return ToolImportResult(
            digest,
            len(results),
            _dedupe(candidates),
            _normalize_advisories(advisories, raw, context, digest),
        )

    def parse(self, raw: bytes, context: NormalizationContext) -> list[dict[str, Any]]:
        return list(self.import_artifact(raw, context).findings)


__all__ = [
    "GarakAdapter",
    "GiskardAdapter",
    "MAX_NATIVE_ARTIFACT_BYTES",
    "MAX_NATIVE_FINDINGS",
    "MAX_NATIVE_RECORDS",
    "PromptfooAdapter",
    "PyritAdapter",
    "ToolImportResult",
]
