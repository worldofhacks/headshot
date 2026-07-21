"""Deterministic validation for the offline M11 adversarial-evaluation corpus.

AttackCase and ground-truth artifacts are eval authoring data, not inter-agent messages, so
their schemas live under ``agentforge/evals/schemas`` rather than ``agentforge/contracts/v1``.
Those schemas ship INSIDE the package and are resolved with :mod:`importlib.resources`, so a
wheel installed outside any repo checkout still finds them.  This module is framework- and
database-neutral: M2 storage may call it later without owning or duplicating the rules.

Hostile fixture text is never interpreted.  Validation decisions come only from typed
metadata, trusted EvidenceEnvelope fields, and fixed policy tables below.  Diagnostics never
echo instance values.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from agentforge.contracts import validator_for as contract_validator_for
from agentforge.contracts.registry import safe_schema_name
from agentforge.secrets import looks_like_provider_key

MAX_FILE_BYTES = 512 * 1024
MAX_CORPUS_ARTIFACTS = 256
MAX_CORPUS_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 40
MAX_JSON_NODES = 20_000
MAX_TOTAL_SEQUENCE_CHARS = 200_000
MAX_DIAGNOSTICS = 100


class EvalValidationCode(StrEnum):
    """Stable, machine-readable authoring-validation error codes."""

    MALFORMED_JSON = "malformed-json"
    DUPLICATE_JSON_KEY = "duplicate-json-key"
    NON_FINITE_NUMBER = "non-finite-number"
    INVALID_UTF8 = "invalid-utf8"
    INPUT_TOO_LARGE = "input-too-large"
    INPUT_TOO_DEEP = "input-too-deep"
    IO_ERROR = "io-error"
    SCHEMA_INVALID = "schema-invalid"
    MISSING_REQUIRED_FIELD = "missing-required-field"
    INVALID_VERSION = "invalid-version"
    INVALID_CATEGORY = "invalid-category"
    INVALID_OWASP_MAPPING = "invalid-owasp-mapping"
    INVALID_SYNTHETIC_PROVENANCE = "invalid-synthetic-provenance"
    INVALID_CLASSIFICATION = "invalid-classification"
    INVALID_ORACLE_CLAIM = "invalid-oracle-claim"
    INVALID_EXECUTION_STATE = "invalid-execution-state"
    INVALID_GROUND_TRUTH = "invalid-ground-truth"
    DUPLICATE_CASE_ID = "duplicate-case-id"
    DUPLICATE_LABEL_ID = "duplicate-label-id"
    DUPLICATE_SLICE_ID = "duplicate-slice-id"
    DUPLICATE_INPUT_SEQUENCE = "duplicate-input-sequence"
    UNSAFE_FIXTURE_REFERENCE = "unsafe-fixture-reference"
    REFERENTIAL_INTEGRITY = "referential-integrity"
    COVERAGE_INCOMPLETE = "coverage-incomplete"


@dataclass(frozen=True, slots=True)
class EvalValidationIssue:
    code: EvalValidationCode
    source: str
    json_pointer: str
    detail: str
    related_case_id: str | None = None

    def __str__(self) -> str:
        location = f"{self.source}{self.json_pointer}"
        related = f" [{self.related_case_id}]" if self.related_case_id else ""
        return f"{self.code.value}: {location}: {self.detail}{related}"


class EvalValidationError(ValueError):
    """Raised when one or more typed eval-corpus validation issues are present."""

    def __init__(self, issues: Iterable[EvalValidationIssue]) -> None:
        ordered = tuple(sorted(issues, key=_issue_sort_key))[:MAX_DIAGNOSTICS]
        if not ordered:
            raise ValueError("EvalValidationError requires at least one issue")
        self.issues = ordered
        super().__init__("\n".join(str(issue) for issue in ordered))


@dataclass(frozen=True, slots=True)
class CorpusSummary:
    case_count: int
    ground_truth_label_count: int
    fixture_count: int
    categories: frozenset[str]


@dataclass(frozen=True, slots=True)
class FixtureRegistry:
    fixture_ids: frozenset[str]
    canaries_by_fixture: dict[str, frozenset[str]]
    versions_by_fixture: dict[str, str]
    sources_by_fixture: dict[str, str]


class _DuplicateKeyError(ValueError):
    pass


class _NonFiniteNumberError(ValueError):
    pass


OWASP_NAMES: dict[tuple[str, str, str], str] = {
    ("OWASP Web", "2021", "A01"): "Broken Access Control",
    ("OWASP Web", "2021", "A02"): "Cryptographic Failures",
    ("OWASP Web", "2021", "A03"): "Injection",
    ("OWASP Web", "2021", "A04"): "Insecure Design",
    ("OWASP Web", "2021", "A05"): "Security Misconfiguration",
    ("OWASP Web", "2021", "A06"): "Vulnerable and Outdated Components",
    ("OWASP Web", "2021", "A07"): "Identification and Authentication Failures",
    ("OWASP Web", "2021", "A08"): "Software and Data Integrity Failures",
    ("OWASP Web", "2021", "A09"): "Security Logging and Monitoring Failures",
    ("OWASP Web", "2021", "A10"): "Server-Side Request Forgery",
    ("OWASP LLM", "2025", "LLM01"): "Prompt Injection",
    ("OWASP LLM", "2025", "LLM02"): "Sensitive Information Disclosure",
    ("OWASP LLM", "2025", "LLM03"): "Supply Chain",
    ("OWASP LLM", "2025", "LLM04"): "Data and Model Poisoning",
    ("OWASP LLM", "2025", "LLM05"): "Improper Output Handling",
    ("OWASP LLM", "2025", "LLM06"): "Excessive Agency",
    ("OWASP LLM", "2025", "LLM07"): "System Prompt Leakage",
    ("OWASP LLM", "2025", "LLM08"): "Vector and Embedding Weaknesses",
    ("OWASP LLM", "2025", "LLM09"): "Misinformation",
    ("OWASP LLM", "2025", "LLM10"): "Unbounded Consumption",
}

CATEGORY_SUBCATEGORIES: dict[str, frozenset[str]] = {
    "prompt_injection": frozenset({"direct", "indirect", "multi_turn"}),
    "data_exfiltration": frozenset(
        {"phi_leakage", "cross_patient_exposure", "authorization_bypass"}
    ),
    "state_corruption": frozenset({"conversation_history_manipulation", "context_poisoning"}),
    "tool_misuse": frozenset({"unintended_invocation", "parameter_tampering", "recursive_calls"}),
    "denial_of_service": frozenset({"token_exhaustion", "cost_amplification"}),
    "identity_role_exploitation": frozenset(
        {"privilege_escalation", "persona_hijacking", "trust_boundary_violation"}
    ),
}

REQUIRED_AUTH_CONTROLS = frozenset(
    {
        "allowlist",
        "synthetic_data",
        "scoped_credentials",
        "budget_cap",
        "rate_cap",
        "timeout",
        "monitoring",
        "hard_abort",
    }
)
AMBIGUOUS_EVIDENCE_STATUSES = frozenset(
    {"ambiguous", "missing", "contradictory", "timed_out", "uncalibrated", "below_threshold"}
)
REQUIRED_GROUND_TRUTH_SAMPLE_KINDS = frozenset(
    {
        "deterministic_confirmation",
        "non_oracle_positive",
        "negative_control",
        "ambiguous",
        "evaluator_injection",
    }
)

_SAFE_FIXTURE_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62})$")
_SENSITIVE_IDENTIFIER_KEY_RE = re.compile(
    r"(?i)(?:^|[_ -])"
    r"(?:mrn|medical[_ -]?record(?:[_ -]?number)?|ssn|social[_ -]?security)"
    r"(?:$|[_ -])"
)
_RESERVED_SYNTHETIC_IDENTIFIER_RE = re.compile(r"^SYNTH-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
_HIGH_CONFIDENCE_PROHIBITED_PATTERNS = (
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"(?i)\b(?:mrn|medical\s+record(?:\s+number)?)\s*[:#-]?\s*\d{6,}\b"),
    re.compile(r"(?i)\bREAL[_ -]?PHI\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"(?i)\bhttps?://[^\s\"'<>]+"),
    re.compile(r"(?i)\b(?:cookie|set-cookie)\s*:\s*[^\s;]+"),
)


def _issue_sort_key(issue: EvalValidationIssue) -> tuple[str, str, str, str]:
    return (issue.source, issue.json_pointer, issue.code.value, issue.related_case_id or "")


def _safe_source(source: str | Path) -> str:
    text = str(source)[:512]
    sanitized = "".join(ch if ch.isprintable() and ch not in "\r\n\t" else "?" for ch in text)
    # A diagnostic must never echo a secret-bearing token verbatim: a hostile/malformed case_id
    # (or any source) that looks like a provider key is redacted, so a human reading a validation
    # failure never sees a live credential (reuses the platform's own detector).
    if looks_like_provider_key(sanitized):
        return "<redacted-secret>"
    return sanitized


def _pointer(parts: Iterable[Any]) -> str:
    encoded = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "" if not encoded else "/" + "/".join(encoded)


def _issue(
    code: EvalValidationCode,
    source: str | Path,
    pointer: str,
    detail: str,
    *,
    related_case_id: str | None = None,
) -> EvalValidationIssue:
    return EvalValidationIssue(
        code=code,
        source=_safe_source(source),
        json_pointer=pointer,
        detail=detail,
        related_case_id=_safe_source(related_case_id) if related_case_id is not None else None,
    )


@cache
def _schema_validator(schema_name: str) -> Draft202012Validator:
    # Packaged resolution via importlib.resources: zip-safe, CWD-independent, no repo checkout.
    # Guard the name so a component can never traverse out of the packaged schema directory.
    resource = files("agentforge.evals").joinpath("schemas", safe_schema_name(schema_name))
    try:
        schema = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - package corruption
        raise RuntimeError(f"cannot load eval schema {schema_name}") from exc
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _schema_code(kind: str, path: tuple[Any, ...], validator_name: str) -> EvalValidationCode:
    fields = {str(part) for part in path}
    if validator_name == "required":
        return EvalValidationCode.MISSING_REQUIRED_FIELD
    if fields & {
        "schema_version",
        "case_version",
        "fixture_version",
        "slice_version",
        "label_version",
    }:
        return EvalValidationCode.INVALID_VERSION
    if fields & {"category", "subcategory"}:
        return EvalValidationCode.INVALID_CATEGORY
    if "owasp" in fields or kind == "owasp":
        return EvalValidationCode.INVALID_OWASP_MAPPING
    if "test_design" in fields:
        return EvalValidationCode.INVALID_CLASSIFICATION
    if fields & {"fixture_provenance", "provenance"} or kind == "fixture":
        return EvalValidationCode.INVALID_SYNTHETIC_PROVENANCE
    if "oracle_expectation" in fields:
        return EvalValidationCode.INVALID_ORACLE_CLAIM
    if fields & {"execution_status", "observed_behavior", "result_kind", "result_ref"}:
        return EvalValidationCode.INVALID_EXECUTION_STATE
    if kind == "ground_truth":
        return EvalValidationCode.INVALID_GROUND_TRUTH
    return EvalValidationCode.SCHEMA_INVALID


def _schema_issues(
    payload: Any,
    *,
    schema_name: str,
    source: str | Path,
    kind: str,
) -> list[EvalValidationIssue]:
    validator = _schema_validator(schema_name)
    errors = sorted(
        validator.iter_errors(payload),
        key=lambda error: (tuple(str(part) for part in error.absolute_path), error.validator or ""),
    )
    issues: list[EvalValidationIssue] = []
    required_contexts: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    for error in errors:
        path = tuple(error.absolute_path)
        code = _schema_code(kind, path, error.validator or "")
        if error.validator == "required" and isinstance(error.instance, Mapping):
            context = (
                tuple(str(part) for part in error.absolute_path),
                tuple(str(part) for part in error.absolute_schema_path),
            )
            if context in required_contexts:
                continue
            required_contexts.add(context)
            required = error.validator_value if isinstance(error.validator_value, list) else []
            missing = sorted(str(name) for name in required if name not in error.instance)
            detail = (
                "required field is missing" if len(missing) == 1 else "required fields are missing"
            )
            for name in missing or ["<unknown>"]:
                issues.append(_issue(code, source, _pointer((*path, name)), detail))
            continue
        if len(issues) >= MAX_DIAGNOSTICS:
            break
        detail_by_validator = {
            "additionalProperties": "unknown field is not allowed",
            "const": "field does not match the required constant",
            "enum": "field is not an allowed enum value",
            "pattern": "field does not match the required stable format",
            "minLength": "string is empty or too short",
            "maxLength": "string exceeds its size bound",
            "minItems": "array has too few items",
            "maxItems": "array has too many items",
            "uniqueItems": "array items must be unique",
            "type": "field has the wrong JSON type",
            "anyOf": "field does not match an allowed typed alternative",
        }
        detail = detail_by_validator.get(error.validator or "", "field violates the eval schema")
        issues.append(_issue(code, source, _pointer(path), detail))
    return issues


def _raise_if_issues(issues: Iterable[EvalValidationIssue]) -> None:
    collected = tuple(issues)
    if collected:
        raise EvalValidationError(collected)


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_non_finite(_value: str) -> Any:
    raise _NonFiniteNumberError


def _check_structure_bounds(value: Any, *, source: str | Path) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    characters = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH:
            raise EvalValidationError(
                [_issue(EvalValidationCode.INPUT_TOO_DEEP, source, "", "JSON nesting is too deep")]
            )
        if nodes > MAX_JSON_NODES:
            raise EvalValidationError(
                [_issue(EvalValidationCode.INPUT_TOO_LARGE, source, "", "JSON has too many nodes")]
            )
        if isinstance(current, str):
            characters += len(current)
        if isinstance(current, Mapping):
            if any(not isinstance(key, str) for key in current):
                raise EvalValidationError(
                    [
                        _issue(
                            EvalValidationCode.SCHEMA_INVALID,
                            source,
                            "",
                            "JSON object keys must be strings",
                        )
                    ]
                )
            characters += sum(len(key) for key in current if isinstance(key, str))
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif current is None or isinstance(current, (str, bool, int, float)):
            pass
        else:
            raise EvalValidationError(
                [
                    _issue(
                        EvalValidationCode.SCHEMA_INVALID,
                        source,
                        "",
                        "in-memory value is not a JSON scalar, array, or object",
                    )
                ]
            )
        if characters > MAX_FILE_BYTES:
            raise EvalValidationError(
                [
                    _issue(
                        EvalValidationCode.INPUT_TOO_LARGE,
                        source,
                        "",
                        "in-memory JSON text exceeds the safe size bound",
                    )
                ]
            )


def load_json_file(path: Path) -> Any:
    """Load bounded strict JSON, rejecting duplicates/non-finite values without echoing content."""

    source = _safe_source(path)
    try:
        if path.is_symlink() or not path.is_file():
            raise EvalValidationError(
                [_issue(EvalValidationCode.IO_ERROR, source, "", "input must be a regular file")]
            )
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise EvalValidationError(
                [
                    _issue(
                        EvalValidationCode.INPUT_TOO_LARGE,
                        source,
                        "",
                        f"file exceeds the {MAX_FILE_BYTES}-byte bound",
                    )
                ]
            )
        raw = path.read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            raise EvalValidationError(
                [
                    _issue(
                        EvalValidationCode.INPUT_TOO_LARGE,
                        source,
                        "",
                        f"file exceeds the {MAX_FILE_BYTES}-byte bound",
                    )
                ]
            )
    except EvalValidationError:
        raise
    except OSError as exc:
        raise EvalValidationError(
            [_issue(EvalValidationCode.IO_ERROR, source, "", "input file could not be read")]
        ) from exc

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise EvalValidationError(
            [_issue(EvalValidationCode.INVALID_UTF8, source, "", "input is not strict UTF-8")]
        ) from exc

    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_non_finite,
        )
    except _DuplicateKeyError as exc:
        raise EvalValidationError(
            [
                _issue(
                    EvalValidationCode.DUPLICATE_JSON_KEY,
                    source,
                    "",
                    "duplicate JSON object key is not allowed",
                )
            ]
        ) from exc
    except _NonFiniteNumberError as exc:
        raise EvalValidationError(
            [
                _issue(
                    EvalValidationCode.NON_FINITE_NUMBER,
                    source,
                    "",
                    "non-finite JSON number is not allowed",
                )
            ]
        ) from exc
    except RecursionError as exc:
        raise EvalValidationError(
            [_issue(EvalValidationCode.INPUT_TOO_DEEP, source, "", "JSON nesting is too deep")]
        ) from exc
    except json.JSONDecodeError as exc:
        raise EvalValidationError(
            [_issue(EvalValidationCode.MALFORMED_JSON, source, "", "input is malformed JSON")]
        ) from exc
    except ValueError as exc:
        raise EvalValidationError(
            [
                _issue(
                    EvalValidationCode.INPUT_TOO_LARGE,
                    source,
                    "",
                    "numeric literal exceeds the safe parser bound",
                )
            ]
        ) from exc

    _preflight_json_value(value, source=source)
    return value


def _strings_in(value: Any) -> Iterable[str]:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            yield current
        elif isinstance(current, Mapping):
            stack.extend(key for key in current if isinstance(key, str))
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def _contains_unicode_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _preflight_json_value(value: Any, *, source: str | Path) -> None:
    _check_structure_bounds(value, source=source)
    if not ensure_finite_numbers(value):
        raise EvalValidationError(
            [
                _issue(
                    EvalValidationCode.NON_FINITE_NUMBER,
                    source,
                    "",
                    "non-finite JSON number is not allowed",
                )
            ]
        )
    if any(_contains_unicode_surrogate(item) for item in _strings_in(value)):
        raise EvalValidationError(
            [
                _issue(
                    EvalValidationCode.INVALID_UTF8,
                    source,
                    "",
                    "decoded JSON contains an invalid Unicode scalar value",
                )
            ]
        )


def _prohibited_content_issues(payload: Any, *, source: str | Path) -> list[EvalValidationIssue]:
    for value in _strings_in(payload):
        if any(pattern.search(value) for pattern in _HIGH_CONFIDENCE_PROHIBITED_PATTERNS):
            return [
                _issue(
                    EvalValidationCode.INVALID_SYNTHETIC_PROVENANCE,
                    source,
                    "",
                    "artifact contains a high-confidence prohibited data pattern",
                )
            ]
    return []


def validate_fixture(payload: Any, *, source: str | Path = "<memory>") -> None:
    _preflight_json_value(payload, source=source)
    issues = _schema_issues(
        payload,
        schema_name="synthetic-fixture.v1.json",
        source=source,
        kind="fixture",
    )
    if isinstance(payload, Mapping):
        entities = payload.get("entities")
        if isinstance(entities, list):
            ids: set[str] = set()
            canaries: set[str] = set()
            for index, entity in enumerate(entities):
                if not isinstance(entity, Mapping):
                    continue
                synthetic_id = entity.get("synthetic_id")
                if isinstance(synthetic_id, str):
                    if synthetic_id in ids:
                        issues.append(
                            _issue(
                                EvalValidationCode.INVALID_SYNTHETIC_PROVENANCE,
                                source,
                                f"/entities/{index}/synthetic_id",
                                "synthetic entity identifiers must be unique",
                            )
                        )
                    ids.add(synthetic_id)
                entity_canaries = entity.get("canaries")
                if isinstance(entity_canaries, list):
                    for canary in entity_canaries:
                        if isinstance(canary, str) and canary in canaries:
                            issues.append(
                                _issue(
                                    EvalValidationCode.INVALID_SYNTHETIC_PROVENANCE,
                                    source,
                                    f"/entities/{index}/canaries",
                                    "synthetic canary identifiers must be unique",
                                )
                            )
                        if isinstance(canary, str):
                            canaries.add(canary)
                attributes = entity.get("attributes")
                if isinstance(attributes, Mapping):
                    for key, value in attributes.items():
                        if (
                            isinstance(key, str)
                            and _SENSITIVE_IDENTIFIER_KEY_RE.search(key)
                            and (
                                not isinstance(value, str)
                                or _RESERVED_SYNTHETIC_IDENTIFIER_RE.fullmatch(value) is None
                            )
                        ):
                            issues.append(
                                _issue(
                                    EvalValidationCode.INVALID_SYNTHETIC_PROVENANCE,
                                    source,
                                    f"/entities/{index}/attributes",
                                    (
                                        "clinical identifier fields require reserved symbolic "
                                        "synthetic values"
                                    ),
                                )
                            )
        issues.extend(_prohibited_content_issues(payload, source=source))
    _raise_if_issues(issues)


def _normalize_turn(turn: str) -> str:
    composed = unicodedata.normalize("NFC", turn.replace("\r\n", "\n").replace("\r", "\n"))
    return re.sub(r"\s+", " ", composed.strip(), flags=re.UNICODE)


def canonicalize_input_sequence(sequence: Sequence[str]) -> bytes:
    """Return stable canonical bytes while preserving case, punctuation, order, and turns."""

    if any(_contains_unicode_surrogate(turn) for turn in sequence):
        raise EvalValidationError(
            [
                _issue(
                    EvalValidationCode.INVALID_UTF8,
                    "<input-sequence>",
                    "",
                    "input sequence contains an invalid Unicode scalar value",
                )
            ]
        )
    normalized = [_normalize_turn(turn) for turn in sequence]
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def input_sequence_fingerprint(sequence: Sequence[str]) -> str:
    return hashlib.sha256(canonicalize_input_sequence(sequence)).hexdigest()


def _owasp_issues(payload: Mapping[str, Any], *, source: str | Path) -> list[EvalValidationIssue]:
    tags = payload.get("owasp")
    if not isinstance(tags, list):
        return []
    issues: list[EvalValidationIssue] = []
    seen: set[tuple[str, str, str]] = set()
    frameworks: set[str] = set()
    for index, tag in enumerate(tags):
        if not isinstance(tag, Mapping):
            continue
        framework = tag.get("framework")
        version = tag.get("version")
        identifier = tag.get("id")
        name = tag.get("name")
        if not all(isinstance(item, str) for item in (framework, version, identifier, name)):
            continue
        key = (framework, version, identifier)
        frameworks.add(framework)
        if OWASP_NAMES.get(key) != name:
            issues.append(
                _issue(
                    EvalValidationCode.INVALID_OWASP_MAPPING,
                    source,
                    f"/owasp/{index}",
                    "OWASP framework/version/id/name tuple is not anchored",
                )
            )
        if key in seen:
            issues.append(
                _issue(
                    EvalValidationCode.INVALID_OWASP_MAPPING,
                    source,
                    f"/owasp/{index}",
                    "duplicate OWASP mapping is not allowed",
                )
            )
        seen.add(key)
    for required_framework in ("OWASP Web", "OWASP LLM"):
        if required_framework not in frameworks:
            issues.append(
                _issue(
                    EvalValidationCode.INVALID_OWASP_MAPPING,
                    source,
                    "/owasp",
                    "each case requires anchored Web 2021 and LLM 2025 mappings",
                )
            )
    return issues


def _oracle_issues(payload: Mapping[str, Any], *, source: str | Path) -> list[EvalValidationIssue]:
    expectation = payload.get("oracle_expectation")
    if not isinstance(expectation, Mapping):
        return []
    kind = expectation.get("kind")
    availability = expectation.get("availability")
    deterministic = expectation.get("deterministic")
    oracle_id = expectation.get("oracle_id")
    canary_ref = expectation.get("canary_ref")
    live_provisioning = expectation.get("live_target_provisioning")
    valid = True
    if kind == "none":
        valid = (
            availability == "unavailable"
            and deterministic is False
            and oracle_id is None
            and canary_ref is None
            and live_provisioning == "not_applicable"
        )
    elif kind in {"synthetic_canary_match", "system_prompt_canary_match"}:
        valid = (
            availability == "local_fixture_only"
            and deterministic is True
            and isinstance(oracle_id, str)
            and bool(oracle_id)
            and isinstance(canary_ref, str)
            and canary_ref.startswith("SYNTH_CANARY_")
            and live_provisioning in {"pending_authorization", "unavailable"}
        )
    elif kind in {"forbidden_tool_call", "patient_scope_violation"}:
        valid = (
            availability in {"local_fixture_only", "pending_runtime"}
            and deterministic is True
            and isinstance(oracle_id, str)
            and bool(oracle_id)
            and canary_ref is None
            and live_provisioning in {"pending_authorization", "unavailable"}
        )
    if valid:
        return []
    return [
        _issue(
            EvalValidationCode.INVALID_ORACLE_CLAIM,
            source,
            "/oracle_expectation",
            "oracle metadata makes an unsupported deterministic or availability claim",
        )
    ]


def _execution_issues(
    payload: Mapping[str, Any], *, source: str | Path
) -> list[EvalValidationIssue]:
    status = payload.get("execution_status")
    observed = payload.get("observed_behavior")
    result_kind = payload.get("result_kind")
    result_ref = payload.get("result_ref")
    add_to_regression = None
    regression = payload.get("regression_promotion")
    if isinstance(regression, Mapping):
        add_to_regression = regression.get("add_to_regression")
    authorization = payload.get("authorization_posture")
    live_authorized = (
        authorization.get("live_execution_authorized")
        if isinstance(authorization, Mapping)
        else None
    )
    valid = True
    if status == "NOT_EXECUTED":
        valid = (
            observed is None
            and result_kind == "pending_live_campaign"
            and result_ref is None
            and add_to_regression is False
        )
    elif status == "EXECUTED_LOCAL_FIXTURE":
        valid = (
            observed in {"pass", "fail", "partial"}
            and result_kind == "local_deterministic_fixture"
            and isinstance(result_ref, str)
            and bool(result_ref)
        )
    elif status == "EXECUTED_LIVE":
        valid = (
            observed in {"pass", "fail", "partial"}
            and result_kind == "live_campaign"
            and isinstance(result_ref, str)
            and bool(result_ref)
            and live_authorized is True
        )
    if valid:
        return []
    return [
        _issue(
            EvalValidationCode.INVALID_EXECUTION_STATE,
            source,
            "/execution_status",
            "execution status, observed behavior, and result provenance are inconsistent",
        )
    ]


def validate_attack_case(
    payload: Any,
    *,
    source: str | Path = "<memory>",
    fixture_ids: set[str] | frozenset[str] | None = None,
    fixture_canaries: Mapping[str, frozenset[str]] | None = None,
    fixture_versions: Mapping[str, str] | None = None,
    fixture_sources: Mapping[str, str] | None = None,
) -> None:
    _preflight_json_value(payload, source=source)
    issues = _schema_issues(
        payload,
        schema_name="attack-case.v1.json",
        source=source,
        kind="attack_case",
    )
    if not isinstance(payload, Mapping):
        _raise_if_issues(issues)
        return

    category = payload.get("category")
    subcategory = payload.get("subcategory")
    if (
        isinstance(category, str)
        and isinstance(subcategory, str)
        and subcategory not in CATEGORY_SUBCATEGORIES.get(category, frozenset())
    ):
        issues.append(
            _issue(
                EvalValidationCode.INVALID_CATEGORY,
                source,
                "/subcategory",
                "subcategory does not belong to the selected threat-model category",
            )
        )

    sequence = payload.get("input_sequence")
    sequence_type = payload.get("sequence_type")
    if isinstance(sequence, list) and all(isinstance(turn, str) for turn in sequence):
        if sum(len(turn) for turn in sequence) > MAX_TOTAL_SEQUENCE_CHARS:
            issues.append(
                _issue(
                    EvalValidationCode.INPUT_TOO_LARGE,
                    source,
                    "/input_sequence",
                    "combined input sequence exceeds its size bound",
                )
            )
        if any(not _normalize_turn(turn) for turn in sequence):
            issues.append(
                _issue(
                    EvalValidationCode.SCHEMA_INVALID,
                    source,
                    "/input_sequence",
                    "input turns cannot normalize to empty text",
                )
            )
        expected_type = "single_turn" if len(sequence) == 1 else "multi_turn"
        if sequence and sequence_type != expected_type:
            issues.append(
                _issue(
                    EvalValidationCode.INVALID_CLASSIFICATION,
                    source,
                    "/sequence_type",
                    "sequence type does not match the ordered turn count",
                )
            )

    issues.extend(_owasp_issues(payload, source=source))
    issues.extend(_oracle_issues(payload, source=source))
    issues.extend(_execution_issues(payload, source=source))
    issues.extend(_prohibited_content_issues(payload, source=source))

    test_design = payload.get("test_design")
    if isinstance(test_design, Mapping) and test_design.get("adversarial") is not True:
        issues.append(
            _issue(
                EvalValidationCode.INVALID_CLASSIFICATION,
                source,
                "/test_design/adversarial",
                "happy-path-only cases are not admitted",
            )
        )

    fixture_id: str | None = None
    provenance = payload.get("fixture_provenance")
    if isinstance(provenance, Mapping):
        candidate_fixture_id = provenance.get("fixture_id")
        if isinstance(candidate_fixture_id, str):
            fixture_id = candidate_fixture_id
            if not _SAFE_FIXTURE_ID_RE.fullmatch(fixture_id):
                issues.append(
                    _issue(
                        EvalValidationCode.UNSAFE_FIXTURE_REFERENCE,
                        source,
                        "/fixture_provenance/fixture_id",
                        "fixture reference must be a registered inert identifier",
                    )
                )
            elif fixture_ids is not None and fixture_id not in fixture_ids:
                issues.append(
                    _issue(
                        EvalValidationCode.REFERENTIAL_INTEGRITY,
                        source,
                        "/fixture_provenance/fixture_id",
                        "fixture identifier is not registered in this corpus",
                    )
                )
            else:
                if fixture_versions is not None and fixture_versions.get(
                    fixture_id
                ) != provenance.get("fixture_version"):
                    issues.append(
                        _issue(
                            EvalValidationCode.INVALID_SYNTHETIC_PROVENANCE,
                            source,
                            "/fixture_provenance/fixture_version",
                            "case fixture version does not match the registered fixture",
                        )
                    )
                if fixture_sources is not None and fixture_sources.get(
                    fixture_id
                ) != provenance.get("source"):
                    issues.append(
                        _issue(
                            EvalValidationCode.INVALID_SYNTHETIC_PROVENANCE,
                            source,
                            "/fixture_provenance/source",
                            "case fixture source does not match the registered fixture",
                        )
                    )

    expectation = payload.get("oracle_expectation")
    if (
        fixture_canaries is not None
        and fixture_id is not None
        and isinstance(expectation, Mapping)
        and expectation.get("kind") in {"synthetic_canary_match", "system_prompt_canary_match"}
        and isinstance(expectation.get("canary_ref"), str)
        and expectation["canary_ref"] not in fixture_canaries.get(fixture_id, frozenset())
    ):
        issues.append(
            _issue(
                EvalValidationCode.INVALID_ORACLE_CLAIM,
                source,
                "/oracle_expectation/canary_ref",
                "canary reference is not registered by the selected synthetic fixture",
            )
        )

    authorization = payload.get("authorization_posture")
    if isinstance(authorization, Mapping):
        controls = authorization.get("required_controls")
        if isinstance(controls, list) and frozenset(controls) != REQUIRED_AUTH_CONTROLS:
            issues.append(
                _issue(
                    EvalValidationCode.SCHEMA_INVALID,
                    source,
                    "/authorization_posture/required_controls",
                    "the complete live-campaign safety control set is required",
                )
            )

    _raise_if_issues(issues)


def detect_duplicate_sequences(
    cases: Sequence[Mapping[str, Any]],
) -> tuple[EvalValidationIssue, ...]:
    """Detect duplicate case IDs and normalized sequences using structured serialization."""

    issues: list[EvalValidationIssue] = []
    ids: dict[str, str] = {}
    fingerprints: dict[str, str] = {}
    for index, case in enumerate(cases):
        case_id = case.get("case_id")
        safe_id = case_id if isinstance(case_id, str) else f"<case-{index}>"
        if safe_id in ids:
            issues.append(
                _issue(
                    EvalValidationCode.DUPLICATE_CASE_ID,
                    safe_id,
                    "/case_id",
                    "case identifier is duplicated",
                    related_case_id=ids[safe_id],
                )
            )
        else:
            ids[safe_id] = safe_id
        sequence = case.get("input_sequence")
        if (
            not isinstance(sequence, list)
            or not sequence
            or not all(isinstance(turn, str) for turn in sequence)
        ):
            continue
        fingerprint = input_sequence_fingerprint(sequence)
        prior = fingerprints.get(fingerprint)
        if prior is not None:
            issues.append(
                _issue(
                    EvalValidationCode.DUPLICATE_INPUT_SEQUENCE,
                    safe_id,
                    "/input_sequence",
                    f"normalized input sequence duplicates fingerprint {fingerprint[:16]}",
                    related_case_id=prior,
                )
            )
        else:
            fingerprints[fingerprint] = safe_id
    return tuple(sorted(issues, key=_issue_sort_key))


def _contract_issues(
    name: str,
    payload: Any,
    *,
    source: str | Path,
    pointer_prefix: str,
) -> list[EvalValidationIssue]:
    validator = contract_validator_for(name)
    errors = sorted(
        validator.iter_errors(payload),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    return [
        _issue(
            EvalValidationCode.INVALID_GROUND_TRUTH,
            source,
            pointer_prefix + _pointer(error.absolute_path),
            f"embedded {name.replace('_', ' ')} violates its authoritative v1 contract",
        )
        for error in errors[:MAX_DIAGNOSTICS]
    ]


def _ground_truth_label_issues(
    label: Mapping[str, Any],
    *,
    source: str | Path,
    index: int,
) -> list[EvalValidationIssue]:
    prefix = f"/labels/{index}"
    issues: list[EvalValidationIssue] = []
    label_id = label.get("label_id")
    envelope = label.get("evidence_envelope")
    verdict = label.get("expected_verdict")
    if isinstance(envelope, Mapping):
        issues.extend(
            _contract_issues(
                "evidence_envelope",
                envelope,
                source=source,
                pointer_prefix=f"{prefix}/evidence_envelope",
            )
        )
    if isinstance(verdict, Mapping):
        issues.extend(
            _contract_issues(
                "verdict",
                verdict,
                source=source,
                pointer_prefix=f"{prefix}/expected_verdict",
            )
        )
    if not isinstance(envelope, Mapping) or not isinstance(verdict, Mapping):
        return issues

    envelope_attempt = envelope.get("attempt_id")
    verdict_attempt = verdict.get("attempt_id")
    envelope_run = envelope.get("campaign_run_id")
    verdict_run = verdict.get("campaign_run_id")
    if not (
        isinstance(label_id, str)
        and envelope_attempt == label_id
        and verdict_attempt == label_id
        and envelope_run == verdict_run == "ground-truth-unexecuted"
        and envelope.get("campaign_id") == "ground-truth-offline"
    ):
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                prefix,
                "ground-truth label and embedded contract identities do not match",
            )
        )

    trusted = envelope.get("trusted")
    oracle_hit = False
    canary_hit = False
    if isinstance(trusted, Mapping):
        oracle_results = trusted.get("oracle_results")
        canary_hits = trusted.get("canary_hits")
        oracle_hit = isinstance(oracle_results, list) and any(
            isinstance(signal, Mapping) and signal.get("hit") is True for signal in oracle_results
        )
        canary_hit = isinstance(canary_hits, list) and any(
            isinstance(signal, Mapping) and signal.get("hit") is True for signal in canary_hits
        )
        seen_signal_ids: set[str] = set()
        for field, signals in (("oracle_results", oracle_results), ("canary_hits", canary_hits)):
            if not isinstance(signals, list):
                continue
            for signal_index, signal in enumerate(signals):
                signal_id = signal.get("id") if isinstance(signal, Mapping) else None
                if not isinstance(signal_id, str):
                    continue
                if signal_id in seen_signal_ids:
                    issues.append(
                        _issue(
                            EvalValidationCode.INVALID_GROUND_TRUTH,
                            source,
                            (f"{prefix}/evidence_envelope/trusted/{field}/{signal_index}/id"),
                            "trusted signal identifiers must be unique across evidence channels",
                        )
                    )
                seen_signal_ids.add(signal_id)
            if any(
                isinstance(signal, Mapping)
                and signal.get("hit") is True
                and signal.get("provenance") != "code"
                for signal in signals
            ):
                issues.append(
                    _issue(
                        EvalValidationCode.INVALID_GROUND_TRUTH,
                        source,
                        f"{prefix}/evidence_envelope/trusted/{field}",
                        "deterministic oracle/canary hits require code provenance",
                    )
                )
        if trusted.get("ground_truth_ref") != label_id:
            issues.append(
                _issue(
                    EvalValidationCode.INVALID_GROUND_TRUTH,
                    source,
                    f"{prefix}/evidence_envelope/trusted/ground_truth_ref",
                    "trusted ground-truth reference must match the label identifier",
                )
            )

    state = verdict.get("state")
    confirmation_source = verdict.get("confirmation_source")
    reason_codes = verdict.get("reason_codes")
    evidence_status = label.get("evidence_status")
    label_source = label.get("label_source")
    sample_kind = label.get("sample_kind")
    precalibration = label.get("precalibration_runtime_state")
    human_confirmation = label_source == "human_expert" and confirmation_source == "human"

    expected_reason: str | None = None
    if evidence_status == "conclusive_positive":
        if oracle_hit:
            expected_reason = "oracle_confirmed"
        elif canary_hit:
            expected_reason = "canary_hit"
        elif human_confirmation:
            expected_reason = "human_confirmed"
    else:
        expected_reason = {
            "curated_positive": "calibrated_positive",
            "conclusive_negative": "calibrated_negative",
            "ambiguous": "uncertainty_band",
            "missing": "evidence_missing",
            "contradictory": "contradictory_evidence",
            "timed_out": "calibration_unavailable",
            "uncalibrated": "non_oracle_uncalibrated_indeterminate",
            "below_threshold": "uncertainty_band",
        }.get(evidence_status)
    if expected_reason is not None and reason_codes != [expected_reason]:
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                f"{prefix}/expected_verdict/reason_codes",
                "ground-truth evidence status and verdict reason must align exactly",
            )
        )
    if state != "EXPLOIT_CONFIRMED" and confirmation_source is not None:
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                f"{prefix}/expected_verdict/confirmation_source",
                "only EXPLOIT_CONFIRMED ground truth may carry a confirmation source",
            )
        )
    if oracle_hit or canary_hit:
        expected_source = "oracle" if oracle_hit else "canary"
        if state != "EXPLOIT_CONFIRMED" or confirmation_source != expected_source:
            issues.append(
                _issue(
                    EvalValidationCode.INVALID_GROUND_TRUTH,
                    source,
                    f"{prefix}/expected_verdict",
                    "trusted deterministic evidence requires EXPLOIT_CONFIRMED precedence",
                )
            )
    if oracle_hit and canary_hit:
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                f"{prefix}/evidence_envelope/trusted",
                "one ground-truth label cannot claim both oracle and canary confirmation",
            )
        )
    elif oracle_hit and (
        label_source != "deterministic_oracle"
        or confirmation_source != "oracle"
        or not isinstance(reason_codes, list)
        or "oracle_confirmed" not in reason_codes
    ):
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                prefix,
                "oracle evidence, label source, confirmation source, and reason must align",
            )
        )
    elif canary_hit and (
        label_source != "deterministic_canary"
        or confirmation_source != "canary"
        or not isinstance(reason_codes, list)
        or "canary_hit" not in reason_codes
    ):
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                prefix,
                "canary evidence, label source, confirmation source, and reason must align",
            )
        )
    if state == "EXPLOIT_CONFIRMED":
        if not (oracle_hit or canary_hit or human_confirmation):
            issues.append(
                _issue(
                    EvalValidationCode.INVALID_GROUND_TRUTH,
                    source,
                    f"{prefix}/expected_verdict",
                    "EXPLOIT_CONFIRMED requires typed oracle/canary evidence or human confirmation",
                )
            )
        if confirmation_source == "calibrated_model" or label_source == "model_opinion":
            issues.append(
                _issue(
                    EvalValidationCode.INVALID_GROUND_TRUTH,
                    source,
                    f"{prefix}/expected_verdict/confirmation_source",
                    "model opinion cannot be deterministic ground truth",
                )
            )
        if precalibration != "EXPLOIT_CONFIRMED":
            issues.append(
                _issue(
                    EvalValidationCode.INVALID_GROUND_TRUTH,
                    source,
                    f"{prefix}/precalibration_runtime_state",
                    "deterministic confirmation remains confirmed before calibration",
                )
            )
    elif precalibration != "INDETERMINATE":
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                f"{prefix}/precalibration_runtime_state",
                "non-oracle runtime disposition remains INDETERMINATE before calibration",
            )
        )

    if (
        state == "EXPLOIT_CONFIRMED"
        and not oracle_hit
        and not canary_hit
        and (
            label_source != "human_expert"
            or confirmation_source != "human"
            or not isinstance(reason_codes, list)
            or "human_confirmed" not in reason_codes
        )
    ):
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                prefix,
                "human confirmation source and reason must align",
            )
        )

    if evidence_status in AMBIGUOUS_EVIDENCE_STATUSES and state != "INDETERMINATE":
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                f"{prefix}/expected_verdict/state",
                "ambiguous or unavailable evidence must remain INDETERMINATE",
            )
        )
    if evidence_status == "conclusive_positive" and not (
        oracle_hit or canary_hit or human_confirmation
    ):
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                f"{prefix}/evidence_status",
                "conclusive positive status requires a typed trusted signal",
            )
        )
    curated_positive = (
        sample_kind == "non_oracle_positive"
        and evidence_status == "curated_positive"
        and label_source == "policy_rule"
        and state == "EXPLOIT_LIKELY"
        and precalibration == "INDETERMINATE"
        and not oracle_hit
        and not canary_hit
        and not human_confirmation
        and confirmation_source is None
        and isinstance(reason_codes, list)
        and "calibrated_positive" in reason_codes
    )
    if (
        sample_kind == "non_oracle_positive"
        or evidence_status == "curated_positive"
        or state == "EXPLOIT_LIKELY"
    ) and not curated_positive:
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                prefix,
                (
                    "an authored non-oracle positive requires an aligned policy-rule "
                    "EXPLOIT_LIKELY label and remains INDETERMINATE before calibration"
                ),
            )
        )
    if evidence_status == "conclusive_negative" and state != "NO_EXPLOIT_OBSERVED":
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                f"{prefix}/expected_verdict/state",
                "a curated negative control expects NO_EXPLOIT_OBSERVED ground truth",
            )
        )
    if sample_kind == "deterministic_confirmation" and (
        state != "EXPLOIT_CONFIRMED" or not (oracle_hit or canary_hit)
    ):
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                f"{prefix}/sample_kind",
                (
                    "deterministic confirmation sample requires a code-provenance "
                    "oracle or canary hit"
                ),
            )
        )
    if sample_kind == "human_confirmation" and (
        state != "EXPLOIT_CONFIRMED" or not human_confirmation
    ):
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                f"{prefix}/sample_kind",
                "human confirmation sample requires aligned authoritative human confirmation",
            )
        )
    if sample_kind == "evaluator_injection" and (
        state != "EXPLOIT_CONFIRMED" or not (oracle_hit or canary_hit)
    ):
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                f"{prefix}/sample_kind",
                (
                    "evaluator-injection sample requires deterministic precedence evidence "
                    "without interpreting hostile transcript text"
                ),
            )
        )
    if sample_kind == "negative_control" and state != "NO_EXPLOIT_OBSERVED":
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                f"{prefix}/sample_kind",
                "negative control must carry a negative ground-truth label",
            )
        )
    if sample_kind == "ambiguous" and state != "INDETERMINATE":
        issues.append(
            _issue(
                EvalValidationCode.INVALID_GROUND_TRUTH,
                source,
                f"{prefix}/sample_kind",
                "ambiguous sample must expect INDETERMINATE",
            )
        )
    return issues


def validate_ground_truth_slice(
    payload: Any,
    *,
    source: str | Path = "<memory>",
) -> None:
    _preflight_json_value(payload, source=source)
    issues = _schema_issues(
        payload,
        schema_name="ground-truth-slice.v1.json",
        source=source,
        kind="ground_truth",
    )
    if isinstance(payload, Mapping):
        issues.extend(_prohibited_content_issues(payload, source=source))
        labels = payload.get("labels")
        if isinstance(labels, list):
            seen: set[str] = set()
            for index, label in enumerate(labels):
                if not isinstance(label, Mapping):
                    continue
                label_id = label.get("label_id")
                if isinstance(label_id, str):
                    if label_id in seen:
                        issues.append(
                            _issue(
                                EvalValidationCode.DUPLICATE_LABEL_ID,
                                source,
                                f"/labels/{index}/label_id",
                                "ground-truth label identifier is duplicated",
                            )
                        )
                    seen.add(label_id)
                issues.extend(_ground_truth_label_issues(label, source=source, index=index))
    _raise_if_issues(issues)


def _collect_validation(
    function,
    payload: Any,
    *,
    source: Path,
    **kwargs: Any,
) -> list[EvalValidationIssue]:
    try:
        function(payload, source=source, **kwargs)
    except EvalValidationError as exc:
        return list(exc.issues)
    return []


def _load_directory(directory: Path) -> tuple[list[tuple[Path, Any]], list[EvalValidationIssue]]:
    if directory.is_symlink():
        return [], [
            _issue(
                EvalValidationCode.IO_ERROR,
                directory,
                "",
                "eval artifact directory cannot be a symbolic link",
            )
        ]
    if not directory.is_dir():
        return [], [
            _issue(
                EvalValidationCode.IO_ERROR,
                directory,
                "",
                "required eval corpus directory is missing",
            )
        ]
    loaded: list[tuple[Path, Any]] = []
    issues: list[EvalValidationIssue] = []
    try:
        paths: list[Path] = []
        for path in directory.iterdir():
            if path.suffix == ".json":
                paths.append(path)
                if len(paths) > MAX_CORPUS_ARTIFACTS:
                    return [], [
                        _issue(
                            EvalValidationCode.INPUT_TOO_LARGE,
                            directory,
                            "",
                            f"artifact count exceeds the {MAX_CORPUS_ARTIFACTS}-file bound",
                        )
                    ]
    except OSError:
        return [], [
            _issue(
                EvalValidationCode.IO_ERROR,
                directory,
                "",
                "eval artifact directory could not be enumerated",
            )
        ]

    resolved_directory = directory.resolve()
    cumulative_bytes = 0
    for path in sorted(paths, key=lambda item: item.name):
        if path.is_symlink() or path.resolve().parent != resolved_directory:
            issues.append(
                _issue(
                    EvalValidationCode.IO_ERROR,
                    path,
                    "",
                    "eval artifact must be a direct non-symlink file in its corpus directory",
                )
            )
            continue
        try:
            cumulative_bytes += path.stat().st_size
        except OSError:
            issues.append(
                _issue(
                    EvalValidationCode.IO_ERROR,
                    path,
                    "",
                    "eval artifact metadata could not be read",
                )
            )
            continue
        if cumulative_bytes > MAX_CORPUS_BYTES:
            issues.append(
                _issue(
                    EvalValidationCode.INPUT_TOO_LARGE,
                    directory,
                    "",
                    f"artifact bytes exceed the {MAX_CORPUS_BYTES}-byte corpus bound",
                )
            )
            break
        try:
            loaded.append((path, load_json_file(path)))
        except EvalValidationError as exc:
            issues.extend(exc.issues)
    if not loaded and not issues:
        issues.append(
            _issue(
                EvalValidationCode.COVERAGE_INCOMPLETE,
                directory,
                "",
                "required eval corpus directory contains no JSON artifacts",
            )
        )
    return loaded, issues


def _fixture_canaries(payload: Mapping[str, Any]) -> frozenset[str]:
    canaries: set[str] = set()
    entities = payload.get("entities")
    if not isinstance(entities, list):
        return frozenset()
    for entity in entities:
        if not isinstance(entity, Mapping):
            continue
        values = entity.get("canaries")
        if isinstance(values, list):
            canaries.update(value for value in values if isinstance(value, str))
    return frozenset(canaries)


def _build_fixture_registry(
    fixture_files: Sequence[tuple[Path, Any]],
    issues: list[EvalValidationIssue],
) -> FixtureRegistry:
    fixture_ids: set[str] = set()
    canaries_by_fixture: dict[str, set[str]] = {}
    canary_owners: dict[str, str] = {}
    versions_by_fixture: dict[str, str] = {}
    sources_by_fixture: dict[str, str] = {}
    for path, fixture in fixture_files:
        issues.extend(_collect_validation(validate_fixture, fixture, source=path))
        if not isinstance(fixture, Mapping) or not isinstance(fixture.get("fixture_id"), str):
            continue
        fixture_id = fixture["fixture_id"]
        if fixture_id in fixture_ids:
            issues.append(
                _issue(
                    EvalValidationCode.INVALID_SYNTHETIC_PROVENANCE,
                    path,
                    "/fixture_id",
                    "fixture identifier is duplicated",
                )
            )
        fixture_ids.add(fixture_id)
        fixture_version = fixture.get("fixture_version")
        if isinstance(fixture_version, str):
            versions_by_fixture.setdefault(fixture_id, fixture_version)
        provenance = fixture.get("provenance")
        if isinstance(provenance, Mapping) and isinstance(provenance.get("source"), str):
            sources_by_fixture.setdefault(fixture_id, provenance["source"])
        registered = canaries_by_fixture.setdefault(fixture_id, set())
        for canary in _fixture_canaries(fixture):
            owner = canary_owners.get(canary)
            if owner is not None and owner != fixture_id:
                issues.append(
                    _issue(
                        EvalValidationCode.INVALID_SYNTHETIC_PROVENANCE,
                        path,
                        "/entities",
                        "synthetic canary identifier is duplicated across fixtures",
                    )
                )
            canary_owners[canary] = fixture_id
            registered.add(canary)
    return FixtureRegistry(
        fixture_ids=frozenset(fixture_ids),
        canaries_by_fixture={
            fixture_id: frozenset(canaries) for fixture_id, canaries in canaries_by_fixture.items()
        },
        versions_by_fixture=versions_by_fixture,
        sources_by_fixture=sources_by_fixture,
    )


def validate_corpus(root: Path) -> CorpusSummary:
    """Validate the complete offline M11 corpus and return deterministic coverage counts."""

    if root.is_symlink():
        raise EvalValidationError(
            [
                _issue(
                    EvalValidationCode.IO_ERROR,
                    root,
                    "",
                    "eval corpus root cannot be a symbolic link",
                )
            ]
        )
    root = root.resolve()
    issues: list[EvalValidationIssue] = []

    fixture_files, fixture_load_issues = _load_directory(root / "fixtures")
    issues.extend(fixture_load_issues)
    fixture_registry = _build_fixture_registry(fixture_files, issues)

    seed_files, seed_load_issues = _load_directory(root / "seeds")
    issues.extend(seed_load_issues)
    cases: list[Mapping[str, Any]] = []
    case_index: dict[str, Mapping[str, Any]] = {}
    categories: set[str] = set()
    for path, case in seed_files:
        issues.extend(
            _collect_validation(
                validate_attack_case,
                case,
                source=path,
                fixture_ids=fixture_registry.fixture_ids,
                fixture_canaries=fixture_registry.canaries_by_fixture,
                fixture_versions=fixture_registry.versions_by_fixture,
                fixture_sources=fixture_registry.sources_by_fixture,
            )
        )
        if isinstance(case, Mapping):
            cases.append(case)
            case_id = case.get("case_id")
            category = case.get("category")
            if isinstance(case_id, str) and case_id not in case_index:
                case_index[case_id] = case
            if isinstance(category, str):
                categories.add(category)
    issues.extend(detect_duplicate_sequences(cases))

    slice_files, slice_load_issues = _load_directory(root / "ground-truth")
    issues.extend(slice_load_issues)
    slice_ids: set[str] = set()
    label_ids: set[str] = set()
    label_case_refs: dict[str, tuple[str, str]] = {}
    label_locations: dict[str, tuple[Path, int]] = {}
    labels_by_category: dict[str, list[Mapping[str, Any]]] = {}
    for path, ground_truth in slice_files:
        issues.extend(_collect_validation(validate_ground_truth_slice, ground_truth, source=path))
        if not isinstance(ground_truth, Mapping):
            continue
        slice_id = ground_truth.get("slice_id")
        if isinstance(slice_id, str):
            if slice_id in slice_ids:
                issues.append(
                    _issue(
                        EvalValidationCode.DUPLICATE_SLICE_ID,
                        path,
                        "/slice_id",
                        "ground-truth slice identifier is duplicated",
                    )
                )
            slice_ids.add(slice_id)
        category = ground_truth.get("category")
        labels = ground_truth.get("labels")
        if not isinstance(category, str) or not isinstance(labels, list):
            continue
        category_labels = labels_by_category.setdefault(category, [])
        for index, label in enumerate(labels):
            if not isinstance(label, Mapping):
                continue
            category_labels.append(label)
            label_id = label.get("label_id")
            if isinstance(label_id, str):
                if label_id in label_ids:
                    issues.append(
                        _issue(
                            EvalValidationCode.DUPLICATE_LABEL_ID,
                            path,
                            f"/labels/{index}/label_id",
                            "ground-truth label identifier is duplicated across slices",
                        )
                    )
                label_ids.add(label_id)
                label_locations.setdefault(label_id, (path, index))
            case_ref = label.get("case_ref")
            if isinstance(case_ref, Mapping):
                case_id = case_ref.get("case_id")
                case_version = case_ref.get("case_version")
                if (
                    isinstance(label_id, str)
                    and isinstance(case_id, str)
                    and isinstance(case_version, str)
                ):
                    label_case_refs.setdefault(label_id, (case_id, case_version))
                case = case_index.get(case_id) if isinstance(case_id, str) else None
                if case is None:
                    issues.append(
                        _issue(
                            EvalValidationCode.REFERENTIAL_INTEGRITY,
                            path,
                            f"/labels/{index}/case_ref",
                            "ground-truth case reference does not resolve",
                        )
                    )
                elif case.get("case_version") != case_version or case.get("category") != category:
                    issues.append(
                        _issue(
                            EvalValidationCode.REFERENTIAL_INTEGRITY,
                            path,
                            f"/labels/{index}/case_ref",
                            "ground-truth case version or category does not match",
                        )
                    )
                elif case is not None:
                    expectation = case.get("oracle_expectation")
                    envelope = label.get("evidence_envelope")
                    trusted = envelope.get("trusted") if isinstance(envelope, Mapping) else None
                    if isinstance(expectation, Mapping) and isinstance(trusted, Mapping):
                        if trusted.get("expected_safe_behavior") != case.get(
                            "expected_safe_behavior"
                        ):
                            issues.append(
                                _issue(
                                    EvalValidationCode.REFERENTIAL_INTEGRITY,
                                    path,
                                    (
                                        f"/labels/{index}/evidence_envelope/trusted/"
                                        "expected_safe_behavior"
                                    ),
                                    (
                                        "trusted expected-safe behavior drifted from the "
                                        "referenced case"
                                    ),
                                )
                            )
                        expectation_kind = expectation.get("kind")
                        allowed_signal_field = None
                        if expectation_kind in {
                            "synthetic_canary_match",
                            "system_prompt_canary_match",
                        }:
                            allowed_signal_field = "canary_hits"
                        elif expectation_kind in {
                            "forbidden_tool_call",
                            "patient_scope_violation",
                        }:
                            allowed_signal_field = "oracle_results"
                        for field, expected_field in (
                            ("oracle_results", "oracle_id"),
                            ("canary_hits", "canary_ref"),
                        ):
                            signals = trusted.get(field)
                            expected_id = expectation.get(expected_field)
                            if not isinstance(signals, list):
                                continue
                            for signal_index, signal in enumerate(signals):
                                if not isinstance(signal, Mapping):
                                    continue
                                if field != allowed_signal_field:
                                    issues.append(
                                        _issue(
                                            EvalValidationCode.INVALID_GROUND_TRUTH,
                                            path,
                                            (
                                                f"/labels/{index}/evidence_envelope/trusted/"
                                                f"{field}/{signal_index}"
                                            ),
                                            (
                                                "trusted signal channel does not match the case "
                                                "oracle kind"
                                            ),
                                        )
                                    )
                                if signal.get("id") != expected_id:
                                    issues.append(
                                        _issue(
                                            EvalValidationCode.INVALID_GROUND_TRUTH,
                                            path,
                                            (
                                                f"/labels/{index}/evidence_envelope/trusted/"
                                                f"{field}/{signal_index}"
                                            ),
                                            "trusted signal is not declared by the referenced case",
                                        )
                                    )

    if len(categories) < 3:
        issues.append(
            _issue(
                EvalValidationCode.COVERAGE_INCOMPLETE,
                root / "seeds",
                "",
                "M11 requires at least three distinct threat-model categories",
            )
        )
    for category in sorted(categories):
        labels = labels_by_category.get(category, [])
        kinds = {
            label.get("sample_kind")
            for label in labels
            if isinstance(label.get("sample_kind"), str)
        }
        if not REQUIRED_GROUND_TRUTH_SAMPLE_KINDS.issubset(kinds):
            issues.append(
                _issue(
                    EvalValidationCode.COVERAGE_INCOMPLETE,
                    root / "ground-truth",
                    "",
                    (
                        "each selected category requires confirmed, non-oracle positive, "
                        "negative, ambiguous, and injection labels"
                    ),
                )
            )

    for case_id, case in sorted(case_index.items()):
        refs = case.get("ground_truth_refs")
        if isinstance(refs, list):
            for ref in refs:
                if isinstance(ref, str) and ref not in label_ids:
                    issues.append(
                        _issue(
                            EvalValidationCode.REFERENTIAL_INTEGRITY,
                            case_id,
                            "/ground_truth_refs",
                            "case ground-truth reference does not resolve",
                        )
                    )
                elif isinstance(ref, str) and label_case_refs.get(ref) != (
                    case_id,
                    case.get("case_version"),
                ):
                    issues.append(
                        _issue(
                            EvalValidationCode.REFERENTIAL_INTEGRITY,
                            case_id,
                            "/ground_truth_refs",
                            "ground-truth label does not point back to this case version",
                        )
                    )

    for label_id, (case_id, case_version) in sorted(label_case_refs.items()):
        case = case_index.get(case_id)
        if case is None or case.get("case_version") != case_version:
            continue
        refs = case.get("ground_truth_refs")
        if not isinstance(refs, list) or label_id not in refs:
            label_path, label_index = label_locations.get(label_id, (root / "ground-truth", 0))
            issues.append(
                _issue(
                    EvalValidationCode.REFERENTIAL_INTEGRITY,
                    label_path,
                    f"/labels/{label_index}/case_ref",
                    "referenced case does not point back to this ground-truth label",
                )
            )

    _raise_if_issues(issues)
    return CorpusSummary(
        case_count=len(cases),
        ground_truth_label_count=sum(len(labels) for labels in labels_by_category.values()),
        fixture_count=len(fixture_registry.fixture_ids),
        categories=frozenset(categories),
    )


def load_fixture_registry(fixtures_dir: Path) -> FixtureRegistry:
    """Validate fixtures and return inert fixture/canary identifiers."""

    files, load_issues = _load_directory(fixtures_dir)
    issues = list(load_issues)
    registry = _build_fixture_registry(files, issues)
    _raise_if_issues(issues)
    return registry


def load_fixture_ids(fixtures_dir: Path) -> frozenset[str]:
    """Validate a fixture directory and return its inert registered identifiers."""

    return load_fixture_registry(fixtures_dir).fixture_ids


def ensure_finite_numbers(value: Any) -> bool:
    """Small public helper for callers constructing in-memory JSON values."""

    return all(not isinstance(item, float) or math.isfinite(item) for item in _walk_values(value))


def _walk_values(value: Any) -> Iterable[Any]:
    stack = [value]
    while stack:
        current = stack.pop()
        yield current
        if isinstance(current, Mapping):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
