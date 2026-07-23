"""Deterministic, authorization-bound regression planning and result evaluation."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from agentforge.contracts import validate

_EVIDENCE_REF = re.compile(r"\Aevidence://sha256/[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_TRIGGERS = frozenset({"target_version_changed", "manual_authorized_replay"})


class RegressionReplayError(ValueError):
    """Replay lineage, deterministic evidence, or authorization binding is invalid."""


@dataclass(frozen=True, slots=True)
class ReplayObservation:
    """One persisted envelope/verdict pair addressed by immutable evidence hash."""

    envelope: Mapping[str, Any]
    verdict: Mapping[str, Any]
    evidence_reference: str


class RegressionReplayGate:
    """Create blocked plans and assess only scope-bound, persisted replay evidence."""

    def plan(
        self,
        *,
        disposition: Mapping[str, Any],
        report: Mapping[str, Any],
        attack_attempt: Mapping[str, Any],
        source_case_version: str,
        target_id: str,
        source_target_version: str,
        replay_target_version: str,
        required_oracle_ids: Sequence[str],
        trigger: str,
        repetitions: int = 3,
    ) -> dict[str, Any]:
        disposition_payload = self._contract("regression_disposition", disposition)
        report_payload = self._contract("vuln_report", report)
        attempt_payload = self._contract("attack_attempt", attack_attempt)
        if disposition_payload["state"] != "admitted" or not disposition_payload["admitted"]:
            raise RegressionReplayError("only an admitted regression may be planned for replay")
        for key in ("finding_id", "report_id", "campaign_run_id", "attempt_id"):
            if disposition_payload[key] != report_payload[key]:
                raise RegressionReplayError("regression disposition/report lineage mismatch")
        if attempt_payload["case_ref"] != report_payload["source_case_id"]:
            raise RegressionReplayError("attack attempt/report source-case lineage mismatch")
        case_version = self._bounded("source case version", source_case_version, 32)
        normalized_target_id = self._bounded("target id", target_id, 64)
        source_version = self._bounded("source target version", source_target_version, 128)
        replay_version = self._bounded("replay target version", replay_target_version, 128)
        if trigger not in _TRIGGERS:
            raise RegressionReplayError("regression replay trigger is invalid")
        if trigger == "target_version_changed" and source_version == replay_version:
            raise RegressionReplayError("target version trigger requires a new target version")
        if (
            isinstance(repetitions, bool)
            or not isinstance(repetitions, int)
            or not 2 <= repetitions <= 20
        ):
            raise RegressionReplayError("replay repetitions must be an integer from 2 to 20")
        oracle_ids = self._oracle_ids(required_oracle_ids)
        attack_hash = self._sha256(attempt_payload["input_sequence"])
        regression_case_id = "RC-" + self._sha256(
            {
                "finding_id": report_payload["finding_id"],
                "source_case_id": report_payload["source_case_id"],
                "source_case_version": case_version,
                "attack_sequence_sha256": attack_hash,
            }
        )
        identity = {
            "regression_case_id": regression_case_id,
            "target_id": normalized_target_id,
            "source_target_version": source_version,
            "replay_target_version": replay_version,
            "trigger": trigger,
            "attack_sequence_sha256": attack_hash,
            "required_oracle_ids": list(oracle_ids),
            "planned_repetitions": repetitions,
        }
        plan: dict[str, Any] = {
            "schema_version": "1",
            "replay_id": "RR-" + self._sha256(identity),
            "regression_case_id": regression_case_id,
            "finding_id": report_payload["finding_id"],
            "report_id": report_payload["report_id"],
            "source_case_ref": {
                "case_id": report_payload["source_case_id"],
                "case_version": case_version,
            },
            "target_id": normalized_target_id,
            "source_target_version": source_version,
            "replay_target_version": replay_version,
            "trigger": trigger,
            "attack_attempt": attempt_payload,
            "attack_sequence_sha256": attack_hash,
            "required_oracle_ids": list(oracle_ids),
            "planned_repetitions": repetitions,
            "authorization_state": "pending_human_authorization",
            "authorization_scope_hash": None,
            "execution_state": "blocked",
            "human_approval_required": True,
        }
        self._contract("regression_replay_plan", plan)
        return plan

    def evaluate(
        self,
        *,
        plan: Mapping[str, Any],
        campaign_run_id: str,
        authorization_scope_hash: str,
        observations: Sequence[ReplayObservation],
    ) -> dict[str, Any]:
        plan_payload = self._contract("regression_replay_plan", plan)
        run_id = self._bounded("campaign run id", campaign_run_id, 128)
        if not isinstance(authorization_scope_hash, str) or not _SHA256.fullmatch(
            authorization_scope_hash
        ):
            raise RegressionReplayError("authorization scope hash must be a SHA-256 digest")
        if isinstance(observations, (str, bytes)) or not isinstance(observations, Sequence):
            raise RegressionReplayError("replay observations must be a sequence")
        if not 1 <= len(observations) <= plan_payload["planned_repetitions"]:
            raise RegressionReplayError("replay observations exceed the planned bounds")

        normalized = [
            self._observation(
                item,
                campaign_run_id=run_id,
                required_oracle_ids=tuple(plan_payload["required_oracle_ids"]),
            )
            for item in observations
        ]
        attempt_ids = [item["attempt_id"] for item in normalized]
        evidence_refs = [item["evidence_reference"] for item in normalized]
        if len(attempt_ids) != len(set(attempt_ids)) or len(evidence_refs) != len(
            set(evidence_refs)
        ):
            raise RegressionReplayError("replay evidence contains a duplicated observation")

        complete = len(normalized) == plan_payload["planned_repetitions"]
        signatures = {
            (
                item["verdict_state"],
                tuple((signal["id"], signal["hit"]) for signal in item["required_signals"]),
            )
            for item in normalized
        }
        deterministic = complete and len(signatures) == 1
        reappeared = any(
            item["verdict_state"] == "EXPLOIT_CONFIRMED"
            or any(signal["hit"] for signal in item["required_signals"])
            for item in normalized
        )
        any_judge_error = any(item["verdict_state"] == "ERROR" for item in normalized)
        contradictory = any(
            (
                any(signal["hit"] for signal in item["required_signals"])
                and item["verdict_state"] != "EXPLOIT_CONFIRMED"
            )
            or (
                item["verdict_state"] == "EXPLOIT_CONFIRMED"
                and not any(signal["hit"] for signal in item["required_signals"])
            )
            for item in normalized
        )

        all_required_safe = all(
            all(signal["hit"] is False for signal in item["required_signals"])
            for item in normalized
        )
        unsafe_judge_states = {"EXPLOIT_CONFIRMED", "EXPLOIT_LIKELY", "ERROR"}
        if deterministic and reappeared:
            state = "failing"
            # The *target* failed, while the regression check itself passed for the right
            # reason: an allowlisted deterministic oracle reproduced the exploit.
            passes_for_right_reason = True
            reasons = ["exploit_reappeared"]
        elif (
            deterministic
            and all_required_safe
            and not any(item["verdict_state"] in unsafe_judge_states for item in normalized)
        ):
            state = "passing"
            passes_for_right_reason = True
            reasons = ["safe_behavior_confirmed_by_required_oracles"]
        else:
            state = "inconclusive"
            passes_for_right_reason = False
            reasons: list[str] = []
            if not complete:
                reasons.append("observation_incomplete")
            if complete and not deterministic:
                reasons.append("replay_non_deterministic")
            if any_judge_error:
                reasons.append("judge_error")
            if contradictory:
                reasons.append("evidence_contradictory")
            if not reasons:
                reasons.append("evidence_contradictory")

        result_body = {
            "replay_id": plan_payload["replay_id"],
            "campaign_run_id": run_id,
            "authorization_scope_hash": authorization_scope_hash,
            "observations": normalized,
        }
        result: dict[str, Any] = {
            "schema_version": "1",
            "result_id": "RVR-" + self._sha256(result_body),
            "replay_id": plan_payload["replay_id"],
            "regression_case_id": plan_payload["regression_case_id"],
            "campaign_run_id": run_id,
            "authorization_scope_hash": authorization_scope_hash,
            "target_id": plan_payload["target_id"],
            "replay_target_version": plan_payload["replay_target_version"],
            "attack_sequence_sha256": plan_payload["attack_sequence_sha256"],
            "planned_repetitions": plan_payload["planned_repetitions"],
            "observation_count": len(normalized),
            "observations": normalized,
            "state": state,
            "deterministic": deterministic,
            "passes_for_right_reason": passes_for_right_reason,
            "reappeared": reappeared,
            "reason_codes": reasons,
            "evidence_references": evidence_refs,
        }
        self._contract("regression_replay_result", result)
        return result

    @classmethod
    def _observation(
        cls,
        observation: ReplayObservation,
        *,
        campaign_run_id: str,
        required_oracle_ids: tuple[str, ...],
    ) -> dict[str, Any]:
        if not isinstance(observation, ReplayObservation):
            raise RegressionReplayError("replay observation must use ReplayObservation")
        envelope = cls._contract("evidence_envelope", observation.envelope)
        verdict = cls._contract("verdict", observation.verdict)
        if (
            envelope["campaign_run_id"] != campaign_run_id
            or verdict["campaign_run_id"] != campaign_run_id
            or envelope["attempt_id"] != verdict["attempt_id"]
        ):
            raise RegressionReplayError("replay envelope/verdict correlation mismatch")
        if not isinstance(observation.evidence_reference, str) or not _EVIDENCE_REF.fullmatch(
            observation.evidence_reference
        ):
            raise RegressionReplayError("replay evidence reference is not content-addressed")
        trusted = envelope["trusted"]
        signals = [*trusted["oracle_results"], *trusted["canary_hits"]]
        by_id: dict[str, dict[str, Any]] = {}
        for signal in signals:
            signal_id = signal["id"]
            if signal_id in by_id:
                raise RegressionReplayError("trusted replay signal identifier is duplicated")
            by_id[signal_id] = signal
        if any(oracle_id not in by_id for oracle_id in required_oracle_ids):
            raise RegressionReplayError("required oracle signal is missing from replay evidence")
        required = [
            {
                "id": oracle_id,
                "provenance": by_id[oracle_id]["provenance"],
                "hit": by_id[oracle_id]["hit"],
            }
            for oracle_id in required_oracle_ids
        ]
        return {
            "attempt_id": envelope["attempt_id"],
            "evidence_reference": observation.evidence_reference,
            "verdict_state": verdict["state"],
            "required_signals": required,
        }

    @staticmethod
    def _contract(name: str, value: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise RegressionReplayError(f"{name} payload must be a mapping")
        candidate = copy.deepcopy(dict(value))
        try:
            validate(name, candidate)
        except Exception as exc:
            raise RegressionReplayError(f"{name} payload fails its contract: {exc}") from exc
        return candidate

    @staticmethod
    def _bounded(label: str, value: str, maximum: int) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            raise RegressionReplayError(
                f"{label} must be a non-empty string no longer than {maximum} characters"
            )
        return value

    @staticmethod
    def _oracle_ids(values: Sequence[str]) -> tuple[str, ...]:
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise RegressionReplayError("required oracle identifiers must be a sequence")
        identifiers = tuple(values)
        if not 1 <= len(identifiers) <= 32 or len(identifiers) != len(set(identifiers)):
            raise RegressionReplayError("required oracle identifiers must be unique and bounded")
        if any(
            not isinstance(value, str) or not value.strip() or len(value) > 160
            for value in identifiers
        ):
            raise RegressionReplayError("required oracle identifier is invalid")
        return identifiers

    @staticmethod
    def _sha256(value: Any) -> str:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
