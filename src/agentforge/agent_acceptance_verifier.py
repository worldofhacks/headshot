"""Exact PostgreSQL/Langfuse reconciliation for one agent-only acceptance run.

The verifier is deliberately target-free. It accepts only the three-role
Orchestrator -> Judge -> Documentation chain, exactly one canonical provider event per role,
and zero durable target requests. Remote Langfuse observations are evidence only after every
typed agent/generation pair reconciles with the canonical 0017/0018-0019 lineage.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from sqlalchemy import Connection, Engine, text

from agentforge.correlation import campaign_trace_id
from agentforge.providers.lineage import served_provider_matches_configured

ACCEPTANCE_ROLES = ("orchestrator", "judge", "documentation")
OBSERVATION_FIELDS = "core,basic,io,usage,metadata,model"
_EXPECTED_LIMITS = {
    "schema_version": "1",
    "network_scope": "openrouter_langfuse_only",
    "target_call_limit": 0,
    "allowed_roles": list(ACCEPTANCE_ROLES),
    "role_call_caps": {role: 1 for role in ACCEPTANCE_ROLES},
    "role_usd_caps": {
        "orchestrator": "1.5",
        "judge": "4",
        "documentation": "1",
    },
    "global_call_cap": 3,
    "global_usd_cap": "10",
}
_PROVIDER_EVENT_ID = re.compile(r"^[0-9a-f]{64}$")
_SAFE_PROVIDER_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/@+-]*$")
_SENSITIVE_PROVIDER_IDENTITY = re.compile(
    r"\bsk-(?:(?:ant|or|proj)-)?[A-Za-z0-9_-]{8,}\b|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
    r"(?:api[_ -]?key|token|secret|password|authorization|credential|"
    r"provider[_-]?key|target[_-]?session|session[_-]?id)[\"']?\s*[:=]",
    re.IGNORECASE,
)


def _is_safe_provider_identity(value: object, *, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and len(value) <= maximum
        and _SAFE_PROVIDER_IDENTITY.fullmatch(value) is not None
        and _SENSITIVE_PROVIDER_IDENTITY.search(value) is None
    )


def _served_provider_matches_configured(configured: object, observed: object) -> bool:
    if not isinstance(configured, str) or not isinstance(observed, str):
        return False
    try:
        return served_provider_matches_configured(configured, observed)
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class AcceptanceSnapshot:
    """One immutable acceptance authority plus its logical and physical facts."""

    run: dict[str, Any]
    attempts: tuple[dict[str, Any], ...]
    agents: tuple[dict[str, Any], ...]
    provider_calls: tuple[dict[str, Any], ...]
    target_request_count: int

    @property
    def trace_id(self) -> str:
        return campaign_trace_id(str(self.run["run_id"]))


def _field(value: Any, *names: str) -> Any:
    for name in names:
        if isinstance(value, dict) and name in value:
            return value[name]
        if hasattr(value, name):
            return getattr(value, name)
    return None


def _metadata(observation: Any) -> dict[str, Any]:
    value = _field(observation, "metadata")
    return dict(value) if isinstance(value, dict) else {}


def _structured_io(observation: Any, field: str) -> Any:
    value = _field(observation, field)
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _decimal(value: Any, *, label: str) -> Decimal:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise AssertionError(f"{label} is unavailable") from exc
    if not result.is_finite() or result < 0:
        raise AssertionError(f"{label} is invalid")
    return result


def _usage_value(observation: Any, key: str) -> int | None:
    usage = _field(observation, "usage_details", "usageDetails")
    if usage is None:
        return None
    if not isinstance(usage, dict):
        raise AssertionError("Langfuse usage details are invalid")
    if key not in usage:
        return None
    value = usage[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AssertionError(f"Langfuse {key} usage is invalid")
    return value


def _cost_value(observation: Any) -> Decimal | None:
    details = _field(observation, "cost_details", "costDetails")
    if details is None:
        return None
    if not isinstance(details, dict) or "total" not in details:
        raise AssertionError("Langfuse cost details are invalid")
    return _decimal(details["total"], label="Langfuse total cost")


def load_acceptance_snapshot(
    connection: Connection,
    *,
    run_id: str,
    lock_authority: bool = False,
) -> AcceptanceSnapshot:
    """Load one acceptance run from canonical lineage without model payloads."""

    if not isinstance(run_id, str) or not run_id.startswith("AR-"):
        raise AssertionError("agent acceptance run identity is invalid")
    lock_clause = " FOR UPDATE OF r" if lock_authority else ""
    run = (
        connection.execute(
            text(
                "SELECT r.organization_id, r.run_id, r.run_kind, "
                "r.acceptance_configuration_sha256, "
                "r.acceptance_generation_policy_sha256, "
                "r.acceptance_context_sha256, r.acceptance_attempt_id, "
                "r.acceptance_limits, "
                "r.acceptance_actor_id, r.acceptance_provenance, "
                "(SELECT state FROM campaign_run_events s "
                "WHERE s.organization_id = r.organization_id AND s.run_id = r.run_id "
                "ORDER BY s.id DESC LIMIT 1) AS state "
                "FROM campaign_runs r WHERE r.run_id = :run_id" + lock_clause
            ),
            {"run_id": run_id},
        )
        .mappings()
        .one_or_none()
    )
    if run is None:
        raise AssertionError("agent acceptance run does not exist")
    organization_id = str(run["organization_id"])
    attempts = tuple(
        dict(row)
        for row in connection.execute(
            text(
                "SELECT organization_id, run_id, attempt_id, ordinal, case_id, "
                "case_content_hash, category, severity, attack_class, owasp_mappings, "
                "fixture_provenance, source_tool, source_technique "
                "FROM campaign_attempts WHERE organization_id = :org AND run_id = :run_id "
                "ORDER BY ordinal, attempt_id"
            ),
            {"org": organization_id, "run_id": run_id},
        )
        .mappings()
        .all()
    )
    agents = tuple(
        dict(row)
        for row in connection.execute(
            text(
                "SELECT execution_id, organization_id, campaign_run_id, attempt_id, "
                "parent_execution_id, agent_role, provider, model, execution_mode, "
                "status, error_code, started_at, finished_at, duration_ms, "
                "input_sha256, output_sha256, returned_model, upstream_provider, "
                "provider_request_id, input_tokens, output_tokens, reasoning_tokens, "
                "measured_cost, cost_measurement_state, provider_event_ids, "
                "physical_attempts, configuration_set_sha256, "
                "role_configuration_sha256, generation_policy_sha256, "
                "judge_calibration_id, judge_calibration_state, oracle_agreement, "
                "decision_authority, trace_id, langfuse_status, langfuse_verified_at, detail "
                "FROM agent_executions WHERE organization_id = :org "
                "AND campaign_run_id = :run_id ORDER BY id"
            ),
            {"org": organization_id, "run_id": run_id},
        )
        .mappings()
        .all()
    )
    provider_calls = tuple(
        dict(row)
        for row in connection.execute(
            text(
                "SELECT i.invocation_id, i.organization_id, i.campaign_run_id, "
                "i.campaign_attempt_id, i.logical_execution_id, i.parent_execution_id, "
                "i.agent_role, i.physical_sequence, i.requested_model, "
                "i.configured_upstream, i.prompt_version, i.prompt_sha256, "
                "i.configuration_set_sha256, i.role_configuration_sha256, "
                "i.generation_policy_sha256, i.started_at, "
                "e.event_id, e.status AS event_status, "
                "e.returned_model AS event_returned_model, "
                "e.upstream_provider AS event_upstream_provider, "
                "e.provider_request_id AS event_provider_request_id, "
                "e.input_tokens AS event_input_tokens, "
                "e.output_tokens AS event_output_tokens, "
                "e.reasoning_tokens AS event_reasoning_tokens, "
                "e.cost_measurement_state AS event_cost_measurement_state, "
                "e.measured_cost_usd AS event_measured_cost_usd, "
                "e.error_code AS event_error_code, e.finished_at AS event_finished_at, "
                "e.duration_ms AS event_duration_ms "
                "FROM provider_call_invocations i LEFT JOIN provider_call_events e "
                "ON e.organization_id = i.organization_id "
                "AND e.invocation_id = i.invocation_id "
                "WHERE i.organization_id = :org AND i.campaign_run_id = :run_id "
                "ORDER BY i.physical_sequence, i.invocation_id"
            ),
            {"org": organization_id, "run_id": run_id},
        )
        .mappings()
        .all()
    )
    target_request_count = int(
        connection.execute(
            text(
                "SELECT count(*) FROM outbound_http_requests "
                "WHERE organization_id = :org AND campaign_run_id = :run_id"
            ),
            {"org": organization_id, "run_id": run_id},
        ).scalar_one()
    )
    return AcceptanceSnapshot(
        run=dict(run),
        attempts=attempts,
        agents=agents,
        provider_calls=provider_calls,
        target_request_count=target_request_count,
    )


def assert_durable_acceptance(snapshot: AcceptanceSnapshot) -> dict[str, dict[str, Any]]:
    """Require exactly three successful logical/physical calls and no target traffic."""

    run = snapshot.run
    if run["run_kind"] != "agent_acceptance" or run["state"] != "complete":
        raise AssertionError("agent acceptance authority is not complete")
    if dict(run["acceptance_limits"]) != _EXPECTED_LIMITS:
        raise AssertionError("agent acceptance limits do not match the closed envelope")
    if snapshot.target_request_count != 0:
        raise AssertionError("agent acceptance has forbidden durable target traffic")
    attempt_id = run["acceptance_attempt_id"]
    if not isinstance(attempt_id, str) or len(attempt_id) != 64 or len(snapshot.attempts) != 1:
        raise AssertionError("agent acceptance requires one canonical synthetic attempt")
    attempt = snapshot.attempts[0]
    if (
        attempt["organization_id"] != run["organization_id"]
        or attempt["run_id"] != run["run_id"]
        or attempt["attempt_id"] != attempt_id
        or attempt["ordinal"] != 0
        or attempt["case_id"] != "agentforge-hosted-acceptance-v1"
        or attempt["case_content_hash"] != run["acceptance_context_sha256"]
        or any(
            attempt[field] is not None
            for field in (
                "category",
                "severity",
                "attack_class",
                "owasp_mappings",
                "source_tool",
                "source_technique",
            )
        )
        or attempt["fixture_provenance"]
        != {
            "classification": "synthetic",
            "contains_real_phi": False,
            "schema_version": "1",
            "source": "agentforge.live_acceptance",
        }
    ):
        raise AssertionError("agent acceptance canonical synthetic attempt is invalid")
    if len(snapshot.agents) != len(ACCEPTANCE_ROLES):
        raise AssertionError("agent acceptance requires exactly three logical executions")
    roles = [str(row["agent_role"]) for row in snapshot.agents]
    if Counter(roles) != Counter(ACCEPTANCE_ROLES):
        raise AssertionError("agent acceptance logical role coverage is invalid")
    by_role = {str(row["agent_role"]): row for row in snapshot.agents}
    execution_ids = {str(row["execution_id"]) for row in snapshot.agents}
    if len(execution_ids) != len(ACCEPTANCE_ROLES):
        raise AssertionError("agent acceptance execution identities are duplicated")

    orchestrator = by_role["orchestrator"]
    judge = by_role["judge"]
    documentation = by_role["documentation"]
    if (
        orchestrator["parent_execution_id"] is not None
        or judge["parent_execution_id"] != orchestrator["execution_id"]
        or documentation["parent_execution_id"] != judge["execution_id"]
    ):
        raise AssertionError(
            "agent acceptance parent chain must be Orchestrator -> Judge -> Documentation"
        )

    for row in snapshot.agents:
        execution_id = str(row["execution_id"])
        detail = row["detail"]
        if (
            row["organization_id"] != run["organization_id"]
            or row["campaign_run_id"] != run["run_id"]
            or row["attempt_id"] != attempt_id
            or row["execution_mode"] != "hosted_advisory"
            or row["status"] != "succeeded"
            or row["error_code"] is not None
            or row["finished_at"] is None
            or row["duration_ms"] is None
            or not _is_safe_provider_identity(row["returned_model"], maximum=160)
            or row["returned_model"] != row["model"]
            or not _is_safe_provider_identity(row["upstream_provider"], maximum=128)
            or not _is_safe_provider_identity(row["provider_request_id"], maximum=256)
            or row["input_tokens"] is None
            or row["output_tokens"] is None
            or row["reasoning_tokens"] is None
            or row["measured_cost"] is None
            or row["cost_measurement_state"] != "measured"
            or row["physical_attempts"] != 1
            or row["configuration_set_sha256"] != run["acceptance_configuration_sha256"]
            or row["generation_policy_sha256"] != run["acceptance_generation_policy_sha256"]
            or row["trace_id"] != snapshot.trace_id
            or row["langfuse_status"] not in {"queued", "exported"}
            or (row["langfuse_status"] == "exported") != (row["langfuse_verified_at"] is not None)
            or not isinstance(detail, dict)
            or detail.get("acceptance_id") != run["run_id"]
            or detail.get("run_kind") != "agent_acceptance"
            or detail.get("synthetic") is not True
            or detail.get("target_call_limit") != 0
        ):
            raise AssertionError(f"{execution_id}: logical acceptance lineage is invalid")
        event_ids = row["provider_event_ids"]
        if not isinstance(event_ids, list) or len(event_ids) != 1:
            raise AssertionError(f"{execution_id}: logical provider-event projection is invalid")

    if (
        judge["judge_calibration_state"] != "failed"
        or not isinstance(judge["judge_calibration_id"], str)
        or not str(judge["judge_calibration_id"]).startswith("JC-")
        or judge["decision_authority"] != "oracle"
        or type(judge["oracle_agreement"]) is not bool
    ):
        raise AssertionError("agent acceptance Judge is not advisory and oracle-decisive")
    for role in ("orchestrator", "documentation"):
        row = by_role[role]
        if (
            row["judge_calibration_id"] is not None
            or row["judge_calibration_state"] is not None
            or row["decision_authority"] is not None
            or row["oracle_agreement"] is not None
        ):
            raise AssertionError(f"{role}: non-Judge execution carries Judge authority")

    if len(snapshot.provider_calls) != len(ACCEPTANCE_ROLES):
        raise AssertionError("agent acceptance requires exactly three provider invocations/events")
    physical_by_execution: dict[str, dict[str, Any]] = {}
    event_ids: set[str] = set()
    for call in snapshot.provider_calls:
        execution_id = str(call["logical_execution_id"])
        logical = next(
            (row for row in snapshot.agents if row["execution_id"] == execution_id),
            None,
        )
        if logical is None or execution_id in physical_by_execution:
            raise AssertionError("provider lineage does not map one-to-one to logical executions")
        event_id = call["event_id"]
        if (
            not isinstance(event_id, str)
            or _PROVIDER_EVENT_ID.fullmatch(event_id) is None
            or event_id in event_ids
        ):
            raise AssertionError("provider event identity is unavailable or duplicated")
        event_ids.add(event_id)
        if (
            call["organization_id"] != run["organization_id"]
            or call["campaign_run_id"] != run["run_id"]
            or call["campaign_attempt_id"] != attempt_id
            or call["parent_execution_id"] != logical["parent_execution_id"]
            or call["agent_role"] != logical["agent_role"]
            or call["physical_sequence"] != 1
            or call["requested_model"] != logical["model"]
            or not _served_provider_matches_configured(
                call["configured_upstream"],
                logical["upstream_provider"],
            )
            or call["configuration_set_sha256"] != logical["configuration_set_sha256"]
            or call["role_configuration_sha256"] != logical["role_configuration_sha256"]
            or call["generation_policy_sha256"] != logical["generation_policy_sha256"]
            or call["event_status"] != "succeeded"
            or call["event_returned_model"] != logical["returned_model"]
            or call["event_upstream_provider"] != logical["upstream_provider"]
            or call["event_provider_request_id"] != logical["provider_request_id"]
            or call["event_input_tokens"] != logical["input_tokens"]
            or call["event_output_tokens"] != logical["output_tokens"]
            or call["event_reasoning_tokens"] != logical["reasoning_tokens"]
            or call["event_cost_measurement_state"] != "measured"
            or call["event_measured_cost_usd"] != logical["measured_cost"]
            or call["event_error_code"] is not None
            or call["event_finished_at"] is None
            or call["event_duration_ms"] is None
            or logical["provider_event_ids"] != [event_id]
        ):
            raise AssertionError(f"{execution_id}: physical provider lineage does not reconcile")
        physical_by_execution[execution_id] = call
    if set(physical_by_execution) != execution_ids:
        raise AssertionError("provider lineage does not cover every logical execution")
    return by_role


def _assert_observation_environment(
    observation: Any,
    *,
    expected_environment: str,
    label: str,
) -> None:
    if _metadata(observation).get("deployment.environment") != expected_environment:
        raise AssertionError(f"{label}: deployment environment does not reconcile")
    if _field(observation, "environment") != expected_environment:
        raise AssertionError(f"{label}: native Langfuse environment does not reconcile")


def _assert_remote_metadata(
    observation: Any,
    *,
    row: dict[str, Any],
    expected_environment: str,
    label: str,
) -> None:
    metadata = _metadata(observation)
    expected = {
        "organization_id": row["organization_id"],
        "campaign_run_id": row["campaign_run_id"],
        "run.kind": "agent_acceptance",
        "agent.acceptance_run_id": row["campaign_run_id"],
        "attempt_id": row["attempt_id"],
        "parent_execution_id": row["parent_execution_id"],
        "agent.execution_id": row["execution_id"],
        "agent.role": row["agent_role"],
        "agent.provider": row["provider"],
        "agent.model": row["model"],
        "agent.execution_mode": row["execution_mode"],
        "agent.input_sha256": row["input_sha256"],
        "agent.output_sha256": row["output_sha256"],
        "agent.configuration_set_sha256": row["configuration_set_sha256"],
        "agent.role_configuration_sha256": row["role_configuration_sha256"],
        "agent.generation_policy_sha256": row["generation_policy_sha256"],
        "agent.status": row["status"],
        "agent.returned_model": row["returned_model"],
        "agent.upstream_provider": row["upstream_provider"],
        "agent.provider_request_id": row["provider_request_id"],
        "agent.physical_attempts": row["physical_attempts"],
        "agent.provider_event_ids": row["provider_event_ids"],
        "cost.measurement_state": row["cost_measurement_state"],
        "cost.source": "provider_measured",
        "currency": "USD",
        "judge.calibration_id": row["judge_calibration_id"],
        "judge.calibration_state": row["judge_calibration_state"],
        "judge.oracle_agreement": row["oracle_agreement"],
        "judge.decision_authority": row["decision_authority"],
        "error_code": None,
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise AssertionError(
                f"{row['execution_id']}: {label} metadata {key} does not reconcile"
            )
    if _decimal(metadata.get("cost.usd"), label="Langfuse metadata cost") != _decimal(
        row["measured_cost"],
        label="durable measured cost",
    ):
        raise AssertionError(f"{row['execution_id']}: {label} metadata cost does not reconcile")
    if _decimal(metadata.get("agent.duration_ms"), label="Langfuse duration") != _decimal(
        row["duration_ms"],
        label="durable duration",
    ):
        raise AssertionError(f"{row['execution_id']}: {label} duration does not reconcile")
    _assert_observation_environment(
        observation,
        expected_environment=expected_environment,
        label=f"{row['execution_id']}: {label}",
    )


def assert_remote_acceptance(
    snapshot: AcceptanceSnapshot,
    observations: list[Any],
    *,
    expected_environment: str,
) -> dict[str, tuple[str, str]]:
    """Reconcile exactly three typed Langfuse agent/generation pairs."""

    assert_durable_acceptance(snapshot)
    if len(observations) != len(ACCEPTANCE_ROLES) * 2:
        raise AssertionError("Langfuse acceptance trace must contain exactly three role pairs")
    rows_by_execution = {str(row["execution_id"]): row for row in snapshot.agents}
    observations_by_execution: defaultdict[str, list[Any]] = defaultdict(list)
    observation_ids: set[str] = set()
    for observation in observations:
        observation_id = _field(observation, "id")
        if not isinstance(observation_id, str) or not observation_id:
            raise AssertionError("Langfuse observation identity is unavailable")
        if observation_id in observation_ids:
            raise AssertionError("Langfuse observation identity is duplicated")
        observation_ids.add(observation_id)
        execution_id = _metadata(observation).get("agent.execution_id")
        if execution_id not in rows_by_execution:
            raise AssertionError("Langfuse observation references an unknown acceptance execution")
        observations_by_execution[str(execution_id)].append(observation)

    evidence: dict[str, tuple[str, str]] = {}
    for execution_id, row in rows_by_execution.items():
        expected_agent_name = f"agent.{row['agent_role']}"
        expected_generation_name = f"{expected_agent_name}.runtime"
        execution_observations = observations_by_execution[execution_id]
        signatures = Counter(
            (_field(observation, "name"), _field(observation, "type"))
            for observation in execution_observations
        )
        if signatures != Counter(
            {
                (expected_agent_name, "AGENT"): 1,
                (expected_generation_name, "GENERATION"): 1,
            }
        ):
            raise AssertionError(
                f"{execution_id}: expected exactly one typed agent/runtime observation pair"
            )
        agent = next(item for item in execution_observations if _field(item, "type") == "AGENT")
        generation = next(
            item for item in execution_observations if _field(item, "type") == "GENERATION"
        )
        for label, observation in (("agent", agent), ("generation", generation)):
            if _field(observation, "trace_id", "traceId") != snapshot.trace_id:
                raise AssertionError(f"{execution_id}: {label} trace does not reconcile")
            if _field(observation, "end_time", "endTime") is None:
                raise AssertionError(f"{execution_id}: {label} observation is not terminal")
            if _field(observation, "status_message", "statusMessage") != "succeeded":
                raise AssertionError(f"{execution_id}: {label} terminal status does not reconcile")
            if _structured_io(observation, "input") != {"sha256": row["input_sha256"]}:
                raise AssertionError(f"{execution_id}: {label} input hash does not reconcile")
            if _structured_io(observation, "output") != {"sha256": row["output_sha256"]}:
                raise AssertionError(f"{execution_id}: {label} output hash does not reconcile")
            _assert_remote_metadata(
                observation,
                row=row,
                expected_environment=expected_environment,
                label=label,
            )

        agent_id = str(_field(agent, "id"))
        generation_id = str(_field(generation, "id"))
        if (
            _field(
                generation,
                "parent_observation_id",
                "parentObservationId",
            )
            != agent_id
        ):
            raise AssertionError(f"{execution_id}: generation is not a child of its agent")
        parent_execution_id = row["parent_execution_id"]
        remote_parent = _field(agent, "parent_observation_id", "parentObservationId")
        if parent_execution_id is None:
            if remote_parent is not None:
                raise AssertionError(f"{execution_id}: root agent has a remote parent")
        else:
            parent_agents = [
                item
                for item in observations_by_execution[str(parent_execution_id)]
                if _field(item, "type") == "AGENT"
            ]
            if len(parent_agents) != 1 or remote_parent != _field(parent_agents[0], "id"):
                raise AssertionError(f"{execution_id}: native cross-agent parentage is incorrect")

        if _field(generation, "provided_model_name", "providedModelName") != row["returned_model"]:
            raise AssertionError(f"{execution_id}: served model does not reconcile")
        remote_usage = {
            "input": _usage_value(generation, "input"),
            "output": _usage_value(generation, "output"),
            "reasoning": _usage_value(generation, "reasoning"),
        }
        durable_usage = {
            "input": row["input_tokens"],
            "output": row["output_tokens"],
            "reasoning": row["reasoning_tokens"],
        }
        if remote_usage != durable_usage:
            raise AssertionError(f"{execution_id}: provider token usage does not reconcile")
        if _usage_value(generation, "total") != sum(remote_usage.values()):
            raise AssertionError(f"{execution_id}: total token usage does not reconcile")
        if _cost_value(generation) != _decimal(
            row["measured_cost"],
            label="durable measured cost",
        ):
            raise AssertionError(f"{execution_id}: provider cost does not reconcile")
        evidence[str(row["agent_role"])] = (agent_id, generation_id)
    return evidence


def record_queryback_verification(
    engine: Engine,
    *,
    run_id: str,
    execution_ids: list[str],
) -> None:
    """Atomically mark exactly the remotely reconciled three executions exported."""

    if len(execution_ids) != len(ACCEPTANCE_ROLES) or len(set(execution_ids)) != len(
        ACCEPTANCE_ROLES
    ):
        raise AssertionError("verified acceptance execution identities are invalid")
    expected_ids = set(execution_ids)
    with engine.begin() as connection:
        snapshot = load_acceptance_snapshot(
            connection,
            run_id=run_id,
            lock_authority=True,
        )
        assert_durable_acceptance(snapshot)
        durable_ids = {str(row["execution_id"]) for row in snapshot.agents}
        if durable_ids != expected_ids:
            raise AssertionError("verified execution identities differ from durable acceptance")
        recorded_ids = set(
            connection.execute(
                text(
                    "UPDATE agent_executions SET langfuse_status = 'exported', "
                    "langfuse_verified_at = COALESCE(langfuse_verified_at, clock_timestamp()) "
                    "WHERE organization_id = :org AND campaign_run_id = :run_id "
                    "AND execution_id = ANY(:execution_ids) "
                    "AND langfuse_status IN ('queued', 'exported') RETURNING execution_id"
                ),
                {
                    "org": snapshot.run["organization_id"],
                    "run_id": run_id,
                    "execution_ids": list(expected_ids),
                },
            ).scalars()
        )
        if recorded_ids != expected_ids:
            raise AssertionError(
                "acceptance Langfuse verification persistence did not match all three executions"
            )


__all__ = [
    "ACCEPTANCE_ROLES",
    "OBSERVATION_FIELDS",
    "AcceptanceSnapshot",
    "assert_durable_acceptance",
    "assert_remote_acceptance",
    "load_acceptance_snapshot",
    "record_queryback_verification",
]
