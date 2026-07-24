"""Durable, redacted per-request telemetry; every transport is an in-memory fake."""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, text

from agentforge.control_plane.store import ControlPlaneStore
from agentforge.secrets import Secret
from agentforge.target.base import TargetRequest
from agentforge.target.openemr_adapter import OpenEmrAdapter
from agentforge.telemetry import OutboundHttpTelemetry
from agentforge.telemetry.outbound import _LangfuseBridge, _sanitize_text


class _Response:
    status_code = 200
    headers = {"Content-Type": "application/json"}

    def __init__(self, text_value: str) -> None:
        self.text = text_value


class _Client:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.calls = 0

    def request(self, *_args, **_kwargs):
        self.calls += 1
        return self.response


class _Langfuse:
    def __init__(self) -> None:
        self.started: list[dict] = []
        self.finished: list[dict] = []
        self.agent_started: list[dict] = []
        self.agent_finished: list[dict] = []
        self.flushed = False

    @staticmethod
    def configured() -> bool:
        return True

    @staticmethod
    def auth_check() -> bool:
        return True

    def start(self, **values):
        self.started.append(values)
        return (object(), object())

    def finish(self, _state, **values) -> None:
        self.finished.append(values)

    def start_agent(self, **values):
        self.agent_started.append(values)
        observation_id = f"{len(self.agent_started):016x}"
        return (object(), object(), "deterministic_zero", observation_id)

    def finish_agent(self, _state, **values) -> None:
        self.agent_finished.append(values)

    def flush(self) -> None:
        self.flushed = True

    def shutdown(self) -> None:
        return None


def _seed_campaign(engine: Engine) -> tuple[str, str]:
    organization_id = "org_OutboundTelemetry"
    run_id = "run-outbound-telemetry-0001"
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO campaign_runs (run_id, organization_id, authorization_request_id, "
                "scope_hash, launcher_user_id, launcher_session_id) VALUES "
                "(:run_id, :org, 'request-outbound-telemetry', :hash, "
                "'user_OutboundTelemetry', 'sess_OutboundTelemetry') "
                "ON CONFLICT DO NOTHING"
            ),
            {"run_id": run_id, "org": organization_id, "hash": "d" * 64},
        )
    return organization_id, run_id


def test_physical_target_request_is_persisted_and_exported_without_credential(
    migrated_db: Engine,
) -> None:
    organization_id, run_id = _seed_campaign(migrated_db)
    ticks = iter((10.0, 10.125))
    telemetry = OutboundHttpTelemetry(
        migrated_db,
        environment="staging",
        per_request_cost_usd=0.01,
        monotonic=lambda: next(ticks),
    )
    langfuse = _Langfuse()
    telemetry.langfuse = langfuse  # type: ignore[assignment]
    raw_session = "session-value-that-must-never-reach-telemetry"
    client = _Client(_Response(f'{{"echo":"{raw_session}","answer":"synthetic"}}'))
    adapter = OpenEmrAdapter(
        base_url="https://target.example.test",
        relative_path="chat",
        payload_profile="copilot_chat",
        credential=Secret(raw_session),
        client=client,
        telemetry=telemetry,
    )
    response = adapter.send(
        TargetRequest(
            turns=("synthetic adversarial prompt",),
            metadata={
                "organization_id": organization_id,
                "campaign_run_id": run_id,
                "attempt_id": "attempt-outbound-telemetry-0001",
                "case_id": "case-synthetic-0001",
            },
        )
    )
    telemetry.flush()

    assert client.calls == 1
    assert raw_session in response.output  # target evidence remains verbatim
    with migrated_db.connect() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT * FROM outbound_http_requests "
                    "WHERE organization_id = :org AND campaign_run_id = :run_id"
                ),
                {"org": organization_id, "run_id": run_id},
            )
            .mappings()
            .one()
        )
    assert row["status"] == "succeeded"
    assert row["status_code"] == 200
    assert float(row["duration_ms"]) == 125.0
    assert float(row["measured_cost"]) == 0.01
    assert row["langfuse_status"] == "exported"
    assert raw_session not in str(row["request_payload"])
    assert raw_session not in row["response_payload"]
    assert "***REDACTED***" in row["response_payload"]
    assert langfuse.flushed is True
    assert raw_session not in str(langfuse.started)
    assert raw_session not in str(langfuse.finished)
    assert langfuse.started[0]["model"] == "openemr"
    assert langfuse.started[0]["version"] == "unknown"
    assert langfuse.started[0]["metadata"]["deployment.environment"] == "staging"
    assert langfuse.started[0]["metadata"]["http.request.body.size"] == row["request_bytes"]
    assert langfuse.finished[0]["metadata"]["http.response.body.size"] == row["response_bytes"]
    assert set(langfuse.started[0]["request_payload"]) == {"sha256", "bytes"}
    assert set(langfuse.finished[0]["output"]) == {"sha256", "bytes"}


def test_many_requests_share_one_campaign_trace_and_reconcile_individually(
    migrated_db: Engine,
) -> None:
    organization_id, run_id = _seed_campaign(migrated_db)
    ticks = iter((10.0, 10.010, 11.0, 11.020))
    telemetry = OutboundHttpTelemetry(
        migrated_db,
        environment="staging",
        monotonic=lambda: next(ticks),
    )
    langfuse = _Langfuse()
    telemetry.langfuse = langfuse  # type: ignore[assignment]
    adapter = OpenEmrAdapter(
        base_url="https://target.example.test",
        relative_path="chat",
        payload_profile="copilot_chat",
        credential=Secret("bounded-test-session"),
        client=_Client(_Response('{"answer":"bounded response"}')),
        telemetry=telemetry,
    )

    for index in range(2):
        adapter.send(
            TargetRequest(
                turns=(f"reviewed adversarial prompt {index}",),
                metadata={
                    "organization_id": organization_id,
                    "campaign_run_id": run_id,
                    "attempt_id": f"attempt-shared-trace-{index}",
                },
            )
        )
    telemetry.flush()

    with migrated_db.connect() as connection:
        rows = (
            connection.execute(
                text(
                    "SELECT request_id, trace_id, langfuse_status "
                    "FROM outbound_http_requests WHERE campaign_run_id = :run_id "
                    "ORDER BY started_at"
                ),
                {"run_id": run_id},
            )
            .mappings()
            .all()
        )
    assert len(rows) == 2
    assert len({row["request_id"] for row in rows}) == 2
    assert len({row["trace_id"] for row in rows}) == 1
    assert all(row["langfuse_status"] == "exported" for row in rows)
    assert len(langfuse.started) == 2
    assert {item["trace_id"] for item in langfuse.started} == {rows[0]["trace_id"]}


def test_sanitizer_removes_opaque_authorization_cookie_and_url_credentials() -> None:
    opaque = "opaque-access-value-abcdefghijklmnop"
    cookie = "secondary-cookie-abcdefghijklmnop"
    password = "userinfo-password-abcdefghijklmnop"
    value = (
        f"Authorization: Bearer {opaque}\n"
        f"Cookie: session=first; secondary={cookie}\n"
        f"https://operator:{password}@target.example.test/chat"
    )

    sanitized = _sanitize_text(value, ())

    assert opaque not in sanitized
    assert cookie not in sanitized
    assert password not in sanitized
    assert "REDACTED_AUTHORIZATION" in sanitized
    assert "REDACTED_COOKIE" in sanitized
    assert "REDACTED_USERINFO" in sanitized


@pytest.mark.parametrize(
    "base_url,expected",
    [
        ("https://us.cloud.langfuse.com", True),
        ("http://langfuse.internal", False),
        ("https://user:password@langfuse.invalid", False),
        ("https://langfuse.invalid?credential=unsafe", False),
    ],
)
def test_langfuse_export_requires_a_safe_https_endpoint(
    monkeypatch: pytest.MonkeyPatch,
    base_url: str,
    expected: bool,
) -> None:
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-lf-public")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk-lf-secret")
    monkeypatch.setenv("LANGFUSE_BASE_URL", base_url)

    assert _LangfuseBridge.configured() is expected


def test_runner_and_langfuse_connection_heartbeat_is_persisted(migrated_db: Engine) -> None:
    telemetry = OutboundHttpTelemetry(migrated_db, environment="staging")
    telemetry.langfuse = _Langfuse()  # type: ignore[assignment]

    telemetry.heartbeat(force_connection_check=True)

    with migrated_db.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT component_id, availability FROM runtime_component_status "
                "WHERE environment = 'staging' AND component_id IN ('runner','langfuse')"
            )
        ).all()
    assert dict(rows) == {
        "runner": "operational and evidenced",
        "langfuse": "operational and evidenced",
    }


def test_all_agent_roles_are_exported_with_observed_latency_and_spend(
    migrated_db: Engine,
) -> None:
    organization_id, run_id = _seed_campaign(migrated_db)
    telemetry = OutboundHttpTelemetry(migrated_db, environment="staging")
    langfuse = _Langfuse()
    telemetry.langfuse = langfuse  # type: ignore[assignment]
    store = ControlPlaneStore(migrated_db, environment="staging")
    parent: str | None = None

    for index, role in enumerate(("orchestrator", "red_team", "judge", "documentation")):
        execution_id = store.start_agent_execution(
            run_id=run_id,
            agent_role=role,
            attempt_id=f"attempt-{index}" if role in {"judge", "documentation"} else None,
            parent_execution_id=parent,
            input_payload={"role": role, "fixture_classification": "synthetic"},
        )
        with migrated_db.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT langfuse_status FROM agent_executions "
                        "WHERE execution_id = :execution_id"
                    ),
                    {"execution_id": execution_id},
                ).scalar_one()
                == "not_attempted"
            )
        telemetry.begin_agent(
            execution_id=execution_id,
            input_payload={"role": role, "fixture_classification": "synthetic"},
        )
        with migrated_db.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT langfuse_status FROM agent_executions "
                        "WHERE execution_id = :execution_id"
                    ),
                    {"execution_id": execution_id},
                ).scalar_one()
                == "queued"
            )
        measured_cost = 0.0 if role in {"orchestrator", "judge"} else 0.01 * index
        store.finish_agent_execution(
            execution_id=execution_id,
            status="succeeded",
            output_payload={"role": role, "result": "complete"},
            measured_cost=measured_cost,
        )
        telemetry.finish_agent(
            execution_id=execution_id,
            output_payload={"role": role, "result": "complete"},
        )
        parent = execution_id

    telemetry.flush()

    with migrated_db.connect() as connection:
        rows = (
            connection.execute(
                text(
                    "SELECT agent_role, duration_ms, measured_cost, langfuse_status "
                    "FROM agent_executions WHERE campaign_run_id = :run_id ORDER BY id"
                ),
                {"run_id": run_id},
            )
            .mappings()
            .all()
        )
    assert {row["agent_role"] for row in rows} == {
        "orchestrator",
        "red_team",
        "judge",
        "documentation",
    }
    assert all(float(row["duration_ms"]) >= 0 for row in rows)
    assert all(row["langfuse_status"] == "exported" for row in rows)
    assert float(rows[0]["measured_cost"]) == 0.0
    assert float(rows[2]["measured_cost"]) == 0.0
    assert [item["role"] for item in langfuse.agent_started] == [
        "orchestrator",
        "red_team",
        "judge",
        "documentation",
    ]
    assert [item["parent_observation_id"] for item in langfuse.agent_started] == [
        None,
        "0000000000000001",
        "0000000000000002",
        "0000000000000003",
    ]
    assert [item["measured_cost"] for item in langfuse.agent_finished] == [
        0.0,
        0.01,
        0.0,
        0.03,
    ]
