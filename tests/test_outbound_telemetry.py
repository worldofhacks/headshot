"""Durable, redacted per-request telemetry; every transport is an in-memory fake."""

from __future__ import annotations

from sqlalchemy import Engine, text

from agentforge.secrets import Secret
from agentforge.target.base import TargetRequest
from agentforge.target.openemr_adapter import OpenEmrAdapter
from agentforge.telemetry import OutboundHttpTelemetry


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
