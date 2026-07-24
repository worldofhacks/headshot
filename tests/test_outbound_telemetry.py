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


class _DisabledLangfuse(_Langfuse):
    @staticmethod
    def configured() -> bool:
        return False


class _TransientReadFailureEngine:
    """Delegate every operation except a bounded number of completion reads."""

    def __init__(self, engine: Engine, *, failures: int) -> None:
        self.engine = engine
        self.failures = failures
        self.connect_calls = 0

    def begin(self):
        return self.engine.begin()

    def connect(self):
        self.connect_calls += 1
        if self.connect_calls <= self.failures:
            raise RuntimeError("transient completion read failure")
        return self.engine.connect()


def _seed_campaign(engine: Engine, *, suffix: str) -> tuple[str, str]:
    organization_id = "org_OutboundTelemetry"
    run_id = f"run-outbound-telemetry-{suffix}"
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO campaign_runs (run_id, organization_id, authorization_request_id, "
                "scope_hash, launcher_user_id, launcher_session_id) VALUES "
                "(:run_id, :org, :request_id, :hash, "
                "'user_OutboundTelemetry', 'sess_OutboundTelemetry') "
                "ON CONFLICT DO NOTHING"
            ),
            {
                "run_id": run_id,
                "org": organization_id,
                "request_id": f"request-outbound-{suffix}",
                "hash": "d" * 64,
            },
        )
    return organization_id, run_id


def test_physical_target_request_is_persisted_and_queued_for_queryback_without_credential(
    migrated_db: Engine,
) -> None:
    organization_id, run_id = _seed_campaign(migrated_db, suffix="physical-request")
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
                "target_id": "openemr-live",
                "target_version": "version-1",
                "surface_id": "clinical-copilot",
                "surface_version": "surface-1",
                "execution_profile": "live",
                "future_untrusted_metadata": raw_session,
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
    assert row["langfuse_status"] == "queued"
    assert raw_session not in str(row["request_payload"])
    assert raw_session not in row["response_payload"]
    assert "***REDACTED***" in row["response_payload"]
    assert langfuse.flushed is True
    assert raw_session not in str(langfuse.started)
    assert raw_session not in str(langfuse.finished)
    assert langfuse.started[0]["model"] == "openemr"
    assert langfuse.started[0]["version"] == "version-1"
    assert langfuse.started[0]["metadata"]["deployment.environment"] == "staging"
    assert langfuse.started[0]["metadata"]["http.request.body.size"] == row["request_bytes"]
    assert langfuse.finished[0]["metadata"]["http.response.body.size"] == row["response_bytes"]
    assert (
        langfuse.finished[0]["metadata"]["http.request.body.sha256"]
        == langfuse.started[0]["metadata"]["http.request.body.sha256"]
    )
    assert langfuse.finished[0]["metadata"]["target_id"] == "openemr-live"
    assert "future_untrusted_metadata" not in langfuse.started[0]["metadata"]
    assert set(langfuse.started[0]["request_payload"]) == {"sha256", "bytes"}
    assert set(langfuse.finished[0]["output"]) == {"sha256", "bytes"}


def test_target_projection_uses_postgres_canonical_duration_and_cost(
    migrated_db: Engine,
) -> None:
    organization_id, run_id = _seed_campaign(migrated_db, suffix="canonical-accounting")
    ticks = iter((10.0, 10.0012346))
    telemetry = OutboundHttpTelemetry(
        migrated_db,
        environment="staging",
        per_request_cost_usd=0.01234567,
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

    adapter.send(
        TargetRequest(
            turns=("reviewed adversarial prompt",),
            metadata={
                "organization_id": organization_id,
                "campaign_run_id": run_id,
                "attempt_id": "attempt-canonical-accounting",
            },
        )
    )

    with migrated_db.connect() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT duration_ms, measured_cost FROM outbound_http_requests "
                    "WHERE organization_id = :org AND campaign_run_id = :run_id"
                ),
                {"org": organization_id, "run_id": run_id},
            )
            .mappings()
            .one()
        )
    canonical_duration = float(row["duration_ms"])
    canonical_cost = float(row["measured_cost"])
    assert canonical_duration == 1.235
    assert canonical_cost == 0.012346
    assert langfuse.started[0]["measured_cost"] == canonical_cost
    assert langfuse.started[0]["metadata"]["cost.usd"] == canonical_cost
    assert langfuse.finished[0]["measured_cost"] == canonical_cost
    assert langfuse.finished[0]["metadata"]["duration_ms"] == canonical_duration


def test_many_requests_share_one_campaign_trace_and_reconcile_individually(
    migrated_db: Engine,
) -> None:
    organization_id, run_id = _seed_campaign(migrated_db, suffix="shared-trace")
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
    assert all(row["langfuse_status"] == "queued" for row in rows)
    assert len(langfuse.started) == 2
    assert {item["trace_id"] for item in langfuse.started} == {rows[0]["trace_id"]}


def test_target_observation_is_a_native_child_of_bound_red_team(
    migrated_db: Engine,
) -> None:
    organization_id, run_id = _seed_campaign(migrated_db, suffix="target-red-team-parent")
    telemetry = OutboundHttpTelemetry(migrated_db, environment="staging")
    langfuse = _Langfuse()
    telemetry.langfuse = langfuse  # type: ignore[assignment]
    store = ControlPlaneStore(migrated_db, environment="staging")
    red_team_execution = store.start_agent_execution(
        run_id=run_id,
        agent_role="red_team",
        input_payload={"cycle": 0},
    )
    telemetry.begin_agent(
        execution_id=red_team_execution,
        input_payload={"cycle": 0},
    )
    attempt = store.ensure_campaign_attempt(
        run_id=run_id,
        ordinal=0,
        case_id="case-native-parent",
    )
    store.bind_agent_execution_attempt(
        execution_id=red_team_execution,
        run_id=run_id,
        attempt_id=attempt.attempt_id,
    )
    telemetry.bind_agent_attempt(
        execution_id=red_team_execution,
        attempt_id=attempt.attempt_id,
    )
    store.finish_agent_execution(
        execution_id=red_team_execution,
        status="succeeded",
        output_payload={"case_ref": "case-native-parent"},
    )
    telemetry.finish_agent(
        execution_id=red_team_execution,
        output_payload={"case_ref": "case-native-parent"},
    )

    adapter = OpenEmrAdapter(
        base_url="https://target.example.test",
        relative_path="chat",
        payload_profile="copilot_chat",
        credential=Secret("bounded-test-session"),
        client=_Client(_Response('{"answer":"bounded response"}')),
        telemetry=telemetry,
    )
    response = adapter.send(
        TargetRequest(
            turns=("reviewed adversarial prompt",),
            metadata={
                "organization_id": organization_id,
                "campaign_run_id": run_id,
                "attempt_id": attempt.attempt_id,
                "red_team_execution_id": red_team_execution,
            },
        )
    )

    assert response.status == 200
    assert langfuse.started[0]["parent_observation_id"] == "0000000000000001"
    assert langfuse.started[0]["metadata"]["red_team_execution_id"] == red_team_execution


def test_unresolved_target_parent_skips_projection_without_retrying_target(
    migrated_db: Engine,
) -> None:
    organization_id, run_id = _seed_campaign(migrated_db, suffix="unresolved-target-parent")
    telemetry = OutboundHttpTelemetry(migrated_db, environment="staging")
    langfuse = _Langfuse()
    telemetry.langfuse = langfuse  # type: ignore[assignment]
    client = _Client(_Response('{"answer":"bounded response"}'))
    adapter = OpenEmrAdapter(
        base_url="https://target.example.test",
        relative_path="chat",
        payload_profile="copilot_chat",
        credential=Secret("bounded-test-session"),
        client=client,
        telemetry=telemetry,
    )

    response = adapter.send(
        TargetRequest(
            turns=("reviewed adversarial prompt",),
            metadata={
                "organization_id": organization_id,
                "campaign_run_id": run_id,
                "attempt_id": "attempt-unresolved-parent",
                "red_team_execution_id": "unknown-red-team-execution",
            },
        )
    )

    assert response.status == 200
    assert client.calls == 1
    assert langfuse.started == []
    with migrated_db.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT langfuse_status FROM outbound_http_requests "
                    "WHERE campaign_run_id = :run_id"
                ),
                {"run_id": run_id},
            ).scalar_one()
            == "error"
        )


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
        ("https://langfuse.invalid/unexpected-path", False),
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


def test_langfuse_bridge_uses_native_parent_span_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-lf-public")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk-lf-secret")
    monkeypatch.setenv("LANGFUSE_BASE_URL", "https://us.cloud.langfuse.com")
    calls: list[dict] = []
    observation = object()

    class Manager:
        def __enter__(self):
            return observation

    class Client:
        def start_as_current_observation(self, **values):
            calls.append(values)
            return Manager()

    bridge = _LangfuseBridge()
    bridge.client = Client()

    state = bridge.start(
        trace_id="7" * 32,
        model="openemr",
        version="target-v1",
        request_payload={"sha256": "a" * 64, "bytes": 80},
        metadata={"red_team_execution_id": "execution-red-team"},
        measured_cost=0.01,
        parent_observation_id="0123456789abcdef",
    )

    assert state is not None
    assert state[1] is observation
    assert calls[0]["trace_context"] == {
        "trace_id": "7" * 32,
        "parent_span_id": "0123456789abcdef",
    }


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


def test_hosted_runtime_heartbeat_is_content_addressed_and_secret_free(
    migrated_db: Engine,
) -> None:
    telemetry = OutboundHttpTelemetry(migrated_db, environment="staging")
    configuration_sha256 = "a" * 64

    telemetry.hosted_runtime_heartbeat(
        configuration_sha256=configuration_sha256,
        provider_bindings_verified=True,
        langfuse_observation_ready=True,
    )

    with migrated_db.connect() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT component_id, name, kind, availability, detail "
                    "FROM runtime_component_status WHERE environment = 'staging' "
                    "AND component_id = :configuration"
                ),
                {"configuration": configuration_sha256},
            )
            .mappings()
            .one()
        )
    assert dict(row) == {
        "component_id": configuration_sha256,
        "name": "OpenRouter hosted runtime",
        "kind": "model-runtime",
        "availability": "operational and evidenced",
        "detail": ("four sealed provider bindings and Langfuse authentication verified by Runner"),
    }
    serialized = repr(dict(row)).lower()
    assert "secretref://" not in serialized
    assert "credential_reference" not in serialized
    assert "openrouter_api_key" not in serialized

    with pytest.raises(ValueError, match="configuration identity"):
        telemetry.hosted_runtime_heartbeat(
            configuration_sha256="A" * 64,
            provider_bindings_verified=True,
            langfuse_observation_ready=True,
        )


def test_hosted_runtime_stays_blocked_when_langfuse_is_not_authenticated(
    migrated_db: Engine,
) -> None:
    telemetry = OutboundHttpTelemetry(migrated_db, environment="staging")
    configuration_sha256 = "b" * 64

    telemetry.hosted_runtime_heartbeat(
        configuration_sha256=configuration_sha256,
        provider_bindings_verified=True,
        langfuse_observation_ready=False,
    )

    with migrated_db.connect() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT availability, detail FROM runtime_component_status "
                    "WHERE environment = 'staging' AND component_id = :configuration"
                ),
                {"configuration": configuration_sha256},
            )
            .mappings()
            .one()
        )
    assert dict(row) == {
        "availability": "blocked pending authorization",
        "detail": ("Langfuse authentication is unavailable for mandatory hosted observations"),
    }


def test_all_agent_roles_are_queued_for_queryback_with_observed_latency_and_spend(
    migrated_db: Engine,
) -> None:
    organization_id, run_id = _seed_campaign(migrated_db, suffix="all-agent-roles")
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
    assert all(row["langfuse_status"] == "queued" for row in rows)
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
    started_metadata = langfuse.agent_started[0]["metadata"]
    finished_metadata = langfuse.agent_finished[0]["metadata"]
    for key in (
        "deployment.environment",
        "organization_id",
        "campaign_run_id",
        "agent.execution_id",
        "agent.role",
        "agent.provider",
        "agent.model",
        "agent.execution_mode",
        "agent.input_sha256",
    ):
        assert finished_metadata[key] == started_metadata[key]
    assert finished_metadata["agent.status"] == "succeeded"


def test_disabled_agent_finish_releases_state_none_handle(migrated_db: Engine) -> None:
    _organization_id, run_id = _seed_campaign(migrated_db, suffix="disabled-agent")
    telemetry = OutboundHttpTelemetry(migrated_db, environment="staging")
    telemetry.langfuse = _DisabledLangfuse()  # type: ignore[assignment]
    store = ControlPlaneStore(migrated_db, environment="staging")
    execution_id = store.start_agent_execution(
        run_id=run_id,
        agent_role="orchestrator",
        input_payload={"cycle": 0},
    )

    telemetry.begin_agent(execution_id=execution_id, input_payload={"cycle": 0})
    assert execution_id in telemetry._agent_handles
    assert telemetry._agent_handles[execution_id].langfuse_state is None
    store.finish_agent_execution(
        execution_id=execution_id,
        status="succeeded",
        output_payload={"selected": "authorized-case"},
    )
    telemetry.finish_agent(
        execution_id=execution_id,
        output_payload={"selected": "authorized-case"},
    )

    assert execution_id not in telemetry._agent_handles
    assert execution_id not in telemetry._pending_agent_finishes
    with migrated_db.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT langfuse_status FROM agent_executions "
                    "WHERE execution_id = :execution_id"
                ),
                {"execution_id": execution_id},
            ).scalar_one()
            == "disabled"
        )


def test_flush_retries_each_pending_agent_finish_once_and_queues_for_queryback(
    migrated_db: Engine,
) -> None:
    _organization_id, run_id = _seed_campaign(migrated_db, suffix="pending-agent-finish")
    telemetry = OutboundHttpTelemetry(migrated_db, environment="staging")
    langfuse = _Langfuse()
    telemetry.langfuse = langfuse  # type: ignore[assignment]
    store = ControlPlaneStore(migrated_db, environment="staging")
    execution_id = store.start_agent_execution(
        run_id=run_id,
        agent_role="red_team",
        input_payload={"cycle": 1},
    )
    secret = "retry-only-secret-that-must-not-be-retained"
    telemetry.begin_agent(
        execution_id=execution_id,
        input_payload={"cycle": 1},
        redactions=(secret,),
    )
    store.finish_agent_execution(
        execution_id=execution_id,
        status="succeeded",
        output_payload={"selected": "authorized-case"},
        input_tokens=11,
        output_tokens=7,
        measured_cost=0.02,
    )
    transient_engine = _TransientReadFailureEngine(migrated_db, failures=2)
    telemetry.engine = transient_engine  # type: ignore[assignment]

    telemetry.finish_agent(
        execution_id=execution_id,
        output_payload={"private": secret},
    )

    assert transient_engine.connect_calls == 1
    assert execution_id in telemetry._agent_handles
    assert execution_id in telemetry._pending_agent_finishes
    assert secret not in repr(telemetry._pending_agent_finishes[execution_id])
    assert langfuse.agent_finished == []

    telemetry.flush()

    # A checkpoint attempts each pending finish once; a second read failure is retained rather
    # than recursed immediately.
    assert transient_engine.connect_calls == 2
    assert execution_id in telemetry._pending_agent_finishes
    assert langfuse.agent_finished == []

    telemetry.flush()

    assert transient_engine.connect_calls == 3
    assert execution_id not in telemetry._agent_handles
    assert execution_id not in telemetry._pending_agent_finishes
    assert len(langfuse.agent_finished) == 1
    assert langfuse.agent_finished[0]["input_tokens"] == 11
    assert langfuse.agent_finished[0]["output_tokens"] == 7
    assert langfuse.agent_finished[0]["measured_cost"] == 0.02
    assert langfuse.flushed is True
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


def test_repeated_children_keep_native_parentage_until_campaign_release(
    migrated_db: Engine,
) -> None:
    _organization_id, run_id = _seed_campaign(migrated_db, suffix="repeated-parent")
    telemetry = OutboundHttpTelemetry(migrated_db, environment="staging")
    langfuse = _Langfuse()
    telemetry.langfuse = langfuse  # type: ignore[assignment]
    store = ControlPlaneStore(migrated_db, environment="staging")
    parent = store.start_agent_execution(
        run_id=run_id,
        agent_role="orchestrator",
        input_payload={"cycle": 0},
    )
    telemetry.begin_agent(execution_id=parent, input_payload={"cycle": 0})
    store.finish_agent_execution(
        execution_id=parent,
        status="succeeded",
        output_payload={"selected": "authorized-case"},
    )
    telemetry.finish_agent(
        execution_id=parent,
        output_payload={"selected": "authorized-case"},
    )

    children: list[str] = []
    for cycle in (1, 2):
        child = store.start_agent_execution(
            run_id=run_id,
            agent_role="red_team",
            parent_execution_id=parent,
            input_payload={"cycle": cycle},
        )
        telemetry.begin_agent(execution_id=child, input_payload={"cycle": cycle})
        store.finish_agent_execution(
            execution_id=child,
            status="succeeded",
            output_payload={"cycle": cycle, "selected": "authorized-case"},
        )
        telemetry.finish_agent(
            execution_id=child,
            output_payload={"cycle": cycle, "selected": "authorized-case"},
        )
        children.append(child)

    assert [item["parent_observation_id"] for item in langfuse.agent_started] == [
        None,
        "0000000000000001",
        "0000000000000001",
    ]
    telemetry.flush()
    telemetry.release_campaign(run_id)
    assert not telemetry._agent_observation_ids
    assert not telemetry._agent_campaign_ids
