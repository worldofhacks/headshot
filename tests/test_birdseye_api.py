"""Authoritative Birdseye projection contracts."""

from __future__ import annotations

import json

from sqlalchemy import Engine, text

from agentforge.api.birdseye import build_birdseye_snapshot
from agentforge.api.postgres import PostgresApiBackend
from agentforge.auth.principal import Principal
from agentforge.policy.recorder import ExecutionRecorder


def _principal(organization_id: str) -> Principal:
    return Principal(
        user_id="user_birdseye_reader",
        session_id="session_birdseye_reader",
        organization_id=organization_id,
        organization_role="org:operator",
        organization_permissions=frozenset({"org:console:read"}),
    )


def test_birdseye_is_registry_derived_and_omits_missing_components(
    migrated_db: Engine,
) -> None:
    environment = "local"
    organization_id = "org_BirdseyeFixture"
    with migrated_db.begin() as connection:
        connection.execute(
            text("DELETE FROM runtime_component_status WHERE environment = :environment"),
            {"environment": environment},
        )

    with migrated_db.connect() as connection:
        unobserved = build_birdseye_snapshot(
            connection,
            organization_id=organization_id,
            environment=environment,
        )
    assert unobserved["instrumentation"]["system_state"] == "unavailable"
    unobserved_nodes = {node["component_id"]: node for node in unobserved["nodes"]}
    assert unobserved_nodes["agent:judge"]["runtime_state"] == "unavailable"

    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO runtime_component_status "
                "(environment, component_id, name, kind, availability, detail, heartbeat_at) "
                "VALUES (:environment, 'runner', 'Campaign runner', 'worker', "
                "'operational and evidenced', 'private runner heartbeat', clock_timestamp()) "
                "ON CONFLICT (environment, component_id) DO UPDATE SET "
                "availability = EXCLUDED.availability, detail = EXCLUDED.detail, "
                "heartbeat_at = EXCLUDED.heartbeat_at"
            ),
            {"environment": environment},
        )

    with migrated_db.connect() as connection:
        projected = build_birdseye_snapshot(
            connection,
            organization_id=organization_id,
            environment=environment,
        )
    assert projected["campaign"] is None

    backend = PostgresApiBackend(migrated_db, environment=environment)
    result = backend.read("birdseye", _principal(organization_id))

    assert result.state == "ready", result.model_dump()
    assert result.data["campaign"] is None
    assert result.data["instrumentation"]["queue_queued"] == 0
    assert result.data["instrumentation"]["queue_leased"] == 0
    assert result.data["instrumentation"]["confirmed_finding_count"] == 0
    assert result.data["security_posture"]["tested_categories"] == 0
    assert result.data["security_posture"]["priority_source"] == "unavailable"
    assert result.data["category_outcomes"] == []
    assert result.data["agent_activity"] == []
    assert result.data["instrumentation"]["total_components"] == 7
    nodes = {node["component_id"]: node for node in result.data["nodes"]}
    assert set(nodes) == {
        "web-api",
        "postgres",
        "runner",
        "agent:orchestrator",
        "agent:red_team",
        "agent:judge",
        "agent:documentation",
    }
    assert nodes["runner"]["target_access"] == "policy-gated"
    assert nodes["runner"]["accounting_status"] is None
    assert nodes["runner"]["is_fresh"] is True
    assert nodes["agent:judge"]["heartbeat_at"] is None
    assert nodes["agent:judge"]["availability"] == "runtime execution not observed"
    assert nodes["agent:judge"]["runtime_state"] == "unavailable"
    assert nodes["agent:judge"]["healthy_instances"] == 0
    assert nodes["agent:judge"]["accounting_status"] == "not_applicable"
    assert nodes["agent:judge"]["current_task"].startswith("Configured; runtime execution")
    assert result.data["instrumentation"]["system_state"] == "degraded"
    assert "langfuse" not in nodes
    assert all(
        edge["source_component_id"] in nodes and edge["target_component_id"] in nodes
        for edge in result.data["edges"]
    )

    components = backend.read("components", _principal(organization_id))
    component_ids = {component["component_id"] for component in components.data}
    assert "runner" in component_ids
    assert "langfuse" not in component_ids


def test_birdseye_projects_security_outcomes_and_recorded_agent_causality(
    migrated_db: Engine,
) -> None:
    organization_id = "org_BirdseyeOutcomeFixture"
    run_id = "birdseye-outcome-run"
    attempt_id = "birdseye-outcome-attempt"
    scope_hash = "a" * 64
    scope = {
        "target_id": "copilot-live",
        "target_version": "2.0.0",
        "surface_id": "chat",
        "surface_version": "1.0.0",
        "execution_profile": "live",
        "caps": {
            "budget_usd": 5,
            "max_attempts_per_run": 9,
            "target_requests_per_second": 1,
            "run_timeout_seconds": 900,
        },
    }
    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, launcher_user_id, "
                "launcher_session_id, expires_at) VALUES "
                "('birdseye-outcome-request', :org, :scope_hash, CAST(:scope AS jsonb), "
                "'user_birdseye_launcher', 'sess_birdseye_launcher', "
                "TIMESTAMPTZ '2026-07-24 00:00:00+00')"
            ),
            {"org": organization_id, "scope_hash": scope_hash, "scope": json.dumps(scope)},
        )
        connection.execute(
            text(
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, authorization_request_id, scope_hash, "
                "launcher_user_id, launcher_session_id) VALUES "
                "(:run, :org, 'birdseye-outcome-request', :scope_hash, "
                "'user_birdseye_launcher', 'sess_birdseye_launcher')"
            ),
            {"run": run_id, "org": organization_id, "scope_hash": scope_hash},
        )
        connection.execute(
            text(
                "INSERT INTO campaign_run_events (organization_id, run_id, state) "
                "VALUES (:org, :run, 'running')"
            ),
            {"org": organization_id, "run": run_id},
        )
        connection.execute(
            text(
                "INSERT INTO campaign_attempts "
                "(organization_id, run_id, attempt_id, ordinal, case_id, case_content_hash, "
                "category, severity, attack_class, owasp_mappings, fixture_provenance) VALUES "
                "(:org, :run, :attempt, 0, 'case-prompt-injection', :case_hash, "
                "'prompt_injection', 'critical', 'regression', '[]'::jsonb, "
                "CAST(:fixture_provenance AS jsonb))"
            ),
            {
                "org": organization_id,
                "run": run_id,
                "attempt": attempt_id,
                "case_hash": "b" * 64,
                "fixture_provenance": json.dumps(
                    {
                        "classification": "synthetic",
                        "contains_real_phi": False,
                    }
                ),
            },
        )
        evidence = {
            "schema_version": "1",
            "campaign_run_id": run_id,
            "attempt_id": attempt_id,
            "campaign_id": run_id,
            "target_id": "copilot-live",
            "target_version": "2.0.0",
            "attack_attempt": {"case_ref": "case-prompt-injection"},
            "request_transcript": {"turns": ["synthetic fixture"]},
            "response_transcript": "synthetic canary observed",
            "policy_decision_id": "policy-decision-birdseye",
            "executed_at": "2026-07-23T18:00:10+00:00",
            "trace_id": "1" * 32,
            "correlation_id": run_id,
            "recorder_identity": "headshot-recorder",
            "recorder_version": "1",
            "organization_id": organization_id,
            "surface_id": "chat",
            "surface_version": "1.0.0",
            "authorization_scope_hash": scope_hash,
            "execution_profile": "live",
            "evidence_provenance": "live_target",
        }
        stored = ExecutionRecorder().record(evidence, connection)
        verdict_id = connection.execute(
            text(
                "INSERT INTO verdict "
                "(state, confidence, campaign_run_id, attempt_id, organization_id, "
                "confirmation_source, created_at) VALUES "
                "('EXPLOIT_CONFIRMED', 1, :run, :attempt, :org, 'oracle', "
                "TIMESTAMPTZ '2026-07-23 18:00:11+00') RETURNING id"
            ),
            {"run": run_id, "attempt": attempt_id, "org": organization_id},
        ).scalar_one()
        # A Judge row without integrity-verifiable attempt evidence must not inflate the
        # disposition projection.  Foreign-key enforcement is intentionally disabled for this
        # corruption fixture above; production writes cannot create this row.
        connection.execute(
            text(
                "INSERT INTO verdict "
                "(state, confidence, campaign_run_id, attempt_id, organization_id, "
                "confirmation_source, created_at) VALUES "
                "('EXPLOIT_CONFIRMED', 1, :run, 'birdseye-unverified-attempt', :org, "
                "'oracle', TIMESTAMPTZ '2026-07-23 18:00:12+00')"
            ),
            {"run": run_id, "org": organization_id},
        )
        connection.execute(
            text(
                "INSERT INTO finding "
                "(finding_id, organization_id, state, severity, category, target_version, "
                "source_kind, execution_profile, published) VALUES "
                "('finding-birdseye-outcome', :org, 'documented', 'critical', "
                "'prompt_injection', '2.0.0', 'campaign', 'live', false)"
            ),
            {"org": organization_id},
        )
        connection.execute(
            text(
                "INSERT INTO finding_evidence_links "
                "(organization_id, finding_id, campaign_run_id, attempt_id, "
                "evidence_content_hash, verdict_id, provenance) VALUES "
                "(:org, 'finding-birdseye-outcome', :run, :attempt, :hash, :verdict, "
                "'live_target')"
            ),
            {
                "org": organization_id,
                "run": run_id,
                "attempt": attempt_id,
                "hash": stored.content_hash,
                "verdict": verdict_id,
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_run_summaries "
                "(organization_id, run_id, execution_profile, provenance, attempt_count, "
                "request_count, confirmed_finding_count, measured_cost, currency, started_at, "
                "ended_at) VALUES (:org, :run, 'live', 'live_target', 1, 1, 1, 0.25, 'USD', "
                "TIMESTAMPTZ '2026-07-23 18:00:00+00', "
                "TIMESTAMPTZ '2026-07-23 18:00:30+00')"
            ),
            {"org": organization_id, "run": run_id},
        )
        connection.execute(
            text(
                "INSERT INTO outbound_http_requests "
                "(request_id, organization_id, campaign_run_id, attempt_id, trace_id, "
                "operation, provider, method, destination_host, relative_path, request_payload, "
                "response_payload, status, status_code, request_bytes, response_bytes, "
                "duration_ms, measured_cost, langfuse_status, started_at, finished_at) VALUES "
                "('birdseye-target-request', :org, :run, :attempt, :trace, "
                "'target.chat', 'openemr-live', 'POST', 'authorized.example', '/api/chat', "
                "'{}'::jsonb, '{}', 'succeeded', 200, 2, 2, 50, 0.25, 'queued', "
                "clock_timestamp() - INTERVAL '8 seconds', "
                "clock_timestamp() - INTERVAL '7 seconds')"
            ),
            {
                "org": organization_id,
                "run": run_id,
                "attempt": attempt_id,
                "trace": "f" * 32,
            },
        )
        orchestration = {
            "directive": {
                "category": "prompt_injection",
                "coverage_goal": "Validate the unresolved critical prompt-injection finding.",
            },
            "priority_reason": "unresolved_critical_finding",
        }
        connection.execute(
            text(
                "INSERT INTO audit_events "
                "(organization_id, event_type, aggregate_type, aggregate_id, payload) VALUES "
                "(:org, 'campaign.orchestrated', 'campaign_run', :run, CAST(:payload AS jsonb))"
            ),
            {
                "org": organization_id,
                "run": run_id,
                "payload": json.dumps(orchestration),
            },
        )
        for execution_id, parent, role, attempt, offset, duration_ms, cost in (
            ("birdseye-exec-orchestrator", None, "orchestrator", None, 1, 12, 0.0),
            (
                "birdseye-exec-red-team",
                "birdseye-exec-orchestrator",
                "red_team",
                None,
                2,
                120,
                0.02,
            ),
            (
                "birdseye-exec-judge",
                "birdseye-exec-red-team",
                "judge",
                attempt_id,
                3,
                8,
                0.0,
            ),
            (
                "birdseye-exec-documentation",
                "birdseye-exec-judge",
                "documentation",
                attempt_id,
                4,
                42,
                0.01,
            ),
        ):
            connection.execute(
                text(
                    "INSERT INTO agent_executions "
                    "(execution_id, organization_id, campaign_run_id, attempt_id, "
                    "parent_execution_id, agent_role, status, provider, model, execution_mode, "
                    "configuration_version, input_sha256, output_sha256, input_tokens, "
                    "output_tokens, measured_cost, cost_measurement_state, "
                    "trace_id, langfuse_status, langfuse_verified_at, detail, started_at, "
                    "finished_at, "
                    "duration_ms) VALUES "
                    "(:execution, :org, :run, :attempt, :parent, :role, 'succeeded', "
                    "'headshot', 'fixture-engine-v1', 'deterministic', 1, :input_hash, "
                    ":output_hash, :input_tokens, :output_tokens, :cost, 'measured', :trace, "
                    ":langfuse_status, CASE WHEN :langfuse_verified "
                    "THEN clock_timestamp() ELSE NULL END, "
                    '\'{"phase":"recorded_fixture"}\'::jsonb, '
                    "clock_timestamp() - (:offset + 2) * INTERVAL '1 second', "
                    "clock_timestamp() - (:offset + 1) * INTERVAL '1 second', :duration_ms)"
                ),
                {
                    "execution": execution_id,
                    "org": organization_id,
                    "run": run_id,
                    "attempt": attempt,
                    "parent": parent,
                    "role": role,
                    "input_hash": str(offset) * 64,
                    "output_hash": str(offset + 1) * 64,
                    "trace": str(offset) * 32,
                    "offset": offset,
                    "duration_ms": duration_ms,
                    "input_tokens": offset * 10,
                    "output_tokens": offset * 2,
                    "cost": cost,
                    "langfuse_status": "queued" if role == "orchestrator" else "exported",
                    "langfuse_verified": role != "orchestrator",
                },
            )
        connection.execute(
            text(
                "UPDATE agent_executions SET execution_mode = 'hosted_advisory', "
                "input_tokens = NULL, output_tokens = NULL "
                "WHERE execution_id = 'birdseye-exec-judge'"
            )
        )
        connection.execute(
            text(
                "UPDATE agent_executions SET provider = 'openrouter', "
                "model = 'openai/gpt-5.4', execution_mode = 'hosted_advisory', "
                "returned_model = 'openai/gpt-5.4', upstream_provider = 'OpenAI', "
                "provider_request_id = 'birdseye-provider-request-documentation' "
                "WHERE execution_id = 'birdseye-exec-documentation'"
            )
        )
        connection.execute(
            text(
                "INSERT INTO runtime_component_status "
                "(environment, component_id, name, kind, availability, detail, heartbeat_at) "
                "VALUES ('local', 'runner', 'Campaign runner', 'worker', "
                "'operational and evidenced', 'private runner heartbeat', clock_timestamp()), "
                "('local', 'langfuse', 'Langfuse tracing', 'telemetry', "
                "'operational and evidenced', 'authenticated export heartbeat', "
                "clock_timestamp()) ON CONFLICT (environment, component_id) DO UPDATE SET "
                "availability = EXCLUDED.availability, detail = EXCLUDED.detail, "
                "heartbeat_at = EXCLUDED.heartbeat_at"
            )
        )

    with migrated_db.connect() as connection:
        snapshot = build_birdseye_snapshot(
            connection,
            organization_id=organization_id,
            environment="local",
        )

    assert snapshot["campaign"]["target_name"] == "copilot-live"
    assert snapshot["security_posture"]["tested_categories"] == 1
    assert snapshot["security_posture"]["exploited_count"] == 1
    assert snapshot["security_posture"]["critical_open_finding_count"] == 1
    assert snapshot["security_posture"]["priority_source"] == "orchestrator_decision"
    assert snapshot["security_posture"]["cost_per_attempt_usd"] == 0.25
    assert snapshot["security_posture"]["cost_velocity_usd_per_minute"] == 0.5
    assert snapshot["instrumentation"]["measured_cost_usd"] == 0.25
    assert snapshot["instrumentation"]["budget_utilization"] == 0.05
    assert snapshot["instrumentation"]["confirmed_count"] == 1
    assert snapshot["instrumentation"]["likely_count"] == 0
    assert snapshot["instrumentation"]["review_count"] == 0
    assert snapshot["instrumentation"]["confirmed_finding_count"] == 1
    assert snapshot["instrumentation"]["system_state"] == "nominal"
    assert len(snapshot["category_outcomes"]) == 3
    assert len(snapshot["agent_activity"]) == 4
    assert snapshot["agent_activity"][2]["parent_execution_id"] == "birdseye-exec-red-team"
    assert snapshot["agent_activity"][2]["verdict_state"] == "EXPLOIT_CONFIRMED"
    nodes = {node["component_id"]: node for node in snapshot["nodes"]}
    assert nodes["agent:orchestrator"]["p50_latency_ms"] == 12.0
    assert nodes["agent:red_team"]["p95_latency_ms"] == 120.0
    assert nodes["agent:judge"]["measured_cost_usd"] == 0.0
    assert nodes["agent:judge"]["accounting_status"] == "unavailable"
    assert nodes["agent:documentation"]["measured_cost_usd"] == 0.01
    assert nodes["agent:documentation"]["accounting_status"] == "measured"
    assert nodes["agent:documentation"]["detail"] == "OpenAI/openai/gpt-5.4 · hosted_advisory"
    assert nodes["agent:documentation"]["execution_count"] == 1
    assert nodes["agent:documentation"]["input_tokens"] == 40
    assert nodes["agent:documentation"]["output_tokens"] == 8
    assert nodes["agent:documentation"]["token_observation_count"] == 1
    assert nodes["agent:documentation"]["langfuse_queued_count"] == 0
    assert nodes["agent:documentation"]["langfuse_exported_count"] == 1
    assert nodes["agent:documentation"]["langfuse_verified_count"] == 1
    assert nodes["agent:documentation"]["last_langfuse_verified_at"] is not None
    assert nodes["agent:orchestrator"]["langfuse_queued_count"] == 1
    assert nodes["agent:orchestrator"]["langfuse_exported_count"] == 0
    assert nodes["agent:orchestrator"]["langfuse_verified_count"] == 0
    assert nodes["agent:orchestrator"]["last_langfuse_verified_at"] is None
    assert nodes["agent:documentation"]["langfuse_status"] == "exported"
    assert nodes["langfuse"]["queue_depth"] == 2
    edges = {edge["edge_id"]: edge for edge in snapshot["edges"]}
    assert edges["runner-to-langfuse"]["state"] == "active"

    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE agent_executions SET langfuse_status = 'exported', "
                "langfuse_verified_at = clock_timestamp() "
                "WHERE organization_id = :org AND campaign_run_id = :run"
            ),
            {"org": organization_id, "run": run_id},
        )
    with migrated_db.connect() as connection:
        request_pending_snapshot = build_birdseye_snapshot(
            connection,
            organization_id=organization_id,
            environment="local",
        )
    request_pending_edges = {edge["edge_id"]: edge for edge in request_pending_snapshot["edges"]}
    request_pending_nodes = {
        node["component_id"]: node for node in request_pending_snapshot["nodes"]
    }
    assert request_pending_edges["runner-to-langfuse"]["state"] == "active"
    assert (
        "4 remotely verified; 1 awaiting exact query-back"
        in request_pending_edges["runner-to-langfuse"]["detail"]
    )
    assert request_pending_nodes["langfuse"]["current_task"].startswith(
        "Awaiting exact remote verification"
    )

    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE outbound_http_requests SET langfuse_status = 'exported', "
                "langfuse_verified_at = clock_timestamp() "
                "WHERE organization_id = :org AND campaign_run_id = :run"
            ),
            {"org": organization_id, "run": run_id},
        )
    with migrated_db.connect() as connection:
        verified_snapshot = build_birdseye_snapshot(
            connection,
            organization_id=organization_id,
            environment="local",
        )
    verified_edges = {edge["edge_id"]: edge for edge in verified_snapshot["edges"]}
    verified_nodes = {node["component_id"]: node for node in verified_snapshot["nodes"]}
    assert verified_edges["runner-to-langfuse"]["state"] == "complete"
    assert (
        "5 remotely verified; 0 awaiting exact query-back"
        in verified_edges["runner-to-langfuse"]["detail"]
    )
    assert verified_nodes["langfuse"]["current_task"].startswith("Remote query-back verified")


def test_birdseye_never_presents_a_substituted_model_as_the_agent_identity(
    migrated_db: Engine,
) -> None:
    """A served model that is not the requested one must not stand alone as fleet identity.

    Rendered by itself it reads exactly like a normal call, so the system map would show the
    provider's claim as though it were the authorized model.
    """

    organization_id = "org_BirdseyeSubstitution"
    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO agent_executions "
                "(execution_id, organization_id, campaign_run_id, agent_role, status, provider, "
                "model, execution_mode, configuration_version, input_sha256, output_sha256, "
                "returned_model, upstream_provider, provider_request_id, input_tokens, "
                "output_tokens, reasoning_tokens, physical_attempts, configuration_set_sha256, "
                "role_configuration_sha256, generation_policy_sha256, measured_cost, "
                "cost_measurement_state, trace_id, detail, started_at, finished_at, duration_ms, "
                "error_code) VALUES "
                "('birdseye-substituted', :org, 'run-substituted', 'red_team', 'failed', "
                "'openrouter', 'qwen/qwen3.5-397b-a17b', 'hosted_advisory', 1, repeat('a',64), "
                "repeat('b',64), 'openai/gpt-5.4', 'OpenAI', 'req-substituted', 100, 20, 5, 1, "
                "repeat('c',64), repeat('d',64), repeat('e',64), 0.01, 'measured', "
                "repeat('f',32), '{}'::jsonb, clock_timestamp(), clock_timestamp(), 10, "
                "'provider-model-substituted')"
            ),
            {"org": organization_id},
        )

    with migrated_db.connect() as connection:
        snapshot = build_birdseye_snapshot(
            connection,
            organization_id=organization_id,
            environment="local",
        )

    node = next(item for item in snapshot["nodes"] if item["component_id"] == "agent:red_team")
    # Both identities are present and the divergence is named, not implied.
    assert "qwen/qwen3.5-397b-a17b" in node["detail"]
    assert "openai/gpt-5.4" in node["detail"]
    assert "substituted" in node["detail"]
