"""The traced Red Team generation must always terminalize, and never lie about what it cost.

Every test here drives the REAL stack end to end: a real :class:`OpenRouterTransport` over
``httpx.MockTransport`` (so the provider bytes are the provider's), the real
:class:`TracedHostedRedTeamProvider`, the real ``_DurableHostedExecutionLifecycle`` from
``runner.py``, a real :class:`ControlPlaneStore`, and a real Alembic-migrated PostgreSQL. Nothing
is asserted against what a double recorded — the assertions read the ``agent_executions`` row and
the ``audit_events`` rows the run actually wrote.

That is deliberate. Two earlier rounds of this work went green against a hand-written fake
lifecycle and shipped dead code: round 1's fix was unreachable because the real transport never
reaches the state the stand-in was monkeypatched into, and round 6's fallback never executed at
all because the real ``runner.finish`` popped its execution context before the store write while
the stand-in did not. The only test that can distinguish a working fix from those is one that runs
the real components.

The single legitimate stand-in is the network itself: ``httpx.MockTransport`` supplies the bytes a
remote model would. Everything downstream of the socket is production code.
"""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, text

from agentforge.agents.hosted import HostedConfigurationSet
from agentforge.agents.hosted_runtime import HostedCallBounds
from agentforge.agents.judge.calibration_runtime import JudgeCalibrationStatus
from agentforge.agents.prompts import load_prompt_registry
from agentforge.agents.red_team.hosted_generation import (
    RedTeamRoleIdentity,
    TracedHostedRedTeamProvider,
    TracedRedTeamGenerationError,
)
from agentforge.agents.red_team.providers import REFUSAL_SENTINEL, ProviderExhaustedError
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.providers.openrouter import (
    HostedProviderError,
    HostedProviderResponseError,
    OpenRouterTransport,
)
from agentforge.runner import _DurableHostedExecutionLifecycle
from agentforge.secrets import Secret
from agentforge.telemetry import OutboundHttpTelemetry
from test_hosted_agent_execution_lineage import (
    _GENERATION_POLICY,
    _MODELS,
    _authorized_run,
    _LangfuseProjection,
)

# A credential-shaped continuation. Producing exactly this is the Red Team agent's job, so the
# store's credential screening firing on it is honest, in-contract model output — not an error.
_CREDENTIAL_VARIANT = "Replay this: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9wwwwwwww"
# Serializes past the store's 256 KiB output bound while remaining schema-valid.
_OVERSIZED_VARIANT = "A" * 300_000

_SEED = {
    "case_ref": "AF-M11-PI-001",
    "input_sequence": ["Summarize the chart for patient 12."],
}


def _calibration() -> JudgeCalibrationStatus:
    """A non-Judge run carries no calibration artifact; the lifecycle requires the status object."""

    return JudgeCalibrationStatus(
        state="unavailable",
        calibration_id=None,
        metrics=None,
        reason_codes=(),
        model_authoritative=False,
        source="absent",
    )


def _provider_response(content: str, *, request_id: str = "gen-red-team-1") -> httpx.Response:
    """A well-formed OpenRouter chat completion whose message content is supplied verbatim.

    ``content`` is passed through as raw bytes rather than being built from a dict, so a response
    body carrying a duplicate JSON key reaches the transport exactly as a provider would send it.
    """

    return httpx.Response(
        200,
        json={
            "id": request_id,
            "model": _MODELS["red_team"],
            "openrouter_metadata": {
                "requested": _MODELS["red_team"],
                "endpoints": {
                    "available": [
                        {
                            "provider": "Together",
                            "model": _MODELS["red_team"],
                            "selected": True,
                        }
                    ]
                },
            },
            "choices": [{"message": {"content": content}}],
            "usage": {
                "prompt_tokens": 412,
                "completion_tokens": 96,
                "completion_tokens_details": {"reasoning_tokens": 16},
                "cost": 0.0007125,
            },
        },
    )


def _variants_content(*variants: str) -> str:
    return json.dumps({"variants": list(variants)})


def _traced_provider(
    engine: Engine,
    store: ControlPlaneStore,
    run_id: str,
    configuration: HostedConfigurationSet,
    handler: Any,
) -> tuple[TracedHostedRedTeamProvider, _DurableHostedExecutionLifecycle]:
    """Wire the real transport, the real lifecycle, and the real traced provider together."""

    role = next(item for item in configuration.roles if item.role == "red_team")
    prompt = next(item for item in load_prompt_registry() if item.role == "red_team")
    telemetry = OutboundHttpTelemetry(engine, environment="staging")
    # Langfuse is a remote service, so its client stands in for the same reason the network does.
    # Everything from the lifecycle down — store, durable telemetry rows, database — is real.
    telemetry.langfuse = _LangfuseProjection()  # type: ignore[assignment]
    lifecycle = _DurableHostedExecutionLifecycle(
        store=store,
        telemetry=telemetry,
        run_id=run_id,
        calibration=_calibration(),
    )
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        lineage_recorder=store,
    )
    provider = TracedHostedRedTeamProvider(
        transport=transport,
        lifecycle=lifecycle,
        role_identity=RedTeamRoleIdentity(
            provider=role.provider,
            model=role.model_id,
            upstream_provider=role.upstream_provider,
            prompt_version=prompt.version,
            prompt_sha256=prompt.sha256,
            role_configuration_sha256=role.configuration_sha256,
        ),
        configuration_sha256=configuration.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY,
        call_bounds=HostedCallBounds(
            input_tokens=8_000,
            output_tokens=4_000,
            reasoning_tokens=4_000,
            timeout_seconds=30.0,
        ),
    )
    return provider, lifecycle


def _execution_row(engine: Engine) -> dict[str, Any]:
    with engine.connect() as connection:
        return dict(
            connection.execute(
                text(
                    "SELECT execution_id, status, error_code, returned_model, upstream_provider, "
                    "provider_request_id, input_tokens, output_tokens, reasoning_tokens, "
                    "physical_attempts, measured_cost, cost_measurement_state, finished_at "
                    "FROM agent_executions WHERE agent_role = 'red_team'"
                )
            )
            .mappings()
            .one()
        )


def _audit_event_types(engine: Engine, execution_id: str) -> list[str]:
    with engine.connect() as connection:
        return [
            row["event_type"]
            for row in connection.execute(
                text(
                    "SELECT event_type FROM audit_events WHERE aggregate_type = 'agent_execution' "
                    "AND aggregate_id = :execution ORDER BY cursor"
                ),
                {"execution": execution_id},
            ).mappings()
        ]


def _generate(
    engine: Engine,
    content: str,
    *,
    count: int = 1,
    raises: type[BaseException] = TracedRedTeamGenerationError,
) -> dict[str, Any]:
    """Run one traced generation against a provider that returns ``content``; return the row."""

    store, run_id, configuration = _authorized_run(engine)
    provider, lifecycle = _traced_provider(
        engine,
        store,
        run_id,
        configuration,
        lambda _request: _provider_response(content),
    )
    with lifecycle.invocation(role="red_team"), pytest.raises(raises):
        provider.generate(dict(_SEED), count=count, category="prompt_injection")
    return _execution_row(engine)


def test_credential_bearing_generation_terminalizes_with_both_audit_events(
    migrated_db: Engine,
) -> None:
    """A Red Team payload the store refuses as output must still close its own execution.

    The store screens agent output for credential material, and generating credential-exfiltration
    payloads is precisely this agent's job. Before the fallback existed, the refused success write
    left the row `running` with `agent.started` as its only audit event and no way to close it —
    the platform disabled its fourth agent the first time the model produced a credible payload.
    """

    row = _generate(migrated_db, _variants_content(_CREDENTIAL_VARIANT))

    assert row["status"] == "failed"
    assert row["finished_at"] is not None
    assert row["error_code"] == "red-team-terminal-record-refused"
    assert _audit_event_types(migrated_db, row["execution_id"]) == [
        "agent.started",
        "agent.failed",
    ]


def test_oversized_generation_terminalizes_with_both_audit_events(
    migrated_db: Engine,
) -> None:
    """The same refusal reached through the store's 256 KiB output bound, not its screening."""

    row = _generate(migrated_db, _variants_content(_OVERSIZED_VARIANT))

    assert row["status"] == "failed"
    assert row["finished_at"] is not None
    assert row["error_code"] == "red-team-terminal-record-refused"
    assert _audit_event_types(migrated_db, row["execution_id"]) == [
        "agent.started",
        "agent.failed",
    ]


def test_refused_generation_records_the_cost_it_actually_incurred(
    migrated_db: Engine,
) -> None:
    """A refused output does not make the call free — the qwen generation was made and billed.

    The observation survives the refusal: the terminal record keeps the served identity, the token
    counts, the physical attempt and the exact measured amount, so the run's spend is not
    understated by the size of every payload the store declined to store.
    """

    row = _generate(migrated_db, _variants_content(_CREDENTIAL_VARIANT))

    assert row["cost_measurement_state"] == "measured"
    assert Decimal(str(row["measured_cost"])) == Decimal("0.0007125")
    assert row["returned_model"] == _MODELS["red_team"]
    assert row["provider_request_id"] == "gen-red-team-1"
    assert row["input_tokens"] == 412
    assert row["output_tokens"] == 80
    assert row["reasoning_tokens"] == 16
    assert row["physical_attempts"] == 1


def test_short_generation_records_the_cost_it_actually_incurred(
    migrated_db: Engine,
) -> None:
    """An exhausted generation already terminalized — but claimed the billed call cost nothing.

    The output schema pins EXACTLY `count` entries, so a genuinely short generation arrives as the
    right number of schema-valid strings of which too few are usable: a model that declines one of
    the two requested continuations returns the refusal sentinel, which `_collect_usable` skips.
    The row closed correctly, and then recorded `not_observed` — the state that asserts NO provider
    call was made, for a call that was made, billed, and whose request id was in hand.
    """

    store, run_id, configuration = _authorized_run(migrated_db)
    provider, lifecycle = _traced_provider(
        migrated_db,
        store,
        run_id,
        configuration,
        lambda _request: _provider_response(_variants_content("probe one", REFUSAL_SENTINEL)),
    )
    with lifecycle.invocation(role="red_team"), pytest.raises(ProviderExhaustedError):
        provider.generate(dict(_SEED), count=2, category="prompt_injection")

    row = _execution_row(migrated_db)
    assert row["status"] == "failed"
    assert row["cost_measurement_state"] == "measured"
    assert Decimal(str(row["measured_cost"])) == Decimal("0.0007125")
    assert row["physical_attempts"] == 1


def test_duplicate_json_key_response_is_refused_and_terminalizes(
    migrated_db: Engine,
) -> None:
    """Validation and persistence must not disagree about what the model actually said.

    A repeated key passes schema validation on the FIRST value while `json.loads` keeps the LAST,
    so the payload that is screened, hashed and stored is not the payload that was validated. A
    benign first `variants` and a credential-bearing second one is a smuggling channel through an
    untrusted generator's own output. Reject the ambiguity at the wire instead, and terminalize.
    """

    row = _generate(
        migrated_db,
        f'{{"variants": ["benign probe"], "variants": ["{_CREDENTIAL_VARIANT}"]}}',
        # Refused at the wire now, so the caller sees the provider's own typed refusal rather than
        # the store's credential screening firing on a payload that was never validated.
        raises=HostedProviderResponseError,
    )

    assert row["status"] == "failed"
    assert row["finished_at"] is not None
    assert _audit_event_types(migrated_db, row["execution_id"]) == [
        "agent.started",
        "agent.failed",
    ]
    # The duplicate-key response was still a real, billed call.
    assert row["cost_measurement_state"] == "measured"
    assert Decimal(str(row["measured_cost"])) == Decimal("0.0007125")


def test_dispatched_unbilled_500_records_not_observed_with_one_physical_attempt(
    migrated_db: Engine,
) -> None:
    """A dispatched call that 500s unbilled is neither free nor never-made (the fix-3 path).

    This path was deleted in the terminalization reconcile and left uncovered. A 500 is
    non-retryable, so exactly one physical attempt is dispatched and the transport records it as
    `not_observed` (the upstream carried no usage or cost). The terminal record must therefore keep
    `physical_attempts == 1` — a dispatched call is NEVER recorded as never-made — while cost stays
    honestly `not_observed`. That distinguishes it from `test_no_physical_attempt...`, where NO call
    was dispatched and `physical_attempts` is 0/None. Conflating the two would either understate
    spend risk (a made call read as never-made) or overstate it.
    """

    store, run_id, configuration = _authorized_run(migrated_db)
    provider, lifecycle = _traced_provider(
        migrated_db,
        store,
        run_id,
        configuration,
        lambda _request: httpx.Response(500, json={"error": {"message": "upstream failure"}}),
    )
    with (
        lifecycle.invocation(role="red_team"),
        pytest.raises((TracedRedTeamGenerationError, HostedProviderError)),
    ):
        provider.generate(dict(_SEED), count=1, category="prompt_injection")

    row = _execution_row(migrated_db)
    assert row["status"] == "failed"
    assert row["cost_measurement_state"] == "not_observed"
    assert row["measured_cost"] is None
    # The call WAS dispatched — the unbilled 500 must not erase the physical attempt.
    assert row["physical_attempts"] == 1


def test_no_physical_attempt_still_records_not_observed(
    migrated_db: Engine,
) -> None:
    """The honest `not_observed` case must survive: a failure before any call was dispatched."""

    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = store.start_hosted_agent_execution(
        run_id=run_id,
        agent_role="red_team",
        input_payload={"generation": {"category": "prompt_injection", "count": 1}},
        provider="openrouter",
        model=_MODELS["red_team"],
        upstream_provider="together",
        configuration_set_sha256=configuration.configuration_sha256,
        role_configuration_sha256=next(
            item for item in configuration.roles if item.role == "red_team"
        ).configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY,
        judge_calibration_id=None,
        judge_calibration_state=None,
        detail={"input_kind": "sanitized_hash_summary"},
    )
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="failed",
        output_payload={"status": "failed"},
        error_code="red-team-generation-failed",
    )

    row = _execution_row(migrated_db)
    assert row["cost_measurement_state"] == "not_observed"
    assert row["measured_cost"] is None
