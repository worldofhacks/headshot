"""What the provider actually said, kept once, bounded, redacted, and never invented.

Three layers are exercised with as little pretence as possible:

* the contract (:class:`ProviderTerminalEventV1`) directly, because it is the only thing standing
  between a producer's mistake and a durable row that lies about its own integrity;
* the real :class:`OpenRouterTransport` over ``httpx.MockTransport``, so the recorded bytes are the
  bytes a provider put on the wire rather than a string a test invented downstream of the socket;
* the real :class:`ControlPlaneStore` against a real Alembic-migrated PostgreSQL, because the
  append-only INSERT, its CHECK constraints, and the crash-recovery path are the durability claim.

The single stand-in is the network itself.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from collections.abc import Iterator
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import Engine, text

import _db
from agentforge.agents.hosted import HostedConfigurationSet
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.providers.lineage import (
    MAX_PROVIDER_RESPONSE_BYTES,
    ProviderTerminalEventV1,
    capture_response_evidence,
)
from agentforge.providers.openrouter import HostedProviderError, OpenRouterTransport
from agentforge.secrets import Secret
from test_hosted_agent_execution_lineage import (
    _PROMPTS,
    _SELECTED_PROVIDER,
    _authorized_run,
    _start,
)
from test_openrouter_transport import (
    _configuration,
    _digest,
    _messages,
    _provider_context,
    _ProviderRecorder,
)

# Matched by no pattern in the shared redaction helper. Only the literal bearer value this exact
# call sent can remove it, so its absence proves the credential itself is passed as a redaction
# rather than the transport merely relying on secret-shaped heuristics.
_OPAQUE_CREDENTIAL = "northwind-transport-value-9182"


def _success_payload(*, extra_metadata: str | None = None) -> dict[str, object]:
    metadata: dict[str, object] = {
        "requested": "google/gemini-2.5-pro",
        "endpoints": {
            "available": [
                {
                    "provider": "Google",
                    "model": "google/gemini-2.5-pro",
                    "selected": True,
                }
            ]
        },
    }
    if extra_metadata is not None:
        metadata["additive_future_field"] = extra_metadata
    return {
        "id": "gen-evidence-1",
        "model": "google/gemini-2.5-pro",
        "openrouter_metadata": metadata,
        "choices": [{"message": {"content": '{"verdict":"NO_EXPLOIT_OBSERVED"}'}}],
        "usage": {
            "prompt_tokens": 30,
            "completion_tokens": 10,
            "completion_tokens_details": {"reasoning_tokens": 5},
            "cost": 0.000065,
        },
    }


def _run_judge(
    handler,
    *,
    credential: str = "test-provider-value",
) -> _ProviderRecorder:
    """Drive one real judge call through the real transport and return its lineage recorder."""

    configuration = _configuration()
    recorder = _ProviderRecorder()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret(credential),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        lineage_recorder=recorder,
        sleeper=lambda _seconds: None,
        monotonic=lambda: 0.0,
    )
    transport.invoke(
        role="judge",
        messages=_messages(),
        output_schema={"type": "object"},
        schema_name="judge_verdict",
        generation_policy_sha256=_digest("generation-policy"),
        input_tokens_upper_bound=100,
        max_output_tokens=50,
        max_reasoning_tokens=20,
        timeout_seconds=5,
        provider_context=_provider_context(configuration),
    )
    return recorder


def _terminal_event(**overrides: object) -> ProviderTerminalEventV1:
    """A minimal valid non-success terminal event, so only the response fields are under test."""

    fields: dict[str, object] = {
        "invocation_id": _digest("invocation-under-test"),
        "physical_sequence": 1,
        "status": "timeout",
        "returned_model": None,
        "upstream_provider": None,
        "provider_request_id": None,
        "input_tokens": None,
        "output_tokens": None,
        "reasoning_tokens": None,
        "cost_measurement_state": "not_observed",
        "measured_cost_usd": None,
        "error_code": "provider_timeout",
        "finished_at": datetime.datetime.now(datetime.UTC),
    }
    fields.update(overrides)
    return ProviderTerminalEventV1(**fields)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------------
# The migration
# --------------------------------------------------------------------------------------------


@pytest.fixture
def response_evidence_revision_db() -> Iterator[str]:
    admin = _db.admin_url()
    database = f"agentforge_response_evidence_{uuid.uuid4().hex[:12]}"
    base, _ = _db.split_db(admin)
    url = f"{base}/{database}"
    _db.create_fresh_database(admin, database)
    try:
        _db.alembic_upgrade(url, "0027")
        yield url
    finally:
        _db.drop_database(admin, database)


def _response_columns(url: str) -> set[str]:
    engine = _db.build_engine(url)
    try:
        with engine.connect() as connection:
            return {
                str(row[0])
                for row in connection.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = 'provider_call_events' "
                        "AND column_name LIKE 'response%'"
                    )
                )
            }
    finally:
        engine.dispose()


def test_0028_is_expand_only_and_round_trips(response_evidence_revision_db: str) -> None:
    url = response_evidence_revision_db
    assert _response_columns(url) == set()

    _db.alembic_upgrade(url, "0028")
    assert _response_columns(url) == {
        "response_text",
        "response_truncated",
        "response_sha256",
    }
    engine = _db.build_engine(url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0028"
            )
            # Physical names carry the repo-wide ``ck_<table>_`` naming convention, exactly as the
            # constraints revision 0018 declared on this same table do.
            constraints = {
                str(row[0])
                for row in connection.execute(
                    text(
                        "SELECT conname FROM pg_constraint "
                        "WHERE conrelid = 'provider_call_events'::regclass "
                        "AND contype = 'c' AND conname LIKE '%response%'"
                    )
                )
            }
    finally:
        engine.dispose()
    assert constraints == {
        "ck_provider_call_events_provider_event_response_bounded",
        "ck_provider_call_events_provider_event_response_sha256_shape",
        "ck_provider_call_events_provider_event_response_digest_paired",
    }

    _db.alembic_downgrade(url, "0027")
    assert _response_columns(url) == set()
    _db.alembic_upgrade(url, "0028")
    assert len(_response_columns(url)) == 3


# --------------------------------------------------------------------------------------------
# The contract
# --------------------------------------------------------------------------------------------


def test_digest_covers_exactly_the_recorded_text() -> None:
    body = '{"choices":[{"message":{"content":"held"}}]}'

    response_text, truncated, digest = capture_response_evidence(body)

    assert response_text == body
    assert truncated is False
    assert digest == hashlib.sha256(body.encode("utf-8")).hexdigest()
    event = _terminal_event(
        response_text=response_text,
        response_truncated=truncated,
        response_sha256=digest,
    )
    assert event.response_text == body
    assert event.response_sha256 == digest


def test_truncation_sets_the_flag_and_hashes_only_the_kept_bytes() -> None:
    body = "x" * (MAX_PROVIDER_RESPONSE_BYTES + 4_096)

    response_text, truncated, digest = capture_response_evidence(body)

    assert truncated is True
    assert response_text is not None
    kept = response_text.encode("utf-8")
    assert len(kept) == MAX_PROVIDER_RESPONSE_BYTES
    # The digest must describe what was stored, not what was seen. A digest of the full body would
    # be worse than none: it would look like integrity while failing to verify the stored row.
    assert digest == hashlib.sha256(kept).hexdigest()
    assert digest != hashlib.sha256(body.encode("utf-8")).hexdigest()
    _terminal_event(
        response_text=response_text,
        response_truncated=truncated,
        response_sha256=digest,
    )


def test_truncation_cuts_on_a_character_boundary_so_the_digest_still_verifies() -> None:
    # A 3-byte character straddling the bound: a naive byte cut would leave text that cannot be
    # re-encoded to the digested bytes.
    body = "a" * (MAX_PROVIDER_RESPONSE_BYTES - 1) + "€€"

    response_text, truncated, digest = capture_response_evidence(body)

    assert truncated is True
    assert response_text is not None
    kept = response_text.encode("utf-8")
    assert len(kept) == MAX_PROVIDER_RESPONSE_BYTES - 1
    assert digest == hashlib.sha256(kept).hexdigest()
    assert response_text == body[: MAX_PROVIDER_RESPONSE_BYTES - 1]


def test_absent_response_carries_no_digest_and_no_truncation_claim() -> None:
    assert capture_response_evidence(None) == (None, False, None)
    assert capture_response_evidence(b"bytes are not text") == (None, False, None)

    event = _terminal_event()
    assert event.response_text is None
    assert event.response_sha256 is None
    assert event.response_truncated is False

    with pytest.raises(ValueError, match="unobserved response cannot carry a digest"):
        _terminal_event(response_sha256="a" * 64)
    with pytest.raises(ValueError, match="unobserved response cannot be truncated"):
        _terminal_event(response_truncated=True)


def test_recorded_text_without_a_matching_digest_is_refused() -> None:
    body = "held"
    with pytest.raises(ValueError, match="must digest the exact recorded response text"):
        _terminal_event(response_text=body, response_sha256=None)
    with pytest.raises(ValueError, match="must digest the exact recorded response text"):
        _terminal_event(response_text=body, response_sha256="0" * 64)
    with pytest.raises(ValueError, match="must digest the exact recorded response text"):
        _terminal_event(
            response_text=body,
            response_sha256=hashlib.sha256(b"something else").hexdigest(),
        )


def test_oversized_text_is_refused_rather_than_silently_shortened() -> None:
    body = "x" * (MAX_PROVIDER_RESPONSE_BYTES + 1)
    with pytest.raises(ValueError, match="truncate before hashing"):
        _terminal_event(
            response_text=body,
            response_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
        )


def test_truncation_flag_must_be_a_boolean() -> None:
    with pytest.raises(ValueError, match="response_truncated must be a boolean"):
        _terminal_event(response_truncated=1)


# --------------------------------------------------------------------------------------------
# The real transport
# --------------------------------------------------------------------------------------------


def test_transport_records_the_exact_provider_bytes_for_the_physical_call() -> None:
    sent: list[str] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        response = httpx.Response(200, json=_success_payload())
        sent.append(response.text)
        return response

    recorder = _run_judge(handler)

    event = recorder.events[0]
    assert event.status == "succeeded"
    assert event.response_text == sent[0]
    assert event.response_truncated is False
    assert event.response_sha256 == hashlib.sha256(sent[0].encode("utf-8")).hexdigest()


def test_transport_redacts_the_call_credential_out_of_recorded_bytes() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_success_payload(
                extra_metadata=(
                    f"upstream echoed key={_OPAQUE_CREDENTIAL} "
                    "and Authorization: Bearer abcdefghijklmnopqrstuvwx"
                )
            ),
        )

    recorder = _run_judge(handler, credential=_OPAQUE_CREDENTIAL)

    recorded = recorder.events[0].response_text
    assert recorded is not None
    assert _OPAQUE_CREDENTIAL not in recorded
    assert "abcdefghijklmnopqrstuvwx" not in recorded
    assert "REDACTED" in recorded
    # Redaction happens before hashing, so the digest still describes the stored bytes.
    assert (
        recorder.events[0].response_sha256 == hashlib.sha256(recorded.encode("utf-8")).hexdigest()
    )


def test_transport_truncates_an_oversized_provider_body() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_success_payload(extra_metadata="y" * (MAX_PROVIDER_RESPONSE_BYTES + 1_024)),
        )

    recorder = _run_judge(handler)

    event = recorder.events[0]
    assert event.status == "succeeded"
    assert event.response_truncated is True
    assert event.response_text is not None
    kept = event.response_text.encode("utf-8")
    assert len(kept) <= MAX_PROVIDER_RESPONSE_BYTES
    assert event.response_sha256 == hashlib.sha256(kept).hexdigest()


def test_transport_records_the_body_that_failed_structured_output_validation() -> None:
    payload = _success_payload()
    payload["choices"] = [{"message": {"content": '{"verdict": 12345}'}}]
    sent: list[str] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        response = httpx.Response(200, json=payload)
        sent.append(response.text)
        return response

    configuration = _configuration()
    recorder = _ProviderRecorder()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        lineage_recorder=recorder,
        sleeper=lambda _seconds: None,
        monotonic=lambda: 0.0,
    )
    with pytest.raises(HostedProviderError):
        transport.invoke(
            role="judge",
            messages=_messages(),
            output_schema={
                "type": "object",
                "properties": {"verdict": {"type": "string"}},
                "required": ["verdict"],
                "additionalProperties": False,
            },
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    # The rejected body is precisely the one an operator needs to read. Every attempt keeps its own.
    assert [item.status for item in recorder.events] == ["invalid_output", "invalid_output"]
    assert [item.response_text for item in recorder.events] == sent
    assert json.loads(sent[0])["choices"][0]["message"]["content"] == '{"verdict": 12345}'


def test_a_call_that_never_returned_records_no_response_at_all() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("synthetic provider timeout", request=request)

    configuration = _configuration()
    recorder = _ProviderRecorder()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        lineage_recorder=recorder,
        sleeper=lambda _seconds: None,
        monotonic=lambda: 0.0,
    )
    with pytest.raises(HostedProviderError):
        transport.invoke(
            role="judge",
            messages=_messages(),
            output_schema={"type": "object"},
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    assert recorder.events
    assert [item.status for item in recorder.events] == ["timeout", "timeout"]
    for event in recorder.events:
        assert event.response_text is None
        assert event.response_sha256 is None
        assert event.response_truncated is False


def test_one_attempts_body_never_bleeds_into_the_next_physical_call() -> None:
    sent: list[str] = []
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            response = httpx.Response(200, json=_success_payload())
            sent.append(response.text)
            return response
        raise httpx.ReadTimeout("synthetic provider timeout", request=request)

    payload = _success_payload()
    payload["choices"] = [{"message": {"content": '{"verdict": 12345}'}}]

    def first_invalid_then_timeout(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            response = httpx.Response(200, json=payload)
            sent.append(response.text)
            return response
        raise httpx.ReadTimeout("synthetic provider timeout", request=request)

    configuration = _configuration()
    recorder = _ProviderRecorder()
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("test-provider-value"),
        client=httpx.Client(transport=httpx.MockTransport(first_invalid_then_timeout)),
        lineage_recorder=recorder,
        sleeper=lambda _seconds: None,
        monotonic=lambda: 0.0,
    )
    with pytest.raises(HostedProviderError):
        transport.invoke(
            role="judge",
            messages=_messages(),
            output_schema={
                "type": "object",
                "properties": {"verdict": {"type": "string"}},
                "required": ["verdict"],
                "additionalProperties": False,
            },
            schema_name="judge_verdict",
            generation_policy_sha256=_digest("generation-policy"),
            input_tokens_upper_bound=100,
            max_output_tokens=50,
            max_reasoning_tokens=20,
            timeout_seconds=5,
            provider_context=_provider_context(configuration),
        )

    assert [item.status for item in recorder.events] == ["invalid_output", "timeout"]
    assert recorder.events[0].response_text == sent[0]
    assert recorder.events[1].response_text is None
    assert recorder.events[1].response_sha256 is None


# --------------------------------------------------------------------------------------------
# The real store
# --------------------------------------------------------------------------------------------


def _documentation_invocation(
    store: ControlPlaneStore,
    run_id: str,
    configuration: HostedConfigurationSet,
) -> tuple[str, object]:
    """One open physical attempt on a non-Judge role, so no calibration lineage is in play."""

    execution_id = _start(store, run_id, configuration, role="documentation")
    prompt = _PROMPTS["documentation"]
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    return execution_id, store.begin_physical_attempt(logical, 1)


def _succeeded_event(invocation, **response_fields: object) -> ProviderTerminalEventV1:
    return ProviderTerminalEventV1(
        invocation_id=invocation.invocation_id,
        physical_sequence=invocation.physical_sequence,
        status="succeeded",
        returned_model=invocation.requested_model,
        upstream_provider=_SELECTED_PROVIDER["documentation"],
        provider_request_id="gen-evidence-store-1",
        input_tokens=30,
        output_tokens=5,
        reasoning_tokens=5,
        cost_measurement_state="measured",
        measured_cost_usd=Decimal("0.000065"),
        error_code=None,
        finished_at=datetime.datetime.now(datetime.UTC),
        **response_fields,  # type: ignore[arg-type]
    )


def _stored_response(engine: Engine, invocation_id: str) -> tuple[str | None, bool, str | None]:
    with engine.connect() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT response_text, response_truncated, response_sha256 "
                    "FROM provider_call_events WHERE invocation_id = :invocation"
                ),
                {"invocation": invocation_id},
            )
            .mappings()
            .one()
        )
    return row["response_text"], row["response_truncated"], row["response_sha256"]


def test_settlement_insert_persists_the_response_and_its_digest(migrated_db: Engine) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    _execution_id, invocation = _documentation_invocation(store, run_id, configuration)
    body = json.dumps(_success_payload())
    response_text, truncated, digest = capture_response_evidence(body)

    store.finish_physical_attempt(
        invocation,
        _succeeded_event(
            invocation,
            response_text=response_text,
            response_truncated=truncated,
            response_sha256=digest,
        ),
    )

    stored_text, stored_truncated, stored_digest = _stored_response(
        migrated_db,
        invocation.invocation_id,
    )
    assert stored_text == body
    assert stored_truncated is False
    assert stored_digest == hashlib.sha256(body.encode("utf-8")).hexdigest()


def test_replaying_the_same_terminal_event_still_matches_the_durable_row(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    _execution_id, invocation = _documentation_invocation(store, run_id, configuration)
    response_text, truncated, digest = capture_response_evidence("held provider bytes")
    event = _succeeded_event(
        invocation,
        response_text=response_text,
        response_truncated=truncated,
        response_sha256=digest,
    )

    store.finish_physical_attempt(invocation, event)

    # The idempotent replay rebuilds the event from the row and compares the whole thing. If the
    # response columns were not read back, the second call would report "different terminal facts".
    replayed = store.finish_physical_attempt(invocation, event)
    assert replayed == event
    assert replayed.response_text == "held provider bytes"


def test_truncated_evidence_survives_the_bounded_column(migrated_db: Engine) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    _execution_id, invocation = _documentation_invocation(store, run_id, configuration)
    response_text, truncated, digest = capture_response_evidence(
        "z" * (MAX_PROVIDER_RESPONSE_BYTES + 500)
    )

    store.finish_physical_attempt(
        invocation,
        _succeeded_event(
            invocation,
            response_text=response_text,
            response_truncated=truncated,
            response_sha256=digest,
        ),
    )

    stored_text, stored_truncated, stored_digest = _stored_response(
        migrated_db,
        invocation.invocation_id,
    )
    assert stored_truncated is True
    assert stored_text is not None
    assert len(stored_text.encode("utf-8")) == MAX_PROVIDER_RESPONSE_BYTES
    assert stored_digest == hashlib.sha256(stored_text.encode("utf-8")).hexdigest()


def test_an_unobserved_outcome_stores_no_response(migrated_db: Engine) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    _execution_id, invocation = _documentation_invocation(store, run_id, configuration)

    store.finish_physical_attempt(
        invocation,
        ProviderTerminalEventV1(
            invocation_id=invocation.invocation_id,
            physical_sequence=invocation.physical_sequence,
            status="timeout",
            returned_model=None,
            upstream_provider=None,
            provider_request_id=None,
            input_tokens=None,
            output_tokens=None,
            reasoning_tokens=None,
            cost_measurement_state="not_observed",
            measured_cost_usd=None,
            error_code="provider_timeout",
            finished_at=datetime.datetime.now(datetime.UTC),
        ),
    )

    assert _stored_response(migrated_db, invocation.invocation_id) == (None, False, None)


def test_crash_recovery_records_null_rather_than_inventing_a_response(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id, invocation = _documentation_invocation(store, run_id, configuration)
    # The process that made the call is gone. Nobody saw what came back. The reservation itself is
    # append-only and cannot be aged, so staleness is expressed through the recovery window.
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE agent_executions SET "
                "started_at = clock_timestamp() - interval '10 minutes' "
                "WHERE execution_id = :execution"
            ),
            {"execution": execution_id},
        )

    assert store.recover_interrupted_hosted_executions(
        limit=8,
        stale_after_seconds=0,
    ) == ((execution_id, "provider_outcome_unknown"),)

    with migrated_db.connect() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT status, response_text, response_truncated, response_sha256 "
                    "FROM provider_call_events WHERE invocation_id = :invocation"
                ),
                {"invocation": invocation.invocation_id},
            )
            .mappings()
            .one()
        )
    assert row["status"] == "outcome_unknown"
    assert row["response_text"] is None
    assert row["response_truncated"] is False
    assert row["response_sha256"] is None


# Identity, duration and scope are taken from the reservation so the pre-existing BEFORE trigger
# passes and the row reaches the CHECK constraints added by 0028 — otherwise these tests would
# prove only that the older trigger still fires.
_RAW_EVENT_INSERT = (
    "INSERT INTO provider_call_events "
    "(event_id, invocation_id, organization_id, campaign_run_id, campaign_attempt_id, "
    "logical_execution_id, agent_role, physical_sequence, status, cost_measurement_state, "
    "error_code, finished_at, duration_ms, response_text, response_truncated, response_sha256) "
    "SELECT :event, i.invocation_id, i.organization_id, i.campaign_run_id, i.campaign_attempt_id, "
    "i.logical_execution_id, i.agent_role, i.physical_sequence, 'timeout', 'not_observed', "
    "'provider_timeout', i.started_at + interval '1 second', 1000, "
    ":body, :truncated, :digest "
    "FROM provider_call_invocations i "
    "WHERE i.organization_id = :org AND i.invocation_id = :invocation"
)


def test_database_refuses_a_response_without_its_digest(migrated_db: Engine) -> None:
    """The pairing constraint is the schema's own guard, independent of the Python contract."""

    store, run_id, configuration = _authorized_run(migrated_db)
    _execution_id, invocation = _documentation_invocation(store, run_id, configuration)
    with (
        migrated_db.begin() as connection,
        pytest.raises(Exception, match="provider_event_response_digest_paired"),
    ):
        connection.execute(
            text(_RAW_EVENT_INSERT),
            {
                "event": hashlib.sha256(b"unpaired").hexdigest(),
                "org": invocation.organization_id,
                "invocation": invocation.invocation_id,
                "body": "unverifiable body",
                "truncated": False,
                "digest": None,
            },
        )


def test_database_refuses_a_digest_without_its_response(migrated_db: Engine) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    _execution_id, invocation = _documentation_invocation(store, run_id, configuration)
    with (
        migrated_db.begin() as connection,
        pytest.raises(Exception, match="provider_event_response_digest_paired"),
    ):
        connection.execute(
            text(_RAW_EVENT_INSERT),
            {
                "event": hashlib.sha256(b"orphan-digest").hexdigest(),
                "org": invocation.organization_id,
                "invocation": invocation.invocation_id,
                "body": None,
                "truncated": False,
                "digest": hashlib.sha256(b"nothing to verify").hexdigest(),
            },
        )


def test_database_refuses_a_response_over_the_bound(migrated_db: Engine) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    _execution_id, invocation = _documentation_invocation(store, run_id, configuration)
    oversized = "q" * (MAX_PROVIDER_RESPONSE_BYTES + 1)
    with (
        migrated_db.begin() as connection,
        pytest.raises(Exception, match="provider_event_response_bounded"),
    ):
        connection.execute(
            text(_RAW_EVENT_INSERT),
            {
                "event": hashlib.sha256(b"oversized").hexdigest(),
                "org": invocation.organization_id,
                "invocation": invocation.invocation_id,
                "body": oversized,
                "truncated": True,
                "digest": hashlib.sha256(oversized.encode("utf-8")).hexdigest(),
            },
        )


def test_database_refuses_a_malformed_response_digest(migrated_db: Engine) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    _execution_id, invocation = _documentation_invocation(store, run_id, configuration)
    with (
        migrated_db.begin() as connection,
        pytest.raises(Exception, match="provider_event_response_sha256_shape"),
    ):
        connection.execute(
            text(_RAW_EVENT_INSERT),
            {
                "event": hashlib.sha256(b"malformed-digest").hexdigest(),
                "org": invocation.organization_id,
                "invocation": invocation.invocation_id,
                "body": "held",
                "truncated": False,
                "digest": "NOT-A-DIGEST" + "0" * 52,
            },
        )
