"""Campaign-scoped target sessions are pinned, expiry-aware, and never exposed."""

from __future__ import annotations

import datetime
import hashlib
import json

import pytest

from agentforge.policy.scoped_credentials import (
    CredentialLeaseExpiredError,
    CredentialResolutionError,
    SealedEnvironmentCredentialResolver,
    SessionLeaseMetadata,
)

SESSION_REF = "secretref://staging/openemr/session/generation-20260722a"
SESSION_VALUE = "synthetic-smart-session-value-0001"
ROTATED_VALUE = "synthetic-smart-session-value-0002"


def _metadata(value: str = SESSION_VALUE) -> SessionLeaseMetadata:
    return SessionLeaseMetadata(
        generation="generation-20260722a",
        expires_at=datetime.datetime(2026, 7, 22, 21, 0, tzinfo=datetime.UTC),
        value_sha256=hashlib.sha256(value.encode()).hexdigest(),
        expiry_source="operator_conservative_lease",
    )


def test_one_campaign_pins_one_secret_even_if_process_environment_changes() -> None:
    environment = {"OPENEMR_SMART_SESSION": SESSION_VALUE}
    resolver = SealedEnvironmentCredentialResolver(
        {SESSION_REF: "OPENEMR_SMART_SESSION"},
        environment=environment,
        session_metadata={SESSION_REF: _metadata()},
    )
    lease = resolver.lease(
        SESSION_REF,
        required_until=datetime.datetime(2026, 7, 22, 20, 30, tzinfo=datetime.UTC),
        now=lambda: datetime.datetime(2026, 7, 22, 20, 0, tzinfo=datetime.UTC),
        require_session_metadata=True,
    )

    assert lease.required_until == datetime.datetime(2026, 7, 22, 20, 30, tzinfo=datetime.UTC)
    first = lease.resolve(SESSION_REF)
    environment["OPENEMR_SMART_SESSION"] = ROTATED_VALUE
    second = lease.resolve(SESSION_REF)

    assert first is second
    assert first.reveal() == SESSION_VALUE
    assert lease.resolution_count == 1
    assert SESSION_VALUE not in repr(lease)


def test_silent_rotation_under_the_same_versioned_reference_is_refused() -> None:
    environment = {"OPENEMR_SMART_SESSION": ROTATED_VALUE}
    resolver = SealedEnvironmentCredentialResolver(
        {SESSION_REF: "OPENEMR_SMART_SESSION"},
        environment=environment,
        session_metadata={SESSION_REF: _metadata(SESSION_VALUE)},
    )
    lease = resolver.lease(
        SESSION_REF,
        required_until=datetime.datetime(2026, 7, 22, 20, 30, tzinfo=datetime.UTC),
        now=lambda: datetime.datetime(2026, 7, 22, 20, 0, tzinfo=datetime.UTC),
        require_session_metadata=True,
    )

    with pytest.raises(CredentialResolutionError, match="generation metadata"):
        lease.resolve(SESSION_REF)


def test_session_metadata_rejects_cookie_wrappers_without_path_name_heuristics() -> None:
    reference = "secretref://staging/openemr/generation-20260722a"
    wrapped_value = "sid=synthetic-smart-session-value"
    resolver = SealedEnvironmentCredentialResolver(
        {reference: "OPENEMR_SMART_SESSION"},
        environment={"OPENEMR_SMART_SESSION": wrapped_value},
        session_metadata={
            reference: SessionLeaseMetadata(
                generation="generation-20260722a",
                expires_at=_metadata().expires_at,
                value_sha256=hashlib.sha256(wrapped_value.encode()).hexdigest(),
                expiry_source="operator_conservative_lease",
            )
        },
    )

    with pytest.raises(CredentialResolutionError, match="raw identifier"):
        resolver.resolve(reference)


def test_session_must_cover_the_full_campaign_window_and_version_match_reference() -> None:
    resolver = SealedEnvironmentCredentialResolver(
        {SESSION_REF: "OPENEMR_SMART_SESSION"},
        environment={"OPENEMR_SMART_SESSION": SESSION_VALUE},
        session_metadata={SESSION_REF: _metadata()},
    )

    assert resolver.session_ready(
        SESSION_REF,
        required_until=datetime.datetime(2026, 7, 22, 20, 59, tzinfo=datetime.UTC),
    )
    assert not resolver.session_ready(
        SESSION_REF,
        required_until=datetime.datetime(2026, 7, 22, 21, 1, tzinfo=datetime.UTC),
    )
    with pytest.raises(CredentialLeaseExpiredError, match="campaign window"):
        resolver.lease(
            SESSION_REF,
            required_until=datetime.datetime(2026, 7, 22, 21, 1, tzinfo=datetime.UTC),
            now=lambda: datetime.datetime(2026, 7, 22, 20, 0, tzinfo=datetime.UTC),
            require_session_metadata=True,
        )

    wrong_generation = SessionLeaseMetadata(
        generation="generation-other",
        expires_at=_metadata().expires_at,
        value_sha256=_metadata().value_sha256,
        expiry_source="operator_conservative_lease",
    )
    bad = SealedEnvironmentCredentialResolver(
        {SESSION_REF: "OPENEMR_SMART_SESSION"},
        environment={"OPENEMR_SMART_SESSION": SESSION_VALUE},
        session_metadata={SESSION_REF: wrong_generation},
    )
    assert not bad.session_ready(
        SESSION_REF,
        required_until=datetime.datetime(2026, 7, 22, 20, 30, tzinfo=datetime.UTC),
    )


def test_expiry_during_campaign_and_release_fail_closed() -> None:
    current = [datetime.datetime(2026, 7, 22, 20, 0, tzinfo=datetime.UTC)]
    resolver = SealedEnvironmentCredentialResolver(
        {SESSION_REF: "OPENEMR_SMART_SESSION"},
        environment={"OPENEMR_SMART_SESSION": SESSION_VALUE},
        session_metadata={SESSION_REF: _metadata()},
    )
    lease = resolver.lease(
        SESSION_REF,
        required_until=datetime.datetime(2026, 7, 22, 20, 30, tzinfo=datetime.UTC),
        now=lambda: current[0],
        require_session_metadata=True,
    )
    lease.resolve(SESSION_REF)

    current[0] = datetime.datetime(2026, 7, 22, 21, 0, tzinfo=datetime.UTC)
    with pytest.raises(CredentialLeaseExpiredError):
        lease.resolve(SESSION_REF)

    lease.release()
    with pytest.raises(CredentialResolutionError, match="released"):
        lease.resolve(SESSION_REF)


def test_non_session_credentials_remain_backward_compatible_without_lease_metadata() -> None:
    reference = "secretref://staging/provider/bearer"
    resolver = SealedEnvironmentCredentialResolver(
        {reference: "PROVIDER_BEARER"},
        environment={"PROVIDER_BEARER": "synthetic-bearer-value"},
    )
    lease = resolver.lease(reference, require_session_metadata=False)

    lease.require_valid_through(
        reference,
        required_until=datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1),
    )
    assert lease.resolve(reference).reveal() == "synthetic-bearer-value"


def test_per_call_session_window_refuses_expiry_equality_without_resolving_secret() -> None:
    now = datetime.datetime(2026, 7, 22, 20, 0, tzinfo=datetime.UTC)
    resolver = SealedEnvironmentCredentialResolver(
        {SESSION_REF: "OPENEMR_SMART_SESSION"},
        environment={"OPENEMR_SMART_SESSION": SESSION_VALUE},
        session_metadata={SESSION_REF: _metadata()},
    )
    lease = resolver.lease(
        SESSION_REF,
        required_until=now + datetime.timedelta(minutes=30),
        now=lambda: now,
        require_session_metadata=True,
    )

    lease.require_valid_through(
        SESSION_REF,
        required_until=_metadata().expires_at - datetime.timedelta(microseconds=1),
    )
    with pytest.raises(CredentialLeaseExpiredError, match="external call timeout"):
        lease.require_valid_through(
            SESSION_REF,
            required_until=_metadata().expires_at,
        )
    assert lease.resolution_count == 0


def test_runner_environment_loads_session_value_and_lifecycle_metadata_separately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "AGENTFORGE_CREDENTIAL_BINDINGS_JSON",
        json.dumps({SESSION_REF: "OPENEMR_SMART_SESSION"}),
    )
    monkeypatch.setenv("OPENEMR_SMART_SESSION", SESSION_VALUE)
    monkeypatch.setenv(
        "AGENTFORGE_SESSION_LEASES_JSON",
        json.dumps(
            {
                SESSION_REF: {
                    "generation": _metadata().generation,
                    "expires_at": _metadata().expires_at.isoformat(),
                    "value_sha256": _metadata().value_sha256,
                    "expiry_source": _metadata().expiry_source,
                }
            }
        ),
    )

    resolver = SealedEnvironmentCredentialResolver.from_environment()
    lease = resolver.lease(
        SESSION_REF,
        required_until=datetime.datetime(2026, 7, 22, 20, 30, tzinfo=datetime.UTC),
        now=lambda: datetime.datetime(2026, 7, 22, 20, 0, tzinfo=datetime.UTC),
        require_session_metadata=True,
    )

    assert lease.resolve(SESSION_REF).reveal() == SESSION_VALUE


def test_malformed_runner_session_metadata_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "AGENTFORGE_CREDENTIAL_BINDINGS_JSON",
        json.dumps({SESSION_REF: "OPENEMR_SMART_SESSION"}),
    )
    monkeypatch.setenv(
        "AGENTFORGE_SESSION_LEASES_JSON",
        json.dumps({SESSION_REF: {"generation": _metadata().generation}}),
    )

    with pytest.raises(CredentialResolutionError, match="metadata configuration"):
        SealedEnvironmentCredentialResolver.from_environment()


def test_session_cookie_wrapper_is_refused_without_echoing_the_value() -> None:
    wrapped = "sid=synthetic-session-that-must-not-be-logged"
    resolver = SealedEnvironmentCredentialResolver(
        {SESSION_REF: "OPENEMR_SMART_SESSION"},
        environment={"OPENEMR_SMART_SESSION": wrapped},
        session_metadata={SESSION_REF: _metadata(wrapped)},
    )

    with pytest.raises(CredentialResolutionError) as error:
        resolver.resolve(SESSION_REF)
    assert "raw identifier" in str(error.value)
    assert wrapped not in str(error.value)
