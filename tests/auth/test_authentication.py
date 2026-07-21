"""Offline authentication tests over Clerk's official Python verifier."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from clerk_backend_api.security import authenticate_request as clerk_authenticate_request

from agentforge.auth.clerk import ClerkAuthenticator
from agentforge.auth.errors import (
    AuthenticationError,
    AuthenticationUnavailableError,
    AuthorizationError,
)
from agentforge.auth.principal import Principal

CONSOLE_READ = "org:console:read"
CAMPAIGN_AUTHORIZE = "org:campaign:authorize"


def _assert_status(exc: BaseException, expected: int) -> None:
    assert getattr(exc, "status_code", None) == expected


def test_valid_v2_session_builds_immutable_normalized_principal(
    auth_config, auth_values, token_factory, request_factory
) -> None:
    token = token_factory(
        permissions=(CONSOLE_READ, CAMPAIGN_AUTHORIZE),
        role="approver",
    )

    principal = ClerkAuthenticator(auth_config).authenticate(request_factory(token))

    assert isinstance(principal, Principal)
    assert principal.user_id == auth_values.user_id
    assert principal.session_id == auth_values.session_id
    assert principal.organization_id == auth_values.staging_org_id
    assert principal.organization_role == "org:approver"
    assert principal.organization_permissions == frozenset({CONSOLE_READ, CAMPAIGN_AUTHORIZE})
    assert not hasattr(principal, "__dict__")
    with pytest.raises(FrozenInstanceError):
        principal.user_id = "user_2MutationAttempt"  # type: ignore[misc]


def test_missing_token_maps_to_401(auth_config, request_factory) -> None:
    with pytest.raises(AuthenticationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request_factory())

    _assert_status(excinfo.value, 401)


def test_clerk_cookie_cannot_replace_explicit_bearer_token(
    auth_config, token_factory, request_factory
) -> None:
    token = token_factory()
    request = request_factory(extra_headers={"Cookie": f"__session={token}"})

    with pytest.raises(AuthenticationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request)

    _assert_status(excinfo.value, 401)


def test_malformed_token_maps_to_401(auth_config, request_factory) -> None:
    with pytest.raises(AuthenticationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request_factory("not.a.valid.session-token"))

    _assert_status(excinfo.value, 401)


def test_expired_token_maps_to_401(auth_config, token_factory, request_factory) -> None:
    import time

    token = token_factory(claim_overrides={"exp": int(time.time()) - 60})
    with pytest.raises(AuthenticationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request_factory(token))

    _assert_status(excinfo.value, 401)


def test_not_yet_valid_token_maps_to_401(auth_config, token_factory, request_factory) -> None:
    import time

    token = token_factory(claim_overrides={"nbf": int(time.time()) + 60})
    with pytest.raises(AuthenticationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request_factory(token))

    _assert_status(excinfo.value, 401)


def test_invalid_signature_maps_to_401(
    auth_config, token_factory, request_factory, unrelated_signing_keys
) -> None:
    token = token_factory(signing_key_pair=unrelated_signing_keys)
    with pytest.raises(AuthenticationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request_factory(token))

    _assert_status(excinfo.value, 401)


@pytest.mark.parametrize("algorithm", ["HS256", "none"])
def test_unsupported_or_none_algorithm_is_rejected(
    auth_config, token_factory, request_factory, algorithm: str
) -> None:
    token = token_factory(algorithm=algorithm)
    with pytest.raises(AuthenticationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request_factory(token))

    _assert_status(excinfo.value, 401)


def test_wrong_authorized_party_is_rejected(auth_config, token_factory, request_factory) -> None:
    token = token_factory(authorized_party="https://attacker.example")
    with pytest.raises(AuthenticationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request_factory(token))

    _assert_status(excinfo.value, 401)


def test_wrong_organization_maps_to_403(auth_config, token_factory, request_factory) -> None:
    token = token_factory(organization_id="org_2NotHeadshotFixture")
    with pytest.raises(AuthorizationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request_factory(token))

    _assert_status(excinfo.value, 403)


def test_missing_organization_maps_to_403(auth_config, token_factory, request_factory) -> None:
    token = token_factory(organization_id="")
    with pytest.raises(AuthorizationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request_factory(token))

    _assert_status(excinfo.value, 403)


@pytest.mark.parametrize("missing_claim", ["sub", "sid", "exp"])
def test_missing_core_session_claim_is_rejected(
    auth_config, token_factory, request_factory, missing_claim: str
) -> None:
    token = token_factory(omit_claims=(missing_claim,))
    with pytest.raises(AuthenticationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request_factory(token))

    _assert_status(excinfo.value, 401)


def test_pending_session_is_not_authenticated(auth_config, token_factory, request_factory) -> None:
    token = token_factory(claim_overrides={"sts": "pending"})
    with pytest.raises(AuthenticationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request_factory(token))

    _assert_status(excinfo.value, 401)


def test_actor_session_is_rejected_to_preserve_human_identity_separation(
    auth_config, auth_values, token_factory, request_factory
) -> None:
    token = token_factory(
        permissions=(CAMPAIGN_AUTHORIZE,),
        claim_overrides={"act": {"sub": auth_values.other_user_id}},
    )
    with pytest.raises(AuthorizationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request_factory(token))

    _assert_status(excinfo.value, 403)


def test_machine_token_is_explicitly_rejected_without_backend_api_call(
    auth_config, request_factory
) -> None:
    with pytest.raises(AuthenticationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request_factory("m2m_fixture-machine-token"))

    _assert_status(excinfo.value, 401)


def test_authenticator_passes_networkless_session_only_options(
    auth_config, token_factory, request_factory
) -> None:
    captured: dict[str, object] = {}

    def verifier(request, options):
        captured["options"] = options
        return clerk_authenticate_request(request, options)

    principal = ClerkAuthenticator(auth_config, verifier=verifier).authenticate(
        request_factory(token_factory())
    )
    options = captured["options"]

    assert isinstance(principal, Principal)
    assert options.accepts_token == ["session_token"]
    assert options.jwt_key == auth_config.jwt_key
    assert options.authorized_parties == list(auth_config.authorized_parties)
    assert options.secret_key is None


def test_unexpected_clerk_verifier_failure_fails_closed_with_503(
    auth_config, request_factory
) -> None:
    def broken_verifier(_request, _options):
        raise RuntimeError("fixture verifier failure")

    authenticator = ClerkAuthenticator(auth_config, verifier=broken_verifier)
    with pytest.raises(AuthenticationUnavailableError) as excinfo:
        authenticator.authenticate(request_factory("fixture.invalid.token"))

    _assert_status(excinfo.value, 503)
