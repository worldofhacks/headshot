"""Credential non-disclosure and networkless-verification proofs."""

from __future__ import annotations

import logging
import socket
import traceback

import pytest

from agentforge.auth.clerk import ClerkAuthenticator
from agentforge.auth.errors import AuthenticationError, AuthenticationUnavailableError

CONSOLE_READ = "org:console:read"


def _render_exception(exc: BaseException) -> str:
    return "".join(traceback.format_exception(exc)) + str(exc) + repr(exc)


def test_token_and_authorization_header_are_absent_from_logs_errors_and_traces(
    auth_config, request_factory, caplog
) -> None:
    token = "fixture-sensitive-token.header.payload.signature"
    authorization_header = f"Bearer {token}"

    with caplog.at_level(logging.DEBUG), pytest.raises(AuthenticationError) as excinfo:
        ClerkAuthenticator(auth_config).authenticate(request_factory(token))

    rendered = caplog.text + _render_exception(excinfo.value)
    assert token not in rendered
    assert authorization_header not in rendered


def test_leaky_verifier_exception_is_not_chained_into_public_trace(
    auth_config, request_factory
) -> None:
    token = "fixture-verifier-sensitive-token"
    authorization_header = f"Bearer {token}"

    def leaky_verifier(_request, _options):
        raise RuntimeError(authorization_header)

    with pytest.raises(AuthenticationUnavailableError) as excinfo:
        ClerkAuthenticator(auth_config, verifier=leaky_verifier).authenticate(
            request_factory(token)
        )

    rendered = _render_exception(excinfo.value)
    assert token not in rendered
    assert authorization_header not in rendered
    assert excinfo.value.__context__ is None


def test_principal_repr_contains_no_token_or_authorization_header(
    auth_config, token_factory, request_factory
) -> None:
    token = token_factory(permissions=(CONSOLE_READ,))
    authorization_header = f"Bearer {token}"

    principal = ClerkAuthenticator(auth_config).authenticate(request_factory(token))
    rendered = repr(principal)

    assert token not in rendered
    assert authorization_header not in rendered
    assert "authorization" not in rendered.lower()


def test_networkless_authentication_succeeds_with_all_egress_tripwires_active(
    auth_config, token_factory, request_factory
) -> None:
    principal = ClerkAuthenticator(auth_config).authenticate(request_factory(token_factory()))

    assert principal.user_id


def test_auth_suite_network_tripwire_is_active() -> None:
    with pytest.raises(AssertionError, match="attempted network"):
        socket.socket()
