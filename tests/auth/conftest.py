"""Offline Clerk authentication fixtures.

All JWTs and RSA keys are generated in memory.  No committed private key, Clerk
credential, deployed service, JWKS endpoint, or network connection is used.
"""

from __future__ import annotations

import base64
import socket
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass(frozen=True, slots=True)
class RSAKeyPair:
    """Ephemeral signing material used only by this test process."""

    private_key: bytes
    public_key: str


@dataclass(frozen=True, slots=True)
class RequestStub:
    """The minimal request shape accepted by Clerk's Python SDK."""

    headers: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class AuthValues:
    local_origin: str
    staging_origin: str
    production_origin: str
    staging_org_id: str
    production_org_id: str
    user_id: str
    other_user_id: str
    session_id: str
    staging_publishable_key: str
    production_publishable_key: str


def _publishable_key(prefix: str, frontend_api: str) -> str:
    encoded = base64.b64encode(f"{frontend_api}$".encode()).decode()
    return f"{prefix}_{encoded}"


@pytest.fixture(scope="session")
def auth_values() -> AuthValues:
    return AuthValues(
        local_origin="http://localhost:5173",
        staging_origin="https://headshot-staging.up.railway.app",
        production_origin="https://headshot-production.up.railway.app",
        staging_org_id="org_2HeadshotStagingFixture",
        production_org_id="org_2HeadshotProductionFixture",
        user_id="user_2OperatorFixture",
        other_user_id="user_2ApproverFixture",
        session_id="sess_2HeadshotFixture",
        staging_publishable_key=_publishable_key("pk_test", "headshot-staging.clerk.accounts.dev"),
        production_publishable_key=_publishable_key("pk_live", "clerk.headshot-production.example"),
    )


def _generate_key_pair() -> RSAKeyPair:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return RSAKeyPair(private_key=private_pem, public_key=public_pem.decode())


@pytest.fixture(scope="session")
def signing_keys() -> RSAKeyPair:
    return _generate_key_pair()


@pytest.fixture(scope="session")
def unrelated_signing_keys() -> RSAKeyPair:
    return _generate_key_pair()


@pytest.fixture
def auth_environ(auth_values: AuthValues, signing_keys: RSAKeyPair) -> dict[str, str]:
    """A complete staging configuration with explicit production isolation guards."""

    return {
        "AGENTFORGE_ENVIRONMENT": "staging",
        "CLERK_PUBLISHABLE_KEY": auth_values.staging_publishable_key,
        "CLERK_JWT_KEY": signing_keys.public_key,
        "CLERK_AUTHORIZED_PARTIES": auth_values.staging_origin,
        "CLERK_REQUIRED_ORG_ID": auth_values.staging_org_id,
        "CLERK_PRODUCTION_ORG_ID": auth_values.production_org_id,
        "CLERK_PRODUCTION_AUTHORIZED_PARTIES": auth_values.production_origin,
    }


@pytest.fixture
def auth_config(auth_environ: dict[str, str]) -> Any:
    from agentforge.auth.config import ClerkAuthConfig

    return ClerkAuthConfig.from_env(auth_environ)


@pytest.fixture
def request_factory() -> Callable[..., RequestStub]:
    def build(
        token: str | None = None,
        *,
        extra_headers: Mapping[str, str] | None = None,
    ) -> RequestStub:
        headers = dict(extra_headers or {})
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        return RequestStub(headers=httpx.Headers(headers))

    return build


def _compressed_org_claim(
    organization_id: str,
    role: str,
    permissions: Iterable[str],
) -> tuple[dict[str, str], str | None]:
    """Encode custom permissions in Clerk session-token v2's compact claim shape."""

    by_feature: dict[str, set[str]] = {}
    for permission in permissions:
        parts = permission.split(":")
        if len(parts) != 3 or parts[0] != "org":
            raise ValueError(f"invalid fixture permission: {permission!r}")
        _, feature, action = parts
        by_feature.setdefault(feature, set()).add(action)

    org_claim: dict[str, str] = {
        "id": organization_id,
        "rol": role.removeprefix("org:"),
        "slg": "headshot-fixture",
    }
    if not by_feature:
        return org_claim, None

    features = sorted(by_feature)
    actions = sorted({action for values in by_feature.values() for action in values})
    masks: list[str] = []
    for feature in features:
        mask = sum(1 << actions.index(action) for action in by_feature[feature])
        masks.append(str(mask))

    org_claim["per"] = ",".join(actions)
    org_claim["fpm"] = ",".join(masks)
    return org_claim, ",".join(f"o:{feature}" for feature in features)


@pytest.fixture
def token_factory(
    auth_values: AuthValues,
    signing_keys: RSAKeyPair,
) -> Callable[..., str]:
    """Mint a locally signed Clerk-shaped session token."""

    def mint(
        *,
        permissions: Iterable[str] = ("org:console:read",),
        organization_id: str | None = None,
        role: str = "operator",
        authorized_party: str | None = None,
        user_id: str | None = None,
        session_id: str | None = None,
        signing_key_pair: RSAKeyPair | None = None,
        algorithm: str = "RS256",
        omit_claims: Iterable[str] = (),
        claim_overrides: Mapping[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        org_id = auth_values.staging_org_id if organization_id is None else organization_id
        payload: dict[str, Any] = {
            "v": 2,
            "iss": "https://headshot-staging.clerk.accounts.dev",
            "sub": user_id or auth_values.user_id,
            "sid": session_id or auth_values.session_id,
            "azp": authorized_party or auth_values.staging_origin,
            "iat": now,
            "nbf": now - 10,
            "exp": now + 300,
            "jti": "jwt_headshot_fixture",
            "fva": [0, 0],
            "role": "authenticated",
        }
        if org_id:
            org_claim, features = _compressed_org_claim(org_id, role, permissions)
            payload["o"] = org_claim
            if features is not None:
                payload["fea"] = features

        payload.update(dict(claim_overrides or {}))
        for claim in omit_claims:
            payload.pop(claim, None)

        if algorithm == "RS256":
            pair = signing_key_pair or signing_keys
            key: bytes | str = pair.private_key
        elif algorithm == "none":
            key = ""
        else:
            key = "fixture-hmac-key-is-not-a-clerk-secret-000000"

        return jwt.encode(
            payload,
            key,
            algorithm=algorithm,
            headers={"kid": "headshot-fixture-key"},
        )

    return mint


@pytest.fixture(autouse=True)
def deny_auth_test_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Trip every common egress path for every test in this directory."""

    real_socket = socket.socket

    def blocked(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("authentication test attempted network I/O")

    def blocked_network_socket(
        family: int = socket.AF_INET,
        type: int = socket.SOCK_STREAM,
        proto: int = 0,
        fileno: int | None = None,
    ) -> Any:
        # ASGI TestClient's event loop uses an AF_UNIX socketpair for local thread
        # signalling. Permit that local IPC primitive while denying AF_INET/AF_INET6
        # sockets, DNS, connect helpers, JWKS, and HTTP clients below.
        if family == socket.AF_UNIX:
            return real_socket(family, type, proto, fileno)
        return blocked(family, type, proto, fileno)

    monkeypatch.setattr(socket, "socket", blocked_network_socket)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)

    import clerk_backend_api.security.verifytoken as verifytoken

    monkeypatch.setattr(verifytoken, "_fetch_jwks", blocked)
    monkeypatch.setattr(verifytoken, "_fetch_jwks_async", blocked)
    monkeypatch.setattr(verifytoken.httpx, "Client", blocked)
    monkeypatch.setattr(verifytoken.httpx, "AsyncClient", blocked)
