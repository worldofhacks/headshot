"""Fail-closed Clerk request-authentication configuration."""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from agentforge.auth.errors import AuthConfigurationError

_ENVIRONMENTS = frozenset({"local", "staging", "production"})
_ORG_ID_RE = re.compile(r"\Aorg_[A-Za-z0-9]+\Z")
_PUBLIC_KEY_BEGIN = "-----BEGIN PUBLIC KEY-----"
_PUBLIC_KEY_END = "-----END PUBLIC KEY-----"


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name)
    if value is None or not value.strip():
        raise AuthConfigurationError(f"required authentication setting is missing: {name}")
    return value.strip()


def _is_loopback_host(hostname: str) -> bool:
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _parse_authorized_parties(raw: str, environment: str) -> tuple[str, ...]:
    if "*" in raw:
        raise AuthConfigurationError("wildcard authorized parties are forbidden")

    parties = tuple(part.strip() for part in raw.split(","))
    if not parties or any(not part for part in parties):
        raise AuthConfigurationError("authorized parties must be an explicit origin list")
    if len(parties) != len(set(parties)):
        raise AuthConfigurationError("authorized parties must not contain duplicates")

    for origin in parties:
        if any(character.isspace() for character in origin):
            raise AuthConfigurationError("authorized parties must be exact origins")
        try:
            parsed = urlsplit(origin)
            _ = parsed.port
        except ValueError as exc:
            raise AuthConfigurationError("authorized parties must be valid origins") from exc

        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise AuthConfigurationError("authorized parties must be exact origins")

        loopback = _is_loopback_host(parsed.hostname)
        if environment == "local":
            if not loopback:
                raise AuthConfigurationError("local authorized parties must use loopback origins")
        elif parsed.scheme != "https" or loopback:
            raise AuthConfigurationError(
                "deployed authorized parties must be non-local HTTPS origins"
            )

    return parties


@dataclass(frozen=True, slots=True)
class ClerkAuthConfig:
    """Immutable environment-specific contract for Clerk session verification."""

    environment: str
    publishable_key: str
    jwt_key: str = field(repr=False)
    authorized_parties: tuple[str, ...]
    required_organization_id: str
    clock_skew_in_ms: int = 5_000

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> ClerkAuthConfig:
        """Load only explicit process values; never read dotenv files or management secrets."""

        source = os.environ if environ is None else environ
        environment = source.get("AGENTFORGE_ENVIRONMENT", "local").strip()
        if environment not in _ENVIRONMENTS:
            raise AuthConfigurationError("authentication environment is invalid")

        publishable_key = _required(source, "CLERK_PUBLISHABLE_KEY")
        expected_prefix = "pk_live_" if environment == "production" else "pk_test_"
        if not publishable_key.startswith(expected_prefix):
            raise AuthConfigurationError(
                "Clerk publishable key does not match the deployment environment"
            )

        jwt_key = _required(source, "CLERK_JWT_KEY").replace("\\n", "\n")
        if (
            not jwt_key.startswith(_PUBLIC_KEY_BEGIN)
            or not jwt_key.endswith(_PUBLIC_KEY_END)
            or "PRIVATE KEY" in jwt_key
        ):
            raise AuthConfigurationError("CLERK_JWT_KEY must be a PEM public key")
        parsed_jwt_key = None
        with suppress(Exception):
            parsed_jwt_key = load_pem_public_key(jwt_key.encode("ascii"))
        if not isinstance(parsed_jwt_key, RSAPublicKey) or parsed_jwt_key.key_size < 2_048:
            raise AuthConfigurationError("CLERK_JWT_KEY must be a 2048-bit or stronger RSA key")

        required_organization_id = _required(source, "CLERK_REQUIRED_ORG_ID")
        if _ORG_ID_RE.fullmatch(required_organization_id) is None:
            raise AuthConfigurationError("required Clerk Organization ID is invalid")

        authorized_parties = _parse_authorized_parties(
            _required(source, "CLERK_AUTHORIZED_PARTIES"), environment
        )

        if environment == "staging":
            production_org_id = _required(source, "CLERK_PRODUCTION_ORG_ID")
            production_parties = _parse_authorized_parties(
                _required(source, "CLERK_PRODUCTION_AUTHORIZED_PARTIES"), "production"
            )
            if required_organization_id == production_org_id:
                raise AuthConfigurationError(
                    "staging must not use the production Clerk Organization"
                )
            if set(authorized_parties).intersection(production_parties):
                raise AuthConfigurationError(
                    "staging must not accept a production authorized party"
                )

        return cls(
            environment=environment,
            publishable_key=publishable_key,
            jwt_key=jwt_key,
            authorized_parties=authorized_parties,
            required_organization_id=required_organization_id,
        )
