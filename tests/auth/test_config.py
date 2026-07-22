"""Fail-closed environment configuration for Clerk request authentication."""

from __future__ import annotations

import pytest

from agentforge.auth.config import ClerkAuthConfig
from agentforge.auth.errors import AuthConfigurationError


def test_complete_staging_config_loads(auth_environ, auth_values) -> None:
    config = ClerkAuthConfig.from_env(auth_environ)

    assert config.environment == "staging"
    assert config.publishable_key == auth_values.staging_publishable_key
    assert tuple(config.authorized_parties) == (auth_values.staging_origin,)
    assert config.required_organization_id == auth_values.staging_org_id


@pytest.mark.parametrize(
    "authorized_parties",
    ["*", "https://*.example.com", "https://headshot.example,*"],
)
def test_wildcard_authorized_party_is_rejected(auth_environ, authorized_parties: str) -> None:
    auth_environ["CLERK_AUTHORIZED_PARTIES"] = authorized_parties

    with pytest.raises(AuthConfigurationError):
        ClerkAuthConfig.from_env(auth_environ)


def test_production_http_origin_is_rejected(auth_environ, auth_values) -> None:
    auth_environ.update(
        {
            "AGENTFORGE_ENVIRONMENT": "production",
            "CLERK_PUBLISHABLE_KEY": auth_values.production_publishable_key,
            "CLERK_REQUIRED_ORG_ID": auth_values.production_org_id,
            "CLERK_AUTHORIZED_PARTIES": "http://headshot-production.example",
        }
    )

    with pytest.raises(AuthConfigurationError):
        ClerkAuthConfig.from_env(auth_environ)


def test_staging_cannot_use_production_organization(auth_environ, auth_values) -> None:
    auth_environ["CLERK_REQUIRED_ORG_ID"] = auth_values.production_org_id

    with pytest.raises(AuthConfigurationError):
        ClerkAuthConfig.from_env(auth_environ)


def test_staging_cannot_use_production_origin(auth_environ, auth_values) -> None:
    auth_environ["CLERK_AUTHORIZED_PARTIES"] = auth_values.production_origin

    with pytest.raises(AuthConfigurationError):
        ClerkAuthConfig.from_env(auth_environ)


@pytest.mark.parametrize(
    "guard",
    ["CLERK_PRODUCTION_ORG_ID", "CLERK_PRODUCTION_AUTHORIZED_PARTIES"],
)
def test_staging_requires_explicit_production_comparison_guards(auth_environ, guard: str) -> None:
    auth_environ.pop(guard)

    with pytest.raises(AuthConfigurationError):
        ClerkAuthConfig.from_env(auth_environ)


def test_localhost_origin_is_local_only(auth_environ, auth_values) -> None:
    local = dict(auth_environ)
    local.update(
        {
            "AGENTFORGE_ENVIRONMENT": "local",
            "CLERK_AUTHORIZED_PARTIES": auth_values.local_origin,
        }
    )
    assert tuple(ClerkAuthConfig.from_env(local).authorized_parties) == (auth_values.local_origin,)

    auth_environ["CLERK_AUTHORIZED_PARTIES"] = auth_values.local_origin
    with pytest.raises(AuthConfigurationError):
        ClerkAuthConfig.from_env(auth_environ)


def test_missing_required_config_fails_closed(auth_environ) -> None:
    auth_environ.pop("CLERK_JWT_KEY")

    with pytest.raises(AuthConfigurationError):
        ClerkAuthConfig.from_env(auth_environ)


def test_malformed_pem_public_key_fails_at_config_load(auth_environ) -> None:
    auth_environ["CLERK_JWT_KEY"] = (
        "-----BEGIN PUBLIC KEY-----\nnot-a-valid-rsa-key\n-----END PUBLIC KEY-----"
    )

    with pytest.raises(AuthConfigurationError):
        ClerkAuthConfig.from_env(auth_environ)


def test_frontend_key_and_backend_management_secret_have_no_authority(
    auth_environ, auth_values
) -> None:
    unused_secret = "unused-backend-management-sentinel"
    auth_environ["VITE_CLERK_PUBLISHABLE_KEY"] = "frontend-public-sentinel"
    auth_environ["CLERK_SECRET_KEY"] = unused_secret

    config = ClerkAuthConfig.from_env(auth_environ)

    assert config.publishable_key == auth_values.staging_publishable_key
    assert unused_secret not in repr(config)
