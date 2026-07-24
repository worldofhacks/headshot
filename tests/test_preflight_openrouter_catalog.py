"""Deterministic tests for the credential-free public OpenRouter catalog gate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.prompts import load_prompt_registry

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "preflight_openrouter_catalog.py"
_SPEC = importlib.util.spec_from_file_location("preflight_openrouter_catalog", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
catalog = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(catalog)

_MODELS = {
    "orchestrator": "anthropic/claude-opus-4.8",
    "red_team": "qwen/qwen3.5-397b-a17b",
    "judge": "google/gemini-2.5-pro",
    "documentation": "openai/gpt-5.4",
}
_PROVIDERS = {
    "orchestrator": "amazon-bedrock/eu-west-1",
    "red_team": "atlas-cloud/fp8",
    "judge": "google-vertex/global",
    "documentation": "azure/eu",
}
_COMPLETION_TOKEN_PARAMETERS = {
    "orchestrator": "max_tokens",
    "red_team": "max_tokens",
    "judge": "max_tokens",
    "documentation": "max_completion_tokens",
}
_PROMPTS = {prompt.role: prompt for prompt in load_prompt_registry()}
_NOW = datetime(2026, 7, 24, 22, 44, 17, tzinfo=UTC)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _limits(role: str) -> HostedLimits:
    max_usd = {
        "orchestrator": Decimal("1.5"),
        "red_team": Decimal("1"),
        "judge": Decimal("4"),
        "documentation": Decimal("1"),
    }[role]
    return HostedLimits(
        max_calls=1,
        max_input_tokens=200_000,
        max_output_tokens=20_000,
        max_reasoning_tokens=20_000,
        max_usd=max_usd,
        max_retries=1,
        max_requests_per_second=Decimal("0.5"),
        max_concurrency=1,
    )


def _configuration(
    providers: dict[str, str] | None = None,
) -> HostedConfigurationSet:
    selected_providers = providers or _PROVIDERS
    roles = tuple(
        HostedRoleConfiguration(
            role=role,
            provider="openrouter",
            model_id=model,
            upstream_provider=selected_providers[role],
            completion_token_parameter=_COMPLETION_TOKEN_PARAMETERS[role],
            credential_reference=f"secretref://test/openrouter/{role}/generation-1",
            prompt_sha256=_PROMPTS[role].sha256,
            policy_sha256=_digest(f"policy:{role}:v1"),
            prices=TokenPrices(
                input_usd_per_million_tokens=Decimal("1"),
                output_usd_per_million_tokens=Decimal("1"),
                reasoning_usd_per_million_tokens=Decimal("1"),
            ),
            limits=_limits(role),
        )
        for role, model in _MODELS.items()
    )
    return HostedConfigurationSet(
        roles=roles,
        global_limits=HostedLimits(
            max_calls=4,
            max_input_tokens=800_000,
            max_output_tokens=80_000,
            max_reasoning_tokens=80_000,
            max_usd=Decimal("10"),
            max_retries=1,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


def _endpoint(
    model_id: str,
    tag: str,
    *,
    prompt_price: str = "0.000001",
    completion_price: str = "0.000001",
    status: int = 0,
    max_completion_tokens: int | None = 128_000,
    supported_parameters: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "name": f"Fixture | {model_id}",
        "model_id": model_id,
        "model_name": model_id,
        "provider_name": tag.split("/", 1)[0].title(),
        "tag": tag,
        "status": status,
        "uptime_last_30m": 100,
        "context_length": 1_100_000,
        "max_completion_tokens": max_completion_tokens,
        "supported_parameters": supported_parameters
        or [
            "max_tokens",
            "max_completion_tokens",
            "reasoning",
            "response_format",
            "structured_outputs",
        ],
        "pricing": {
            "prompt": prompt_price,
            "completion": completion_price,
            "discount": 0,
        },
    }


def _feeds() -> dict[str, Any]:
    feeds: dict[str, Any] = {}
    zdr: list[dict[str, Any]] = []
    for role, model_id in _MODELS.items():
        tag = _PROVIDERS[role]
        endpoint = _endpoint(model_id, tag)
        feeds[catalog._model_endpoint_url(model_id)] = {
            "data": {"id": model_id, "endpoints": [endpoint]}
        }
        zdr.append({"model_id": model_id, "tag": tag})
    feeds[catalog._ZDR_ENDPOINT_URL] = {"data": zdr}
    return feeds


def _fetcher(feeds: dict[str, Any]):
    def fetch(url: str) -> bytes:
        value = feeds[url]
        if isinstance(value, Exception):
            raise value
        return json.dumps(value, separators=(",", ":")).encode()

    return fetch


def _audit(
    feeds: dict[str, Any] | None = None,
    configuration: HostedConfigurationSet | None = None,
) -> dict[str, Any]:
    configuration = configuration or _configuration()
    return catalog.audit_catalog(
        configuration.canonical_bytes(),
        fetch=_fetcher(feeds or _feeds()),
        observed_at=_NOW,
    )


def test_exact_catalog_pass_is_redacted_canonical_and_zero_inference() -> None:
    configuration = _configuration()
    result = _audit()

    assert result["ok"] is True
    assert result["reason_codes"] == []
    assert result["configuration"]["configuration_sha256"] == (configuration.configuration_sha256)
    assert result["feeds"]["combined_sha256"]
    assert len(result["roles"]) == 4
    assert all(role["ok"] for role in result["roles"])
    assert result["network"] == {
        "official_origin": "https://openrouter.ai",
        "public_catalog_get_attempts": 5,
        "provider_inference_calls": 0,
        "credential_reads": 0,
        "authorization_headers_sent": False,
    }
    rendered = catalog._canonical_json(result)
    assert rendered == catalog._canonical_json(json.loads(rendered))
    assert b"secretref://" not in rendered
    assert b"generation-1" not in rendered


def test_base_slug_ambiguity_and_missing_exact_route_fail_closed() -> None:
    feeds = _feeds()
    orchestrator_url = catalog._model_endpoint_url(_MODELS["orchestrator"])
    feeds[orchestrator_url]["data"]["endpoints"].append(
        _endpoint(_MODELS["orchestrator"], "amazon-bedrock/us-east-1")
    )
    red_team_url = catalog._model_endpoint_url(_MODELS["red_team"])
    feeds[red_team_url]["data"]["endpoints"] = [_endpoint(_MODELS["red_team"], "digitalocean")]
    providers = dict(_PROVIDERS)
    providers["orchestrator"] = "amazon-bedrock"

    result = _audit(feeds, _configuration(providers))

    assert result["ok"] is False
    by_role = {role["role"]: role for role in result["roles"]}
    assert by_role["orchestrator"]["reason_codes"] == ["configured_provider_is_ambiguous"]
    assert by_role["red_team"]["reason_codes"] == ["configured_provider_has_no_candidate"]
    assert {"configured_provider_is_ambiguous", "configured_provider_has_no_candidate"} <= set(
        result["reason_codes"]
    )


def test_null_completion_bound_and_missing_parameter_are_blocking() -> None:
    feeds = _feeds()
    red_team_url = catalog._model_endpoint_url(_MODELS["red_team"])
    endpoint = feeds[red_team_url]["data"]["endpoints"][0]
    endpoint["max_completion_tokens"] = None
    endpoint["supported_parameters"].remove("structured_outputs")

    result = _audit(feeds)
    red_team = next(role for role in result["roles"] if role["role"] == "red_team")

    assert red_team["ok"] is False
    assert red_team["endpoint"]["max_completion_tokens"] is None
    assert red_team["endpoint"]["missing_required_parameters"] == ["structured_outputs"]
    assert {
        "endpoint_completion_bound_unavailable",
        "endpoint_required_parameters_missing",
    } <= set(red_team["reason_codes"])


def test_preflight_requires_the_configured_completion_token_parameter() -> None:
    feeds = _feeds()
    documentation_url = catalog._model_endpoint_url(_MODELS["documentation"])
    feeds[documentation_url]["data"]["endpoints"][0]["supported_parameters"] = [
        "max_tokens",
        "reasoning",
        "response_format",
        "structured_outputs",
    ]

    result = _audit(feeds)
    documentation = next(role for role in result["roles"] if role["role"] == "documentation")

    assert documentation["completion_token_parameter"] == "max_completion_tokens"
    assert documentation["endpoint"]["missing_required_parameters"] == ["max_completion_tokens"]
    assert "endpoint_required_parameters_missing" in documentation["reason_codes"]


def test_decimal_price_comparison_has_no_float_rounding_escape() -> None:
    feeds = _feeds()
    judge_url = catalog._model_endpoint_url(_MODELS["judge"])
    feeds[judge_url]["data"]["endpoints"][0]["pricing"]["prompt"] = "0.0000010000000000000000000001"

    result = _audit(feeds)
    judge = next(role for role in result["roles"] if role["role"] == "judge")

    assert judge["ok"] is False
    assert "endpoint_input_price_exceeds_ceiling" in judge["reason_codes"]
    assert judge["endpoint"]["observed_price_usd_per_million_tokens"]["input"] == (
        "1.0000000000000000000001"
    )


def test_nonzero_request_price_and_missing_zdr_membership_are_blocking() -> None:
    feeds = _feeds()
    documentation_url = catalog._model_endpoint_url(_MODELS["documentation"])
    feeds[documentation_url]["data"]["endpoints"][0]["pricing"]["request"] = "0.000001"
    feeds[catalog._ZDR_ENDPOINT_URL]["data"] = [
        entry
        for entry in feeds[catalog._ZDR_ENDPOINT_URL]["data"]
        if entry["model_id"] != _MODELS["documentation"]
    ]

    result = _audit(feeds)
    documentation = next(role for role in result["roles"] if role["role"] == "documentation")

    assert {
        "endpoint_request_price_nonzero",
        "endpoint_not_zdr_listed",
    } <= set(documentation["reason_codes"])


def test_public_feed_network_error_emits_only_redacted_failure() -> None:
    feeds = _feeds()
    judge_url = catalog._model_endpoint_url(_MODELS["judge"])
    feeds[judge_url] = OSError("network detail that must not escape")

    result = _audit(feeds)
    rendered = catalog._canonical_json(result)

    assert result["ok"] is False
    assert "public_feed_network_error" in result["reason_codes"]
    assert b"network detail" not in rendered
    assert result["network"]["provider_inference_calls"] == 0
    assert result["network"]["credential_reads"] == 0


def test_invalid_configuration_stops_before_any_public_get() -> None:
    calls: list[str] = []

    result = catalog.audit_catalog(
        b'{"schema_version":"2","roles":[],"global_limits":{}}',
        fetch=lambda url: calls.append(url) or b"{}",
        observed_at=_NOW,
    )

    assert result["ok"] is False
    assert result["reason_codes"] == ["configuration_invalid"]
    assert result["network"]["public_catalog_get_attempts"] == 0
    assert calls == []


def test_full_endpoint_tag_does_not_expand_to_nested_variants() -> None:
    assert catalog._configured_tag_matches("google-vertex", "google-vertex/global/priority")
    assert catalog._configured_tag_matches("google-vertex/global", "google-vertex/global")
    assert not catalog._configured_tag_matches(
        "google-vertex/global", "google-vertex/global/priority"
    )


def test_live_fetch_boundary_disables_auth_proxies_and_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    class Response:
        status_code = 200
        content = b'{"data":[]}'

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            observed["kwargs"] = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def get(self, url: str):
            observed["url"] = url
            return Response()

    monkeypatch.setattr(catalog.httpx, "Client", Client)
    result = catalog.fetch_public_feed(catalog._ZDR_ENDPOINT_URL)

    assert result == b'{"data":[]}'
    assert observed["url"] == "https://openrouter.ai/api/v1/endpoints/zdr"
    assert observed["kwargs"]["follow_redirects"] is False
    assert observed["kwargs"]["trust_env"] is False
    assert "Authorization" not in observed["kwargs"]["headers"]


def test_live_fetch_boundary_rejects_nonofficial_url_before_client_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        catalog.httpx,
        "Client",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("client constructed")),
    )

    with pytest.raises(catalog.CatalogPreflightError, match="non-canonical"):
        catalog.fetch_public_feed("https://example.invalid/api/v1/endpoints")


def test_cli_returns_four_and_writes_canonical_artifact_for_no_candidate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    feeds = _feeds()
    red_team_url = catalog._model_endpoint_url(_MODELS["red_team"])
    feeds[red_team_url]["data"]["endpoints"] = [_endpoint(_MODELS["red_team"], "digitalocean")]
    configuration_path = tmp_path / "configuration.json"
    output_path = tmp_path / "result.json"
    configuration_path.write_bytes(_configuration().canonical_bytes())
    mocked_fetch = _fetcher(feeds)
    monkeypatch.setattr(
        catalog,
        "fetch_public_feed",
        lambda url, **_kwargs: mocked_fetch(url),
    )
    monkeypatch.setattr(
        catalog.sys,
        "argv",
        [
            str(_SCRIPT),
            str(configuration_path),
            "--output",
            str(output_path),
        ],
    )

    assert catalog.main() == 4
    raw = output_path.read_bytes()
    result = json.loads(raw)
    assert raw == catalog._canonical_json(result) + b"\n"
    assert result["ok"] is False
    assert "configured_provider_has_no_candidate" in result["reason_codes"]
