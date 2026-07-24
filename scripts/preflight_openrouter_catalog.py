#!/usr/bin/env python3
"""Credential-free OpenRouter catalog preflight for one hosted configuration set.

This command performs GET requests only against OpenRouter's public model-endpoint and ZDR
catalogs. It never reads an API key, sends an Authorization header, or calls a completion API.

Input is the canonical JSON payload returned by
``HostedConfigurationSet.canonical_payload()``. ``-`` reads that JSON from standard input:

    python scripts/preflight_openrouter_catalog.py hosted-configuration.json \
      --output openrouter-catalog-preflight.json

The emitted JSON is canonical, redacted, and content-addressable. Exit status is zero only when
all four roles resolve to exactly one healthy, ZDR-listed endpoint whose advertised capabilities,
limits, and prices cover the release's server-owned hosted generation policy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from decimal import Decimal, DecimalException, Inexact, InvalidOperation, Rounded, localcontext
from pathlib import Path
from typing import Any

import httpx

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedRoleConfiguration,
    validate_hosted_configuration_set,
)
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY

_SCHEMA_VERSION = "headshot-openrouter-catalog-preflight-v1"
_REQUEST_CONTRACT_VERSION = "openrouter-chat-json-schema-reasoning-v1"
_OPENROUTER_ORIGIN = "https://openrouter.ai"
_MODEL_ENDPOINT_ROOT = f"{_OPENROUTER_ORIGIN}/api/v1/models"
_ZDR_ENDPOINT_URL = f"{_OPENROUTER_ORIGIN}/api/v1/endpoints/zdr"
_REQUIRED_PARAMETERS = frozenset(
    {"max_tokens", "reasoning", "response_format", "structured_outputs"}
)
_MAX_INPUT_BYTES = 1_000_000
_MAX_FEED_BYTES = 10_000_000
_MILLION = Decimal("1000000")

FetchBytes = Callable[[str], bytes]


class CatalogPreflightError(RuntimeError):
    """The local preflight input or public catalog response was unusable."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decimal_text(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonstandard_number(value: str) -> None:
    raise ValueError(f"non-standard JSON number: {value}")


def _strict_json(raw: bytes) -> Any:
    if len(raw) > _MAX_FEED_BYTES:
        raise ValueError("JSON input exceeds the closed size limit")
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_nonstandard_number,
    )


def _model_endpoint_url(model_id: str) -> str:
    # HostedConfigurationSet has already constrained this to one lowercase author/model pair.
    return f"{_MODEL_ENDPOINT_ROOT}/{model_id}/endpoints"


def _configured_tag_matches(configured: str, observed: str) -> bool:
    # OpenRouter documents base-slug expansion only for the provider name. Once a slash is
    # supplied, it is a full endpoint tag and must match exactly.
    if "/" in configured:
        return observed == configured
    return observed == configured or observed.startswith(f"{configured}/")


def _positive_int(value: object) -> int | None:
    if type(value) is not int or value <= 0:
        return None
    return value


def _price_per_million(value: object) -> Decimal:
    if not isinstance(value, str) or not value:
        raise ValueError("catalog price must be a non-empty decimal string")
    try:
        price = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("catalog price is not decimal") from exc
    if not price.is_finite() or price < 0:
        raise ValueError("catalog price must be finite and non-negative")
    parts = price.as_tuple()
    return Decimal((parts.sign, parts.digits, parts.exponent + 6))


def _reservation_ceiling(
    configured_prices: Mapping[str, Decimal],
    *,
    input_tokens: int,
    output_tokens: int,
    reasoning_tokens: int,
) -> Decimal:
    # Authority values must never inherit the process-wide Decimal context. A closed precision
    # bound plus Inexact/Rounded traps turns an unusually precise or hostile configuration into
    # a typed fail-closed result instead of silently rounding it.
    with localcontext() as context:
        context.prec = 256
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        return (
            configured_prices["input"] * input_tokens
            + configured_prices["output"] * output_tokens
            + max(configured_prices["output"], configured_prices["reasoning"]) * reasoning_tokens
        ) / _MILLION


def _endpoint_prices(
    pricing: object,
    *,
    input_token_bound: int,
) -> dict[str, Decimal]:
    if not isinstance(pricing, Mapping):
        raise ValueError("endpoint pricing is unavailable")
    prompt = _price_per_million(pricing.get("prompt"))
    completion = _price_per_million(pricing.get("completion"))
    internal_reasoning_raw = pricing.get("internal_reasoning")
    reasoning = (
        completion if internal_reasoning_raw is None else _price_per_million(internal_reasoning_raw)
    )
    request_raw = pricing.get("request")
    request = Decimal(0) if request_raw is None else _price_per_million(request_raw)

    overrides = pricing.get("overrides", [])
    if not isinstance(overrides, list):
        raise ValueError("endpoint pricing overrides are invalid")
    applicable: list[tuple[int, Mapping[str, Any]]] = []
    for override in overrides:
        if not isinstance(override, Mapping):
            raise ValueError("endpoint pricing override is invalid")
        threshold = _positive_int(override.get("min_prompt_tokens"))
        if threshold is None:
            raise ValueError("endpoint pricing override threshold is invalid")
        if threshold <= input_token_bound:
            applicable.append((threshold, override))
    for _, override in sorted(applicable, key=lambda item: item[0]):
        if "prompt" in override:
            prompt = _price_per_million(override["prompt"])
        if "completion" in override:
            completion = _price_per_million(override["completion"])
        if "internal_reasoning" in override:
            reasoning = _price_per_million(override["internal_reasoning"])
        elif "completion" in override:
            reasoning = completion
        if "request" in override:
            request = _price_per_million(override["request"])
    return {
        "input": prompt,
        "output": completion,
        "reasoning": reasoning,
        "request": request,
    }


def _feed_snapshot(url: str, fetch: FetchBytes) -> dict[str, Any]:
    try:
        raw = fetch(url)
    except Exception:  # noqa: BLE001 - external failures collapse to a redacted reason code
        return {
            "ok": False,
            "url": url,
            "canonical_sha256": None,
            "payload": None,
            "reason_code": "public_feed_network_error",
        }
    if not isinstance(raw, bytes):
        return {
            "ok": False,
            "url": url,
            "canonical_sha256": None,
            "payload": None,
            "reason_code": "public_feed_invalid",
        }
    try:
        payload = _strict_json(raw)
        canonical = _canonical_json(payload)
    except (UnicodeDecodeError, TypeError, ValueError):
        return {
            "ok": False,
            "url": url,
            "canonical_sha256": None,
            "payload": None,
            "reason_code": "public_feed_invalid",
        }
    return {
        "ok": True,
        "url": url,
        "canonical_sha256": _sha256(canonical),
        "payload": payload,
        "reason_code": None,
    }


def _parse_model_endpoints(snapshot: Mapping[str, Any], model_id: str) -> list[Mapping[str, Any]]:
    payload = snapshot.get("payload")
    if not isinstance(payload, Mapping):
        raise ValueError("model feed payload is unavailable")
    data = payload.get("data")
    if not isinstance(data, Mapping) or data.get("id") != model_id:
        raise ValueError("model feed identity differs from the requested exact model")
    endpoints = data.get("endpoints")
    if not isinstance(endpoints, list) or any(
        not isinstance(endpoint, Mapping) for endpoint in endpoints
    ):
        raise ValueError("model endpoint list is invalid")
    return endpoints


def _parse_zdr_endpoints(snapshot: Mapping[str, Any]) -> set[tuple[str, str]]:
    payload = snapshot.get("payload")
    if not isinstance(payload, Mapping) or not isinstance(payload.get("data"), list):
        raise ValueError("ZDR feed payload is invalid")
    result: set[tuple[str, str]] = set()
    for endpoint in payload["data"]:
        if not isinstance(endpoint, Mapping):
            raise ValueError("ZDR endpoint entry is invalid")
        model_id = endpoint.get("model_id")
        tag = endpoint.get("tag")
        if not isinstance(model_id, str) or not model_id:
            raise ValueError("ZDR endpoint model identity is invalid")
        if not isinstance(tag, str) or not tag:
            raise ValueError("ZDR endpoint tag is invalid")
        result.add((model_id, tag))
    return result


def _role_result(
    role: HostedRoleConfiguration,
    *,
    endpoint_snapshot: Mapping[str, Any],
    zdr_endpoints: set[tuple[str, str]] | None,
    privacy_feed_ok: bool,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    result: dict[str, Any] = {
        "role": role.role,
        "model_id": role.model_id,
        "configured_provider_slug": role.upstream_provider,
        "role_configuration_sha256": role.configuration_sha256,
        "match_count": 0,
        "matched_endpoint_tags": [],
        "endpoint": None,
        "ok": False,
        "reason_codes": reason_codes,
    }
    if not endpoint_snapshot.get("ok"):
        reason_codes.append(str(endpoint_snapshot["reason_code"]))
        return result
    try:
        endpoints = _parse_model_endpoints(endpoint_snapshot, role.model_id)
    except ValueError:
        reason_codes.append("model_feed_contract_invalid")
        return result

    matched = [
        endpoint
        for endpoint in endpoints
        if isinstance(endpoint.get("tag"), str)
        and _configured_tag_matches(role.upstream_provider, endpoint["tag"])
    ]
    matched_tags = sorted(str(endpoint["tag"]) for endpoint in matched)
    result["match_count"] = len(matched)
    result["matched_endpoint_tags"] = matched_tags
    if not matched:
        reason_codes.append("configured_provider_has_no_candidate")
        return result
    if len(matched) != 1:
        reason_codes.append("configured_provider_is_ambiguous")
        return result

    endpoint = matched[0]
    tag = str(endpoint["tag"])
    status = endpoint.get("status")
    context_length = _positive_int(endpoint.get("context_length"))
    max_completion_tokens = _positive_int(endpoint.get("max_completion_tokens"))
    supported = endpoint.get("supported_parameters")
    supported_set = (
        {parameter for parameter in supported if isinstance(parameter, str)}
        if isinstance(supported, list)
        else set()
    )
    missing_parameters = sorted(_REQUIRED_PARAMETERS - supported_set)
    call_bounds = DEFAULT_HOSTED_GENERATION_POLICY.call_bounds[role.role]
    requested_completion_tokens = call_bounds.output_tokens + call_bounds.reasoning_tokens

    if type(status) is not int or status != 0:
        reason_codes.append("endpoint_status_not_ready")
    if context_length is None:
        reason_codes.append("endpoint_context_bound_unavailable")
    elif call_bounds.input_tokens + requested_completion_tokens > context_length:
        reason_codes.append("endpoint_context_bound_too_small")
    if max_completion_tokens is None:
        reason_codes.append("endpoint_completion_bound_unavailable")
    elif requested_completion_tokens > max_completion_tokens:
        reason_codes.append("endpoint_completion_bound_too_small")
    if missing_parameters:
        reason_codes.append("endpoint_required_parameters_missing")

    limits = role.limits
    if (
        call_bounds.input_tokens > limits.max_input_tokens
        or call_bounds.output_tokens > limits.max_output_tokens
        or call_bounds.reasoning_tokens > limits.max_reasoning_tokens
    ):
        reason_codes.append("configured_role_limits_below_call_bounds")

    prices: dict[str, Decimal] | None = None
    try:
        prices = _endpoint_prices(
            endpoint.get("pricing"),
            input_token_bound=call_bounds.input_tokens,
        )
    except ValueError:
        reason_codes.append("endpoint_price_unavailable")
    configured_prices = {
        "input": role.prices.input_usd_per_million_tokens,
        "output": role.prices.output_usd_per_million_tokens,
        "reasoning": role.prices.reasoning_usd_per_million_tokens,
    }
    if prices is not None:
        if prices["request"] != 0:
            reason_codes.append("endpoint_request_price_nonzero")
        if prices["input"] > configured_prices["input"]:
            reason_codes.append("endpoint_input_price_exceeds_ceiling")
        if prices["output"] > configured_prices["output"]:
            reason_codes.append("endpoint_output_price_exceeds_ceiling")
        if prices["reasoning"] > configured_prices["reasoning"]:
            reason_codes.append("endpoint_reasoning_price_exceeds_ceiling")

    reservation_ceiling: Decimal | None
    try:
        reservation_ceiling = _reservation_ceiling(
            configured_prices,
            input_tokens=call_bounds.input_tokens,
            output_tokens=call_bounds.output_tokens,
            reasoning_tokens=call_bounds.reasoning_tokens,
        )
    except DecimalException:
        reservation_ceiling = None
        reason_codes.append("configured_price_arithmetic_unrepresentable")
    if reservation_ceiling is not None and reservation_ceiling > role.limits.max_usd:
        reason_codes.append("role_usd_cap_below_single_call_reservation")

    zdr_listed = zdr_endpoints is not None and (role.model_id, tag) in zdr_endpoints
    if not privacy_feed_ok:
        reason_codes.append("privacy_feed_unavailable")
    elif not zdr_listed:
        reason_codes.append("endpoint_not_zdr_listed")

    endpoint_result: dict[str, Any] = {
        "tag": tag,
        "provider_name": (
            endpoint.get("provider_name")
            if isinstance(endpoint.get("provider_name"), str)
            else None
        ),
        "status": status if type(status) is int else None,
        "uptime_last_30m": endpoint.get("uptime_last_30m"),
        "context_length": context_length,
        "max_completion_tokens": max_completion_tokens,
        "requested_completion_tokens": requested_completion_tokens,
        "missing_required_parameters": missing_parameters,
        "zdr_listed": zdr_listed,
        "configured_price_ceiling_usd_per_million_tokens": {
            key: _decimal_text(value) for key, value in configured_prices.items()
        },
        "observed_price_usd_per_million_tokens": (
            {key: _decimal_text(value) for key, value in prices.items() if key != "request"}
            if prices is not None
            else None
        ),
        "reservation_ceiling_usd": (
            _decimal_text(reservation_ceiling) if reservation_ceiling is not None else None
        ),
        "role_max_usd": _decimal_text(role.limits.max_usd),
    }
    result["endpoint"] = endpoint_result
    reason_codes.sort()
    result["ok"] = not reason_codes
    return result


def audit_catalog(
    configuration_raw: bytes,
    *,
    fetch: FetchBytes,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Return one canonicalizable redacted audit; no exception includes configuration content."""

    generated = observed_at or datetime.now(UTC)
    if generated.tzinfo is None or generated.utcoffset() is None:
        raise ValueError("observed_at must be timezone-aware")
    generated_text = generated.astimezone(UTC).isoformat().replace("+00:00", "Z")
    configuration_file_sha256 = _sha256(configuration_raw)
    try:
        payload = _strict_json(configuration_raw)
        configuration = HostedConfigurationSet.from_payload(payload)
        validate_hosted_configuration_set(configuration)
    except (TypeError, ValueError):
        return {
            "schema_version": _SCHEMA_VERSION,
            "observed_at": generated_text,
            "ok": False,
            "reason_codes": ["configuration_invalid"],
            "configuration": {
                "input_sha256": configuration_file_sha256,
                "configuration_sha256": None,
                "schema_version": None,
                "generation_policy_sha256": (DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256),
            },
            "request_contract": _request_contract(),
            "feeds": {"combined_sha256": None, "models": {}, "privacy": None},
            "roles": [],
            "network": _network_summary(public_get_attempts=0),
        }

    snapshots: dict[str, dict[str, Any]] = {}
    for role in configuration.roles:
        if role.model_id not in snapshots:
            url = _model_endpoint_url(role.model_id)
            snapshots[role.model_id] = _feed_snapshot(url, fetch)
    privacy_snapshot = _feed_snapshot(_ZDR_ENDPOINT_URL, fetch)
    privacy_feed_ok = bool(privacy_snapshot["ok"])
    try:
        zdr_endpoints = _parse_zdr_endpoints(privacy_snapshot) if privacy_feed_ok else None
    except ValueError:
        privacy_feed_ok = False
        zdr_endpoints = None
        privacy_snapshot["ok"] = False
        privacy_snapshot["reason_code"] = "public_feed_invalid"

    roles = [
        _role_result(
            role,
            endpoint_snapshot=snapshots[role.model_id],
            zdr_endpoints=zdr_endpoints,
            privacy_feed_ok=privacy_feed_ok,
        )
        for role in configuration.roles
    ]
    feed_reason_codes = {
        str(snapshot["reason_code"])
        for snapshot in (*snapshots.values(), privacy_snapshot)
        if not snapshot["ok"] and snapshot["reason_code"] is not None
    }
    reason_codes = sorted(
        feed_reason_codes | {code for role in roles for code in role["reason_codes"]}
    )
    feed_hashes = {
        "models": {
            model_id: snapshot["canonical_sha256"]
            for model_id, snapshot in sorted(snapshots.items())
        },
        "privacy": privacy_snapshot["canonical_sha256"],
    }
    combined_sha256 = _sha256(_canonical_json(feed_hashes))
    public_get_attempts = len(snapshots) + 1
    return {
        "schema_version": _SCHEMA_VERSION,
        "observed_at": generated_text,
        "ok": not feed_reason_codes and all(role["ok"] for role in roles),
        "reason_codes": reason_codes,
        "configuration": {
            "input_sha256": configuration_file_sha256,
            "configuration_sha256": configuration.configuration_sha256,
            "schema_version": configuration.schema_version,
            "generation_policy_sha256": (DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256),
        },
        "request_contract": _request_contract(),
        "feeds": {
            "combined_sha256": combined_sha256,
            "models": {
                model_id: _redacted_snapshot(snapshot)
                for model_id, snapshot in sorted(snapshots.items())
            },
            "privacy": _redacted_snapshot(privacy_snapshot),
        },
        "roles": roles,
        "network": _network_summary(public_get_attempts=public_get_attempts),
    }


def _request_contract() -> dict[str, Any]:
    return {
        "version": _REQUEST_CONTRACT_VERSION,
        "api_route": "/api/v1/chat/completions",
        "provider_fallbacks_allowed": False,
        "required_parameters": sorted(_REQUIRED_PARAMETERS),
        "structured_output_type": "json_schema",
        "privacy_requirement": "public_zdr_registry_membership",
    }


def _network_summary(*, public_get_attempts: int) -> dict[str, Any]:
    return {
        "official_origin": _OPENROUTER_ORIGIN,
        "public_catalog_get_attempts": public_get_attempts,
        "provider_inference_calls": 0,
        "credential_reads": 0,
        "authorization_headers_sent": False,
    }


def _redacted_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "url": snapshot["url"],
        "ok": snapshot["ok"],
        "canonical_sha256": snapshot["canonical_sha256"],
        "reason_code": snapshot["reason_code"],
    }


def fetch_public_feed(url: str, *, timeout_seconds: float = 10.0) -> bytes:
    """Fetch one fixed official public feed without redirects, proxies, auth, or credentials."""

    if (
        not isinstance(url, str)
        or not url.startswith(f"{_OPENROUTER_ORIGIN}/api/v1/")
        or "@" in url
        or "?" in url
        or "#" in url
    ):
        raise CatalogPreflightError("refusing a non-canonical public catalog URL")
    with httpx.Client(
        follow_redirects=False,
        timeout=timeout_seconds,
        trust_env=False,
        headers={
            "Accept": "application/json",
            "User-Agent": "Headshot-OpenRouter-Catalog-Preflight/1",
        },
    ) as client:
        response = client.get(url)
    if response.status_code != 200:
        raise CatalogPreflightError("public catalog returned a non-success status")
    content = response.content
    if len(content) > _MAX_FEED_BYTES:
        raise CatalogPreflightError("public catalog exceeded the closed size limit")
    return content


def _read_configuration(path: str) -> bytes:
    raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1) if path == "-" else Path(path).read_bytes()
    if not raw or len(raw) > _MAX_INPUT_BYTES:
        raise CatalogPreflightError("configuration input is empty or too large")
    return raw


def _write_result(path: str, result: Mapping[str, Any]) -> None:
    rendered = _canonical_json(result) + b"\n"
    if path == "-":
        sys.stdout.buffer.write(rendered)
        return
    Path(path).write_bytes(rendered)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "configuration",
        help="HostedConfigurationSet canonical JSON file, or '-' for standard input",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="canonical redacted result path (default: standard output)",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=10.0,
        help="per-public-feed GET timeout (default: 10)",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    if (
        isinstance(args.timeout_seconds, bool)
        or not isinstance(args.timeout_seconds, float)
        or not (0 < args.timeout_seconds <= 30)
    ):
        raise SystemExit("--timeout-seconds must be greater than zero and at most 30")
    try:
        raw = _read_configuration(args.configuration)
    except (CatalogPreflightError, OSError):
        raise SystemExit("catalog preflight could not read the configuration input") from None
    result = audit_catalog(
        raw,
        fetch=lambda url: fetch_public_feed(
            url,
            timeout_seconds=args.timeout_seconds,
        ),
    )
    try:
        _write_result(args.output, result)
    except OSError:
        raise SystemExit("catalog preflight could not write its redacted result") from None
    return 0 if result["ok"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
