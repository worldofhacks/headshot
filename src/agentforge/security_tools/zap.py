"""Exact-origin policy and pinned command construction for passive ZAP scans."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Any
from urllib.parse import urlsplit

from agentforge.security_tools.normalization import NormalizationContext, normalize_fixture_findings

ZAP_VERSION = "2.17.0"
ZAP_AMD64_DIGEST = "sha256:c558ee87358911ab17278c70991e856f57793e115d9cd0f88ca475cf82907a1a"
ZAP_IMAGE = f"ghcr.io/zaproxy/zaproxy@{ZAP_AMD64_DIGEST}"
ZAP_MAX_REPORTED_REQUESTS = 200
ZAP_ISOLATED_NETWORK = "agentforge-zap-isolated"
ZAP_FAKE_TARGET_HOST = "agentforge-zap-fake"

# Stable ZAP plugin IDs mapped to the repository's OWASP Web 2021 anchor. Unknown alerts remain
# visible under insecure design; they never silently disappear from normalization.
_OWASP_WEB_BY_PLUGIN = {
    "6": "A01:2021",  # path traversal
    "7": "A03:2021",  # remote file inclusion
    "10010": "A05:2021",  # cookie missing secure attribute
    "10020": "A05:2021",  # anti-clickjacking header
    "10021": "A05:2021",  # X-Content-Type-Options
    "10038": "A05:2021",  # content security policy
    "40012": "A03:2021",  # reflected XSS
    "40018": "A03:2021",  # SQL injection
    "40046": "A10:2021",  # server-side request forgery
    "90019": "A03:2021",  # server-side code injection
}
_SEVERITY_BY_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}
_CONFIDENCE = {"0": 0.25, "1": 0.5, "2": 0.75, "3": 0.95, "4": 1.0}


def validate_zap_origin(
    origin: str,
    *,
    profile: str,
    approved_origin: str | None = None,
    authorization_ref: str | None = None,
) -> str:
    """Return an exact permitted origin or reject before ZAP can open a socket."""
    parsed = urlsplit(origin)
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or not parsed.hostname
    ):
        raise ValueError("ZAP target must be a credential-free exact origin")
    hostname = parsed.hostname.rstrip(".").lower()
    if "clerk" in hostname:
        raise ValueError("identity-provider origins are outside ZAP scope")
    try:
        is_loopback = ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        is_loopback = hostname == "localhost"

    if profile == "local_fake":
        if parsed.scheme != "http" or (not is_loopback and hostname != ZAP_FAKE_TARGET_HOST):
            raise ValueError("local_fake ZAP scans require loopback or the isolated fake target")
    elif profile == "platform_staging":
        if parsed.scheme != "https" or is_loopback or origin != approved_origin:
            raise ValueError("platform_staging ZAP scans require the approved HTTPS origin")
    elif profile == "live_target":
        if (
            parsed.scheme != "https"
            or origin != approved_origin
            or not authorization_ref
            or len(authorization_ref) < 8
        ):
            raise ValueError("live_target ZAP scans require exact approval and authorization")
    else:
        raise ValueError("unsupported ZAP scan profile")
    return origin.rstrip("/")


def passive_baseline_argv(origin: str, report_path: str) -> tuple[str, ...]:
    """Construct a passive baseline command; never construct an active-scan command."""
    return (
        "docker",
        "run",
        "--rm",
        f"--network={ZAP_ISOLATED_NETWORK}",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=256",
        "--memory=2g",
        "--cpus=2",
        ZAP_IMAGE,
        "zap-baseline.py",
        "-t",
        origin,
        "-J",
        report_path,
        "-m",
        "1",
        "-T",
        "2",
        "-z",
        "-config spider.maxDuration=1 -config spider.maxDepth=5 "
        "-config spider.maxChildren=10 -config scanner.threadPerHost=1",
    )


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError("ZAP alert contains an invalid URL")
    default_port = (parsed.scheme == "https" and parsed.port in {None, 443}) or (
        parsed.scheme == "http" and parsed.port in {None, 80}
    )
    authority = (
        parsed.hostname.lower() if default_port else f"{parsed.hostname.lower()}:{parsed.port}"
    )
    return f"{parsed.scheme.lower()}://{authority}"


def normalize_zap(
    raw: bytes,
    context: NormalizationContext,
    *,
    approved_origin: str,
) -> list[dict[str, Any]]:
    """Normalize ZAP JSON and fail closed if any reported request escaped the exact origin."""
    try:
        document = json.loads(raw)
        sites = document["site"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError("malformed ZAP JSON artifact") from exc
    if not isinstance(sites, list):
        raise ValueError("ZAP sites must be an array")
    approved = _origin(approved_origin)
    findings: list[dict[str, Any]] = []
    reported_requests = 0
    for site_index, site in enumerate(sites):
        alerts = site.get("alerts") if isinstance(site, dict) else None
        if not isinstance(alerts, list):
            raise ValueError(f"malformed ZAP site at index {site_index}")
        for alert_index, alert in enumerate(alerts):
            try:
                plugin_id = str(alert["pluginid"])
                instances = alert.get("instances", [])
                if not isinstance(instances, list):
                    raise TypeError
                reported_requests += len(instances)
                if reported_requests > ZAP_MAX_REPORTED_REQUESTS:
                    raise ValueError("ZAP report exceeds the strict request cap")
                for instance in instances:
                    if _origin(instance["uri"]) != approved:
                        raise ValueError("ZAP report proves an exact-origin scope escape")
                risk = str(alert["riskcode"])
                confidence = str(alert.get("confidence", "2"))
                findings.append(
                    {
                        "id": f"{plugin_id}:{site_index}:{alert_index}",
                        "severity": _SEVERITY_BY_RISK[risk],
                        "confidence": _CONFIDENCE[confidence],
                        "owasp_mappings": [_OWASP_WEB_BY_PLUGIN.get(plugin_id, "A04:2021")],
                        "summary": f"ZAP plugin {plugin_id}: {alert['alert']}",
                        "disposition": "validate",
                    }
                )
            except (KeyError, TypeError) as exc:
                raise ValueError(
                    f"malformed ZAP alert at site {site_index}, index {alert_index}"
                ) from exc
    return normalize_fixture_findings(
        json.dumps({"findings": findings}, sort_keys=True, separators=(",", ":")).encode(),
        context,
        raw_artifact_sha256=hashlib.sha256(raw).hexdigest(),
    )
