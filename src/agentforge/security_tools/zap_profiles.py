"""Active (non-passive) ZAP scanning — SEPARATE from the passive-only ``zap.py``.

``zap.py`` is passive-only by invariant and must never construct an active-scan command. Real
active scanning (ZAP active rules, API fuzzing) is a materially higher-risk operation and lives
here, behind three hard gates that all fail closed:

1. **Authorization** — an ``active_scan_argv`` is built ONLY behind a verified
   :class:`ActiveScanAuthorization` whose bound operation hash equals the exact scope of the
   command. No grant, wrong scope, or expired grant → no command.
2. **Pinning** — the command uses the pinned ZAP image digest and a fixed Automation-Framework
   active-rule subset (by digest). The scope must have authorized those exact pinned digests, or
   the build refuses (a grant for a different image/rule set can never run these rules).
3. **Target deny-list** — :func:`validate_active_scan_target` denies identity-provider,
   cloud-metadata, private/loopback, non-https, credentialed, and non-approved origins, so an
   active scanner can never be turned into an SSRF or credential-theft primitive.

Constructing an argv does NOT run it. A live active scan runs only in the private Runner under a
separately minted, owner-authorized grant. Stdlib only; no Docker, no socket.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

from agentforge.security_tools.active_authorization import (
    ActiveScanAuthorization,
    ActiveScanAuthorizationError,
    ActiveScanScope,
)
from agentforge.security_tools.zap import (
    ZAP_AMD64_DIGEST,
    ZAP_IMAGE,
    ZAP_ISOLATED_NETWORK,
)

# The pinned ZAP image digest, as a bare 64-hex (the scope binds a hex digest, not a "sha256:" ref).
ACTIVE_ZAP_IMAGE_SHA256 = ZAP_AMD64_DIGEST.split(":", 1)[1]

# Identity-provider host fragments — an active scanner must never be pointed at the IdP.
_IDP_HOST_FRAGMENTS = (
    "clerk",
    "okta",
    "auth0",
    "login.microsoftonline.com",
    "accounts.google.com",
    "onelogin",
    "pingidentity",
)

# Cloud-metadata hosts (by name) — link-local metadata IPs are caught separately by ip class.
_METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata",
        "metadata.goog",
        "metadata.azure.com",
        "metadata.alibaba.com",
        "metadata.alibabacloud.com",
        "metadata.oraclecloud.com",
        "metadata.tencentyun.com",
    }
)

# Cloud-metadata IP literals NOT caught by is_link_local / is_private (e.g. Azure's DNS +
# wireserver 168.63.129.16). Belt-and-suspenders beyond the IP-class checks.
_METADATA_IPS = frozenset(
    {
        "169.254.169.254",  # AWS/GCP/Azure IMDS (also link-local)
        "168.63.129.16",  # Azure DNS / wireserver (public range — not private/link-local)
        "100.100.200.200",  # Alibaba Cloud metadata
    }
)


@dataclass(frozen=True, slots=True)
class ActiveScanRule:
    """One pinned ZAP active-scan rule in the authorized subset."""

    plugin_id: str
    name: str
    owasp_web: str
    strength: str = "medium"
    threshold: str = "medium"

    def payload(self) -> dict[str, str]:
        return {
            "plugin_id": self.plugin_id,
            "name": self.name,
            "owasp_web": self.owasp_web,
            "strength": self.strength,
            "threshold": self.threshold,
        }


# Destructive / DoS / crash-risk active-rule classes EXCLUDED by policy. The subset is
# injection/traversal/SSRF DETECTION only: buffer overflow (30001), format-string (30002), and
# integer-overflow (30003) send malformed payloads that can crash a fragile target (DoS), and
# no delete / auth-mutating / flood rule is ever included. Enforced by the assertion below + a test.
FORBIDDEN_ACTIVE_RULE_IDS = frozenset({"30001", "30002", "30003"})

# The fixed Automation-Framework active-rule subset. Curated for an LLM-facing web/API target and
# deliberately narrow — high-signal injection/SSRF/traversal classes, never the full destructive
# active policy. Pinned by digest so the grant authorizes exactly these rules and no others.
ACTIVE_SCAN_RULE_SUBSET: tuple[ActiveScanRule, ...] = (
    ActiveScanRule("40018", "SQL Injection", "A03:2021"),
    ActiveScanRule("40019", "SQL Injection - MySQL", "A03:2021"),
    ActiveScanRule("40012", "Cross Site Scripting (Reflected)", "A03:2021"),
    ActiveScanRule("40014", "Cross Site Scripting (Persistent)", "A03:2021"),
    ActiveScanRule("90020", "Remote OS Command Injection", "A03:2021"),
    ActiveScanRule("90019", "Server Side Code Injection", "A03:2021"),
    ActiveScanRule("40046", "Server Side Request Forgery", "A10:2021"),
    ActiveScanRule("6", "Path Traversal", "A01:2021"),
    ActiveScanRule("7", "Remote File Inclusion", "A03:2021"),
    ActiveScanRule("90034", "Cloud Metadata Potentially Exposed", "A05:2021"),
)


def _assert_rule_subset_is_non_destructive() -> None:
    offending = {rule.plugin_id for rule in ACTIVE_SCAN_RULE_SUBSET} & FORBIDDEN_ACTIVE_RULE_IDS
    if offending:
        raise AssertionError(
            f"active-rule subset includes forbidden destructive/DoS rules: {sorted(offending)}"
        )


_assert_rule_subset_is_non_destructive()


def active_scan_rule_subset_sha256() -> str:
    """Return the deterministic 64-hex digest of the pinned active-rule subset."""
    canonical = json.dumps(
        [rule.payload() for rule in ACTIVE_SCAN_RULE_SUBSET],
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _canonical_origin(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or not parsed.hostname
    ):
        raise ValueError("active-scan target must be a credential-free exact origin")
    if parsed.scheme != "https":
        raise ValueError("active-scan target must be https")
    return url.rstrip("/")


def validate_active_scan_target(origin: str, *, approved_origin: str) -> str:
    """Return the exact permitted origin or reject before any active command can be constructed.

    Fail-closed deny-list (defense in depth around the exact-origin match): identity providers,
    cloud-metadata endpoints, private/loopback/link-local/reserved IP literals, non-https,
    credentialed, and any origin other than the owner-approved one.
    """
    normalized = _canonical_origin(origin)
    hostname = urlsplit(normalized).hostname or ""
    host = hostname.rstrip(".").lower()

    if any(fragment in host for fragment in _IDP_HOST_FRAGMENTS):
        raise ValueError("identity-provider origins are outside active-scan scope")
    if host in _METADATA_HOSTS or host in _METADATA_IPS:
        raise ValueError("cloud-metadata endpoints are outside active-scan scope")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if address.is_link_local:
            # 169.254.0.0/16 (incl. the 169.254.169.254 metadata address) and fe80::/10.
            raise ValueError("link-local / cloud-metadata addresses are outside active-scan scope")
        if (
            address.is_loopback
            or address.is_private
            or address.is_reserved
            or address.is_unspecified
        ):
            raise ValueError("private/loopback/internal addresses are outside active-scan scope")

    approved = _canonical_origin(approved_origin)
    if normalized != approved:
        raise ValueError("active scans require the exact owner-approved origin")
    return normalized


def _rule_config_options() -> str:
    """A deterministic ZAP options string enabling ONLY the pinned subset (default policy off)."""
    parts = ["-config ascan.policy.default.enabled=false"]
    for rule in ACTIVE_SCAN_RULE_SUBSET:
        parts.append(f"-config ascan.policy.{rule.plugin_id}.enabled=true")
        parts.append(f"-config ascan.policy.{rule.plugin_id}.strength={rule.strength}")
        parts.append(f"-config ascan.policy.{rule.plugin_id}.threshold={rule.threshold}")
    return " ".join(parts)


def active_scan_argv(
    scope: ActiveScanScope,
    authorization: ActiveScanAuthorization | None,
    *,
    approved_origin: str,
    openapi_spec_url: str,
    report_path: str,
    now: float,
) -> tuple[str, ...]:
    """Construct a pinned, isolated ACTIVE ZAP command — only behind a verified grant.

    Order (all fail-closed): verify the grant against the scope's own operation hash → require the
    scope to have authorized the pinned image + rule-subset digests → validate the target origin
    and the OpenAPI spec origin against the deny-list and the exact approved origin. Only then is
    the argv built. Nothing is executed here.
    """
    ActiveScanAuthorization.verify_optional(
        authorization,
        operation_hash=scope.operation_hash(),
        scope_nonce=scope.scope_nonce,
        now=now,
    )
    if scope.image_sha256 != ACTIVE_ZAP_IMAGE_SHA256:
        raise ActiveScanAuthorizationError(
            "active-scan scope did not authorize the pinned ZAP image digest (fail closed)"
        )
    if active_scan_rule_subset_sha256() not in scope.rule_sha256s:
        raise ActiveScanAuthorizationError(
            "active-scan scope did not authorize the pinned active-rule subset (fail closed)"
        )

    origin = validate_active_scan_target(scope.origin, approved_origin=approved_origin)
    # Compare full authority (host:port), not just the hostname, so a spec served from a
    # non-standard port on the approved host cannot slip through and become an SSRF primitive.
    spec = urlsplit(openapi_spec_url)
    origin_parts = urlsplit(origin)
    if (
        spec.scheme != "https"
        or spec.username
        or spec.password
        or spec.netloc.lower() != origin_parts.netloc.lower()
    ):
        raise ValueError("the OpenAPI spec must be served from the exact approved origin")

    minutes = max(1, int(scope.caps.max_duration_seconds // 60))
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
        "zap-api-scan.py",
        "-t",
        openapi_spec_url,
        "-f",
        "openapi",
        "-J",
        report_path,
        "-T",
        str(minutes),
        "-z",
        _rule_config_options(),
    )


__all__ = [
    "ACTIVE_SCAN_RULE_SUBSET",
    "ACTIVE_ZAP_IMAGE_SHA256",
    "FORBIDDEN_ACTIVE_RULE_IDS",
    "ActiveScanRule",
    "active_scan_argv",
    "active_scan_rule_subset_sha256",
    "validate_active_scan_target",
]
