"""Runnable active-scan entrypoint (``python -m agentforge.security_tools.active_scan_run``).

Run one bounded governed active scan. Three modes, all owner-driven and fail-closed:

* ``--print-template`` — print the ActiveScanAuthorization/Scope/Caps schema PLUS a
  fill-in-the-blanks template (no secrets) for the owner to author;
* ``--mint --config PLAN.json`` — compute the ``operation_hash`` for the authored scope, which the
  owner pastes into the plan's ``authorization`` block with a deadline (the approval step);
* ``--config PLAN.json`` (default) — run ONE bounded governed active scan: zero-call preflight ->
  GovernedScanEgress driven with the real BoundedHttpsSender -> scanner<->permit<->send<->ledger
  parity + per-tool evidence, printed as JSON.

The run is default-disabled: without ``AGENTFORGE_ACTIVE_SCAN_ENABLED`` (checked by the sender) and
a valid, unexpired, in-scope grant, it refuses before any send. The SID is resolved ONLY via the
sealed ``secretref`` binding inside the sender and never appears in the config, argv, or report.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentforge.policy.scoped_credentials import SealedEnvironmentCredentialResolver
from agentforge.security_tools.active_authorization import (
    ActiveScanAuthorization,
    ActiveScanCaps,
    ActiveScanScope,
)
from agentforge.security_tools.active_preflight import active_scan_preflight
from agentforge.security_tools.api_discovery import discover_openapi
from agentforge.security_tools.scan_egress import GovernedScanEgress, ScanEgressAbort
from agentforge.security_tools.scan_sender import (
    ACTIVE_SCAN_ENABLED_ENV,
    ActiveScanSendError,
    BoundedHttpsSender,
)
from agentforge.security_tools.tool_runtime import ToolExecutionEvidence
from agentforge.security_tools.zap_profiles import (
    ACTIVE_ZAP_IMAGE_SHA256,
    active_scan_rule_subset_sha256,
)


def build_scope(spec: Mapping[str, Any]) -> ActiveScanScope:
    caps = ActiveScanCaps.parse(**spec["caps"])
    return ActiveScanScope(
        origin=spec["origin"],
        http_methods=tuple(spec["http_methods"]),
        path_patterns=tuple(spec["path_patterns"]),
        principals=tuple(spec["principals"]),
        image_sha256=spec["image_sha256"],
        addon_sha256s=tuple(spec["addon_sha256s"]),
        rule_sha256s=tuple(spec["rule_sha256s"]),
        callback_domains=tuple(spec["callback_domains"]),
        caps=caps,
        scope_nonce=spec["scope_nonce"],
    )


def build_authorization(spec: Mapping[str, Any]) -> ActiveScanAuthorization:
    return ActiveScanAuthorization(
        operation_hash=spec["operation_hash"],
        scope_nonce=spec["scope_nonce"],
        deadline=float(spec["deadline"]),
    )


def mint_operation_hash(config: Mapping[str, Any]) -> str:
    """Compute the content-addressed operation hash for the authored scope (the owner signs it)."""
    return build_scope(config["scope"]).operation_hash()


def active_scan_schema() -> dict[str, Any]:
    """Human-readable schema: which fields the OWNER supplies for the grant."""
    return {
        "scope.origin": "str — the EXACT owner-approved https origin (scheme+host[:port]).",
        "scope.http_methods": "list[str] — methods the scan may issue (non-mutating unless ok).",
        "scope.path_patterns": "list[str] — allowed URL path globs (e.g. /api/x, /api/x/*).",
        "scope.principals": "list[str] — provisioned SYNTHETIC principals (start 'synthetic-').",
        "scope.image_sha256": "str(64hex) — pinned ZAP image digest (ACTIVE_ZAP_IMAGE_SHA256).",
        "scope.addon_sha256s": "list[str(64hex)] — pinned scanner addon digests.",
        "scope.rule_sha256s": "list[str(64hex)] — MUST include active_scan_rule_subset_sha256().",
        "scope.callback_domains": "list[str] — private OAST domains, or [] to keep OAST disabled.",
        "scope.caps": "obj — max_requests / requests_per_second / max_duration_seconds / findings.",
        "scope.scope_nonce": "str — a fresh random nonce for this single scan instance.",
        "authorization.operation_hash": "str(64hex) — run '--mint' to compute from the scope.",
        "authorization.scope_nonce": "str — same as scope.scope_nonce.",
        "authorization.deadline": "float — expiry as epoch seconds (a bounded window).",
        "approved_origin": "str — the exact owner-approved origin (equals scope.origin).",
        "openapi": "obj — the target OpenAPI schema (paths are intersected with scope).",
        "auth_matrix_entries": "list[[principal, auth_mode, credential_ref|null]] — >=1 entry.",
        "credential_ref": "str|null — a secretref:// handle ONLY (never a secret value).",
        "auth_header": "str — the header the SID is injected under (e.g. 'Cookie').",
    }


def active_scan_template() -> dict[str, Any]:
    """A fill-in-the-blanks plan (NO secrets) the owner authors, mints, approves, and runs."""
    return {
        "_README": (
            "Fill the blanks. NO secrets in this file — only secretref:// handles. "
            "1) author the scope; 2) run `--mint --config THIS` to get operation_hash; "
            "3) paste it + a deadline into 'authorization' (your approval); "
            "4) in the private Runner set AGENTFORGE_ACTIVE_SCAN_ENABLED=1 + the sealed "
            "AGENTFORGE_CREDENTIAL_BINDINGS_JSON, then run `--config THIS`."
        ),
        "scope": {
            "origin": "https://<exact-approved-origin>",
            "http_methods": ["GET", "POST"],
            "path_patterns": ["/api/<in-scope>", "/api/<in-scope>/*"],
            "principals": ["synthetic-anon", "synthetic-<role>"],
            "image_sha256": ACTIVE_ZAP_IMAGE_SHA256,
            "addon_sha256s": ["<addon-sha256-64hex>"],
            "rule_sha256s": [active_scan_rule_subset_sha256()],
            "callback_domains": [],
            "caps": {
                "max_requests": 50,
                "requests_per_second": 2.0,
                "max_duration_seconds": 600.0,
                "max_findings": 200,
            },
            "scope_nonce": "<fresh-random-nonce>",
        },
        "authorization": {
            "operation_hash": "<run --mint to compute>",
            "scope_nonce": "<same as scope.scope_nonce>",
            "deadline": "<expiry as epoch seconds>",
        },
        "approved_origin": "https://<exact-approved-origin>",
        "openapi": {"openapi": "3.0.0", "paths": {"/api/<in-scope>": {"get": {}}}},
        "auth_matrix_entries": [
            ["synthetic-anon", "none", None],
            ["synthetic-<role>", "bearer", "secretref://<runner-binding>"],
        ],
        "credential_ref": None,
        "auth_header": "Cookie",
    }


def run_active_scan(
    config: Mapping[str, Any],
    *,
    sender: Callable[[Any], Any] | None = None,
    env: Mapping[str, str] | None = None,
    clock: Callable[[], float] | None = None,
    sleeper: Callable[[float], None] | None = None,
    run_id: str = "active-run",
) -> dict[str, Any]:
    """Execute one bounded governed active scan; return a JSON-safe report (never raises)."""
    env = os.environ if env is None else env
    clock = clock or time.time
    sleeper = sleeper or time.sleep

    scope = build_scope(config["scope"])
    grant = build_authorization(config["authorization"])
    approved_origin = config["approved_origin"]
    entries = [tuple(entry) for entry in config.get("auth_matrix_entries", [])]
    openapi = config.get("openapi") or {"openapi": "3.0.0", "paths": {}}

    now0 = clock()
    preflight = active_scan_preflight(
        scope,
        grant,
        approved_origin=approved_origin,
        openapi_spec=openapi,
        auth_matrix_entries=entries,
        now=now0,
    )
    report: dict[str, Any] = {
        "ok": False,
        "preflight_ok": preflight.ok,
        "preflight": [
            {"name": c.name, "passed": c.passed, "detail": c.detail} for c in preflight.checks
        ],
        "ledger": [],
        "parity_ok": None,
        "evidence": None,
        "reason": None,
    }
    if not preflight.ok:
        report["reason"] = "preflight not ready — refusing to scan (fail closed)"
        return report

    from agentforge.security_tools.scan_sender import _enabled  # local import: shared flag check

    if not _enabled(env):
        report["reason"] = f"active scanning disabled ({ACTIVE_SCAN_ENABLED_ENV} not set)"
        return report

    api = discover_openapi(openapi, scope=scope)
    egress = GovernedScanEgress(scope, authorization=grant, now=now0)

    if sender is None:
        credential_ref = config.get("credential_ref")
        resolver = (
            SealedEnvironmentCredentialResolver.from_environment().resolve
            if credential_ref
            else None
        )
        sender = BoundedHttpsSender(
            scope,
            credential_ref=credential_ref,
            credential_resolver=resolver,
            auth_header=config.get("auth_header", "Cookie"),
            canary=config.get("canary"),
            env=env,
        )

    min_interval = 1.0 / scope.caps.requests_per_second
    last: float | None = None
    for operation in api.operations:
        send_now = clock()
        if last is not None and (send_now - last) < min_interval:
            sleeper(min_interval - (send_now - last))
            send_now = clock()
        try:
            outcome = egress.send(
                method=operation.method, path=operation.path, dispatch=sender, now=send_now
            )
        except (ScanEgressAbort, ActiveScanSendError) as exc:
            report["ledger"].append(
                {"method": operation.method, "path": operation.path, "error": str(exc)}
            )
            report["reason"] = str(exc)
            break
        last = send_now
        report["ledger"].append(
            {
                "method": operation.method,
                "path": operation.path,
                "status": outcome.status_code,
                "redirected": outcome.redirected,
                "canary_reflected": outcome.canary_reflected,
                "bytes_read": outcome.bytes_read,
                "pinned_ip": outcome.pinned_ip,
            }
        )

    try:
        egress.assert_parity()
        report["parity_ok"] = True
    except ScanEgressAbort as exc:
        report["parity_ok"] = False
        report["reason"] = str(exc)

    reflected = sum(1 for entry in report["ledger"] if entry.get("canary_reflected"))
    evidence = ToolExecutionEvidence.evidenced(
        tool_id="active-http-prober",
        run_id=run_id,
        executed_attempt_count=len(egress.ledger),
        evidenced_finding_count=reflected,
        last_executed_at=datetime.now(UTC).isoformat(),
        evidence_uri=f"governed-egress-ledger://{run_id}",
    )
    report["evidence"] = evidence.to_tool_scope_fields()
    report["ok"] = bool(report["parity_ok"]) and report["reason"] is None
    return report


def _arg(argv: list[str], flag: str) -> str | None:
    if flag in argv:
        index = argv.index(flag)
        if index + 1 < len(argv):
            return argv[index + 1]
    return None


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--print-template" in argv:
        print(
            json.dumps(
                {"schema": active_scan_schema(), "template": active_scan_template()},
                indent=2,
                default=str,
            )
        )
        return 0

    config_path = _arg(argv, "--config")
    if config_path is None:
        print(
            "usage: active_scan_run [--print-template] [--mint] --config PLAN.json", file=sys.stderr
        )
        return 2
    config = json.loads(Path(config_path).read_text())

    if "--mint" in argv:
        print(json.dumps({"operation_hash": mint_operation_hash(config)}, indent=2))
        return 0

    report = run_active_scan(config)
    print(json.dumps(report, indent=2, default=str))
    return 0 if report.get("ok") else 2


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
