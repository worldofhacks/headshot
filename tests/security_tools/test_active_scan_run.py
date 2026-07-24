"""RED tests for the runnable governed active-scan entrypoint.

`python -m agentforge.security_tools.active_scan_run` mints/prints the grant schema+template and
executes ONE bounded governed active scan from an owner-authored config: preflight (zero-call) ->
GovernedScanEgress driven with the real sender -> scanner<->permit<->send<->ledger parity + per-tool
evidence. Every run test injects a fake sender + fake clock, so no socket is opened.
"""

from __future__ import annotations

import json

from agentforge.security_tools.active_scan_run import (
    active_scan_template,
    main,
    mint_operation_hash,
    run_active_scan,
)
from agentforge.security_tools.scan_sender import ACTIVE_SCAN_ENABLED_ENV, SendOutcome
from agentforge.security_tools.zap_profiles import (
    ACTIVE_ZAP_IMAGE_SHA256,
    active_scan_rule_subset_sha256,
)

ORIGIN = "https://copilot.example-hospital.test"
ENABLED = {ACTIVE_SCAN_ENABLED_ENV: "1"}


def _scope_dict(**over) -> dict:
    scope = {
        "origin": ORIGIN,
        "http_methods": ["GET", "POST"],
        "path_patterns": ["/api/copilot", "/api/copilot/*"],
        "principals": ["synthetic-anon"],
        "image_sha256": ACTIVE_ZAP_IMAGE_SHA256,
        "addon_sha256s": ["b" * 64],
        "rule_sha256s": [active_scan_rule_subset_sha256()],
        "callback_domains": [],
        "caps": {
            "max_requests": 50,
            "requests_per_second": 50.0,
            "max_duration_seconds": 600.0,
            "max_findings": 200,
        },
        "scope_nonce": "nonce-0123456789ab",
    }
    scope.update(over)
    return scope


def _config(**over) -> dict:
    scope = over.pop("scope", _scope_dict())
    op_hash = over.pop("operation_hash", None) or mint_operation_hash({"scope": scope})
    config = {
        "scope": scope,
        "authorization": {
            "operation_hash": op_hash,
            "scope_nonce": scope["scope_nonce"],
            "deadline": 10_000.0,
        },
        "approved_origin": ORIGIN,
        "openapi": {
            "openapi": "3.0.0",
            "paths": {"/api/copilot": {"get": {}}, "/api/copilot/history": {"get": {}}},
        },
        "auth_matrix_entries": [["synthetic-anon", "none", None]],
        "credential_ref": None,
        "auth_header": "Cookie",
    }
    config.update(over)
    return config


def _fake_sender(canary_reflected: bool = False):
    def sender(permit) -> SendOutcome:
        return SendOutcome(
            status_code=200,
            pinned_ip="8.8.8.8",
            bytes_read=2,
            response_sha256="0" * 64,
            redirected=False,
            canary_reflected=canary_reflected,
            elapsed_ms=1.0,
        )

    return sender


def _clock():
    box = {"t": 1000.0}

    def now() -> float:
        box["t"] += 100.0
        return box["t"]

    return now


def _run(config, *, sender=None, env=ENABLED):
    return run_active_scan(
        config, sender=sender or _fake_sender(), env=env, clock=_clock(), sleeper=lambda _s: None
    )


def test_print_template_emits_schema_and_blanks_without_secrets(capsys) -> None:
    assert main(["--print-template"]) == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert "schema" in payload and "template" in payload
    template = payload["template"]
    assert template["scope"]["origin"].startswith("https://")
    assert template["scope"]["rule_sha256s"] == [active_scan_rule_subset_sha256()]
    # No secret material anywhere in the template — only references.
    assert "secretref://" in json.dumps(template)
    assert "SID=" not in json.dumps(template)


def test_mint_computes_the_operation_hash_from_the_scope() -> None:
    scope = _scope_dict()
    assert mint_operation_hash({"scope": scope}) == mint_operation_hash({"scope": scope})
    template = active_scan_template()
    assert "scope" in template and "authorization" in template


def test_run_refuses_when_active_scanning_is_disabled() -> None:
    report = _run(_config(), env={})
    assert report["ok"] is False
    assert "disabled" in report["reason"].lower()
    assert report["ledger"] == []


def test_run_refuses_on_preflight_failure() -> None:
    # Non-synthetic principal fails preflight (a real fail-closed gate) -> no sends.
    config = _config(scope=_scope_dict(principals=["real-clinician-jane"]))
    config["auth_matrix_entries"] = [["real-clinician-jane", "none", None]]
    report = _run(config)
    assert report["ok"] is False and report["preflight_ok"] is False
    assert report["ledger"] == []


def test_run_refuses_a_grant_scope_mismatch() -> None:
    report = _run(_config(operation_hash="0" * 64))
    assert report["ok"] is False and report["preflight_ok"] is False


def test_run_executes_over_authorized_ops_with_parity_and_evidence() -> None:
    report = _run(_config())
    assert report["ok"] is True
    assert report["preflight_ok"] is True
    assert report["parity_ok"] is True
    assert len(report["ledger"]) == 2  # two in-scope GET operations
    assert all(entry["status"] == 200 for entry in report["ledger"])
    assert report["evidence"]["runtime_state"] == "evidenced"
    assert report["evidence"]["executed_attempt_count"] == 2


def test_run_never_puts_a_secret_in_the_report() -> None:
    config = _config(credential_ref="secretref://staging/clinician-a")
    report = _run(config)
    assert "SID=" not in json.dumps(report, default=str)
    assert "secretref://staging/clinician-a" not in json.dumps(report, default=str)
