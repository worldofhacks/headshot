"""M1d same-origin Web composition and browser-boundary security contracts."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from agentforge.web import WebSecurityConfig, create_web_app, parse_port


def _console(tmp_path: Path) -> Path:
    console = tmp_path / "console"
    assets = console / "assets"
    assets.mkdir(parents=True)
    (console / "index.html").write_text(
        '<!doctype html><html><body><div id="root"></div>'
        '<script type="module" src="/assets/app-abcdef12.js"></script></body></html>',
        encoding="utf-8",
    )
    (assets / "app-abcdef12.js").write_text("export {};", encoding="utf-8")
    return console


def _security(environment: str = "production") -> WebSecurityConfig:
    origin = "https://headshot.example" if environment != "local" else "http://localhost:5173"
    return WebSecurityConfig(
        environment=environment,
        allowed_origins=(origin,),
        clerk_frontend_api_origin="https://clerk.headshot.example",
        max_request_bytes=1024,
    )


def test_spa_fallback_is_only_for_unknown_non_api_html_gets(tmp_path: Path) -> None:
    app = create_web_app(
        console_dir=_console(tmp_path),
        readiness_check=lambda: True,
        security_config=_security("local"),
    )
    client = TestClient(app)

    direct = client.get("/findings/F-real", headers={"Accept": "text/html"})
    history_route = client.get("/targets/T-real", headers={"Accept": "text/html"})
    api_root = client.get("/api", headers={"Accept": "text/html"})
    unknown_api = client.get("/api/v1/not-real", headers={"Accept": "text/html"})
    json_client = client.get("/not-real", headers={"Accept": "application/json"})
    mutation = client.post("/not-real", headers={"Accept": "text/html"})
    missing_asset = client.get("/assets/missing-abcdef12.js", headers={"Accept": "text/html"})

    assert direct.status_code == history_route.status_code == 200
    assert '<div id="root"></div>' in direct.text
    assert api_root.status_code == unknown_api.status_code == 404
    assert unknown_api.headers["content-type"].startswith("application/json")
    assert json_client.status_code == 404
    assert mutation.status_code == 405
    assert missing_asset.status_code == 404


def test_security_and_cache_headers_preserve_strict_script_policy(tmp_path: Path) -> None:
    app = create_web_app(
        console_dir=_console(tmp_path),
        readiness_check=lambda: True,
        security_config=_security(),
    )
    client = TestClient(app)

    shell = client.get("/live", headers={"Accept": "text/html"})
    asset = client.get("/assets/app-abcdef12.js")
    health = client.get("/health")

    assert shell.headers["cache-control"] == "no-store"
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert health.headers["cache-control"] == "no-store"
    assert shell.headers["strict-transport-security"].startswith("max-age=")
    assert shell.headers["x-content-type-options"] == "nosniff"
    assert shell.headers["referrer-policy"] == "no-referrer"
    assert shell.headers["x-frame-options"] == "DENY"
    assert "camera=()" in shell.headers["permissions-policy"]

    csp = shell.headers["content-security-policy"]
    directives = {
        part.strip().split(" ", 1)[0]: part.strip() for part in csp.split(";") if part.strip()
    }
    assert directives["script-src"] == "script-src 'self'"
    assert "'unsafe-inline'" not in directives["script-src"]
    assert "'unsafe-eval'" not in directives["script-src"]
    assert directives["frame-ancestors"] == "frame-ancestors 'none'"
    assert "style-src-attr 'unsafe-inline'" in csp


def test_cors_is_exact_and_never_wildcard(tmp_path: Path) -> None:
    app = create_web_app(
        console_dir=_console(tmp_path),
        readiness_check=lambda: True,
        security_config=_security(),
    )
    client = TestClient(app)

    allowed = client.options(
        "/api/v1/principal",
        headers={
            "Origin": "https://headshot.example",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    denied = client.options(
        "/api/v1/principal",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "https://headshot.example"
    assert "*" not in allowed.headers.get("access-control-allow-origin", "")
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers


def test_request_body_cap_applies_before_protected_mutation(tmp_path: Path) -> None:
    app = create_web_app(
        console_dir=_console(tmp_path),
        readiness_check=lambda: True,
        security_config=_security("local"),
    )

    response = TestClient(app).post(
        "/api/v1/campaign-authorization-requests",
        content=b"x" * 1025,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "Request too large"}
    assert response.headers["cache-control"] == "no-store"


def test_parse_port_accepts_railway_assignment_and_rejects_unsafe_values() -> None:
    assert parse_port("43117") == 43117
    assert parse_port(None) == 8000

    for invalid in ("", "0", "65536", "-1", "eight-thousand", "8000?debug=1"):
        try:
            parse_port(invalid)
        except ValueError:
            pass
        else:  # pragma: no cover - assertion branch
            raise AssertionError(f"unsafe PORT was accepted: {invalid!r}")
