"""Railway Web process: same-origin FastAPI, protected API, and built console assets."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from agentforge.api.backend import ApiBackend, ApiBackendUnavailable, UnavailableApiBackend
from agentforge.api.router import router as api_router

_DEFAULT_CONSOLE_DIR = Path("/app/console")
_HASHED_ASSET = re.compile(r"\A/assets/.+[-.][a-f0-9]{8,}\.[A-Za-z0-9]+\Z")
_SENSITIVE_QUERY_NAMES = frozenset(
    {
        "access_token",
        "auth",
        "authorization",
        "bearer",
        "jwt",
        "session_token",
        "token",
    }
)
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _exact_origin(value: str, *, environment: str, field: str) -> str:
    if not value or value != value.strip() or "*" in value or any(c.isspace() for c in value):
        raise ValueError(f"{field} must be an exact origin")
    parsed = urlsplit(value)
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"{field} must be an exact origin") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{field} must be an exact origin")
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"} or parsed.hostname.endswith(
        ".localhost"
    )
    if environment == "local":
        if not loopback:
            raise ValueError(f"{field} must be loopback in local mode")
    elif parsed.scheme != "https" or loopback:
        raise ValueError(f"{field} must be non-local HTTPS when deployed")
    return value


@dataclass(frozen=True, slots=True)
class WebSecurityConfig:
    """Explicit browser boundary; wildcard origins are structurally rejected."""

    environment: str
    allowed_origins: tuple[str, ...]
    clerk_frontend_api_origin: str | None = None
    max_request_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        if self.environment not in {"local", "staging", "production"}:
            raise ValueError("web environment is invalid")
        if not self.allowed_origins or len(self.allowed_origins) != len(set(self.allowed_origins)):
            raise ValueError("allowed origins must be an explicit unique list")
        normalized = tuple(
            _exact_origin(origin, environment=self.environment, field="allowed origin")
            for origin in self.allowed_origins
        )
        object.__setattr__(self, "allowed_origins", normalized)
        fapi = self.clerk_frontend_api_origin
        if fapi is not None:
            # Clerk development FAPI remains HTTPS; only the application origin may be local HTTP.
            exact = _exact_origin(fapi, environment="production", field="Clerk FAPI origin")
            object.__setattr__(self, "clerk_frontend_api_origin", exact)
        elif self.environment != "local":
            raise ValueError("deployed Web requires an exact Clerk FAPI origin for CSP")
        if (
            isinstance(self.max_request_bytes, bool)
            or not isinstance(self.max_request_bytes, int)
            or not 1_024 <= self.max_request_bytes <= 10_485_760
        ):
            raise ValueError("max request bytes must be between 1 KiB and 10 MiB")

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> WebSecurityConfig:
        source = os.environ if environ is None else environ
        environment = source.get("AGENTFORGE_ENVIRONMENT", "local").strip()
        raw_origins = source.get("CLERK_AUTHORIZED_PARTIES", "")
        if not raw_origins and environment == "local":
            raw_origins = "http://localhost:5173"
        origins = tuple(value.strip() for value in raw_origins.split(",") if value.strip())
        fapi = source.get("CLERK_FRONTEND_API_ORIGIN") or None
        raw_limit = source.get("AGENTFORGE_MAX_REQUEST_BYTES", "1048576")
        try:
            limit = int(raw_limit)
        except ValueError as exc:
            raise ValueError("AGENTFORGE_MAX_REQUEST_BYTES must be an integer") from exc
        return cls(
            environment=environment,
            allowed_origins=origins,
            clerk_frontend_api_origin=fapi,
            max_request_bytes=limit,
        )

    def content_security_policy(self) -> str:
        connect = ["'self'"]
        if self.clerk_frontend_api_origin:
            connect.append(self.clerk_frontend_api_origin)
        return "; ".join(
            (
                "default-src 'self'",
                "script-src 'self'",
                "script-src-attr 'none'",
                "connect-src " + " ".join(connect),
                "img-src 'self' data: https://img.clerk.com",
                "font-src 'self'",
                # Clerk's reviewed UI uses runtime CSS-in-JS; this exception is isolated to
                # style. Script policy remains self-only with no inline/eval capability.
                "style-src 'self' 'unsafe-inline'",
                "style-src-attr 'unsafe-inline'",
                "worker-src 'self' blob:",
                "frame-src https://challenges.cloudflare.com",
                "frame-ancestors 'none'",
                "object-src 'none'",
                "base-uri 'none'",
                "form-action 'self'",
            )
        )


class RequestBoundaryMiddleware:
    """Reject credential-bearing URLs and cap streamed request bodies before routing."""

    def __init__(self, app: ASGIApp, *, max_request_bytes: int) -> None:
        self.app = app
        self.max_request_bytes = max_request_bytes

    async def _reject(
        self, scope: Scope, receive: Receive, send: Send, status: int, detail: str
    ) -> None:
        body = json.dumps({"detail": detail}, separators=(",", ":")).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        query = scope.get("query_string", b"").decode("latin-1")
        if any(
            name.lower() in _SENSITIVE_QUERY_NAMES
            for name, _ in parse_qsl(query, keep_blank_values=True)
        ):
            await self._reject(scope, receive, send, 400, "Credentials are forbidden in URLs")
            return
        if scope.get("method") not in _BODY_METHODS:
            await self.app(scope, receive, send)
            return

        messages: list[Message] = []
        total = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            total += len(message.get("body", b""))
            if total > self.max_request_bytes:
                await self._reject(scope, receive, send, 413, "Request too large")
                return
            if not message.get("more_body", False):
                break
        index = 0

        async def replay() -> Message:
            nonlocal index
            if index < len(messages):
                message = messages[index]
                index += 1
                return message
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay, send)


class SecurityHeadersMiddleware:
    """Apply cache and browser-security headers uniformly, including errors."""

    def __init__(self, app: ASGIApp, *, config: WebSecurityConfig) -> None:
        self.app = app
        self.config = config

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = self.config.content_security_policy()
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Permissions-Policy"] = (
                    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
                    "interest-cohort=(), browsing-topics=()"
                )
                headers["X-Frame-Options"] = "DENY"
                if self.config.environment == "production":
                    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
                path = scope.get("path", "")
                content_type = headers.get("content-type", "")
                if (
                    path.startswith("/api/")
                    or path in {"/health", "/ready"}
                    or "text/html" in content_type
                ):
                    if "cache-control" not in headers:
                        headers["Cache-Control"] = "no-store"
                elif _HASHED_ASSET.fullmatch(path):
                    headers["Cache-Control"] = "public, max-age=31536000, immutable"
                else:
                    headers["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_with_headers)


def _console_path(console_dir: str | os.PathLike[str] | None) -> Path:
    if console_dir is not None:
        return Path(console_dir)
    configured = os.environ.get("AGENTFORGE_CONSOLE_DIR")
    return Path(configured) if configured else _DEFAULT_CONSOLE_DIR


def create_web_app(
    *,
    console_dir: str | os.PathLike[str] | None = None,
    readiness_check: Callable[[], Any] | None = None,
    security_config: WebSecurityConfig | None = None,
    backend: ApiBackend | None = None,
) -> FastAPI:
    """Compose the only public service without contacting Clerk, a target, or a model."""

    config = security_config or WebSecurityConfig.from_env()
    app = FastAPI(
        title="Headshot Web",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.security_config = config
    app.state.api_backend = backend or UnavailableApiBackend()
    app.state.readiness_check = readiness_check or (lambda: False)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(config.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "Last-Event-ID"],
        expose_headers=[],
        max_age=300,
    )
    app.add_middleware(RequestBoundaryMiddleware, max_request_bytes=config.max_request_bytes)
    app.add_middleware(SecurityHeadersMiddleware, config=config)

    @app.get("/health")
    def health() -> JSONResponse:
        return JSONResponse({"status": "alive"})

    @app.get("/ready")
    def ready() -> JSONResponse:
        try:
            available = bool(app.state.readiness_check())
        except Exception:
            available = False
        if not available:
            return JSONResponse({"status": "not_ready"}, status_code=503)
        return JSONResponse({"status": "ready"})

    app.include_router(api_router)

    root = _console_path(console_dir)
    index = root / "index.html"
    assets = root / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets, check_dir=True), name="console-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(request: Request, full_path: str):
        path = "/" + full_path
        if (
            path == "/api"
            or path.startswith("/api/")
            or path in {"/health", "/ready"}
            or path.startswith("/assets/")
            or "text/html" not in request.headers.get("accept", "")
        ):
            raise HTTPException(status_code=404, detail="Not found")
        if not index.is_file():
            return JSONResponse(
                {"detail": "Console unavailable"},
                status_code=503,
                headers={"Cache-Control": "no-store"},
            )
        return FileResponse(index, media_type="text/html", headers={"Cache-Control": "no-store"})

    @app.exception_handler(ApiBackendUnavailable)
    async def unavailable_handler(_request: Request, _exc: ApiBackendUnavailable) -> JSONResponse:
        return JSONResponse({"detail": "Service unavailable"}, status_code=503)

    return app


def parse_port(raw: str | None) -> int:
    """Parse Railway's assigned PORT without shell interpolation."""

    if raw is None:
        return 8000
    if not raw.isdigit():
        raise ValueError("PORT must be a decimal integer")
    port = int(raw)
    if not 1 <= port <= 65535:
        raise ValueError("PORT must be between 1 and 65535")
    return port


def main(argv: Sequence[str] | None = None) -> int:
    """Run only the public Web process. Runner and Scheduler never import this entrypoint."""

    del argv
    port = parse_port(os.environ.get("PORT"))
    import uvicorn

    uvicorn.run(
        "agentforge.app:app",
        host="0.0.0.0",
        port=port,
        access_log=False,
        proxy_headers=False,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by subprocess/container smoke
    raise SystemExit(main())


__all__ = ["WebSecurityConfig", "create_web_app", "main", "parse_port"]
