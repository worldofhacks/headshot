"""RED tests for WP-17 API discovery — a content-addressed, scope-bounded target surface.

Before an active scan runs, its concrete operation surface is discovered from the target's
OpenAPI schema and INTERSECTED with the authorized active-scan scope: an operation whose method or
path the grant did not authorize is dropped, never scanned. The discovered surface is content-
addressed (schema digest + order-independent surface digest) so it can be reviewed and pinned.

Offline: parses a schema dict; no network fetch.
"""

from __future__ import annotations

import pytest

from agentforge.security_tools.active_authorization import ActiveScanCaps, ActiveScanScope
from agentforge.security_tools.api_discovery import DiscoveredApi, discover_openapi


def _scope(
    *,
    methods: tuple[str, ...] = ("GET", "POST"),
    paths: tuple[str, ...] = ("/api/copilot", "/api/copilot/*"),
) -> ActiveScanScope:
    return ActiveScanScope(
        origin="https://copilot.example-hospital.test",
        http_methods=methods,
        path_patterns=paths,
        principals=("synthetic-clinician-a",),
        image_sha256="a" * 64,
        addon_sha256s=("b" * 64,),
        rule_sha256s=("c" * 64,),
        callback_domains=("oast.agentforge.internal",),
        caps=ActiveScanCaps.parse(
            max_requests=100,
            requests_per_second=10.0,
            max_duration_seconds=600.0,
            max_findings=200,
        ),
        scope_nonce="nonce-0123456789ab",
    )


def _spec() -> dict:
    return {
        "openapi": "3.0.0",
        "paths": {
            "/api/copilot": {
                "post": {"parameters": [{"name": "prompt"}, {"name": "patient_id"}]},
                "get": {},
            },
            "/api/copilot/history": {"get": {"parameters": [{"name": "since"}]}},
            "/admin/users": {"delete": {}},  # out of scope: dropped
        },
    }


def test_discover_extracts_operations_and_parameters() -> None:
    api = discover_openapi(_spec(), scope=_scope())
    assert isinstance(api, DiscoveredApi)
    ops = {(op.method, op.path) for op in api.operations}
    assert ("POST", "/api/copilot") in ops
    assert ("GET", "/api/copilot") in ops
    assert ("GET", "/api/copilot/history") in ops
    post = next(op for op in api.operations if op.method == "POST")
    assert post.parameters == ("patient_id", "prompt")  # sorted, deterministic


def test_discovery_is_bounded_to_the_authorized_scope() -> None:
    ops = {(op.method, op.path) for op in discover_openapi(_spec(), scope=_scope()).operations}
    # /admin/users DELETE is outside both the path and method scope — never discovered.
    assert ("DELETE", "/admin/users") not in ops
    assert all(path.startswith("/api/copilot") for _, path in ops)


def test_method_outside_scope_is_dropped_even_on_an_in_scope_path() -> None:
    scope = _scope(methods=("GET",))  # POST not authorized
    ops = {(op.method, op.path) for op in discover_openapi(_spec(), scope=scope).operations}
    assert ("POST", "/api/copilot") not in ops
    assert ("GET", "/api/copilot") in ops


def test_discovered_surface_is_content_addressed_and_order_independent() -> None:
    api = discover_openapi(_spec(), scope=_scope())
    assert len(api.schema_sha256) == 64 and len(api.surface_sha256) == 64

    reordered = {"openapi": "3.0.0", "paths": dict(reversed(list(_spec()["paths"].items())))}
    api2 = discover_openapi(reordered, scope=_scope())
    assert api2.surface_sha256 == api.surface_sha256, "surface digest is order-independent"

    mutated = _spec()
    mutated["paths"]["/api/copilot"]["put"] = {}
    # 'put' is out of scope so the surface is unchanged, but the schema digest changes.
    api3 = discover_openapi(mutated, scope=_scope())
    assert api3.schema_sha256 != api.schema_sha256


def test_malformed_spec_fails_closed() -> None:
    with pytest.raises(ValueError):
        discover_openapi({"no": "paths"}, scope=_scope())
    with pytest.raises(ValueError):
        discover_openapi("not a dict", scope=_scope())  # type: ignore[arg-type]
