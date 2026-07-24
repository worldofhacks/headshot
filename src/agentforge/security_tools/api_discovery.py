"""WP-17 API discovery — a content-addressed, scope-bounded active-scan target surface.

An active scan must know the concrete (method, path) operations to exercise. They are discovered
from the target's OpenAPI schema and immediately INTERSECTED with the authorized active-scan scope:
any operation whose method or path the grant did not authorize is dropped and never scanned, so
discovery can never widen the scope. The result is content-addressed — a digest of the raw schema
and an order-independent digest of the discovered operation surface — so a reviewer can pin exactly
what will be scanned.

Stdlib only; parses an already-fetched schema dict, never fetches it (the fetch itself, when it
happens, crosses the governed egress in the private Runner).
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass

from agentforge.security_tools.active_authorization import ActiveScanScope

MAX_DISCOVERED_OPERATIONS = 1000
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"})


@dataclass(frozen=True, slots=True)
class ApiOperation:
    method: str
    path: str
    parameters: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DiscoveredApi:
    origin: str
    operations: tuple[ApiOperation, ...]
    schema_sha256: str
    surface_sha256: str


def _path_in_scope(path: str, patterns: tuple[str, ...]) -> bool:
    return any(path == pattern or fnmatch.fnmatch(path, pattern) for pattern in patterns)


def discover_openapi(spec: dict, *, scope: ActiveScanScope) -> DiscoveredApi:
    """Discover the in-scope operation surface from an OpenAPI schema, content-addressed."""
    if not isinstance(spec, dict):
        raise ValueError("OpenAPI spec must be a mapping")
    paths = spec.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise ValueError("OpenAPI spec has no 'paths'")

    allowed_methods = {m.upper() for m in scope.http_methods}
    operations: list[ApiOperation] = []
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            raise ValueError("malformed OpenAPI path item")
        if not _path_in_scope(path, scope.path_patterns):
            continue
        for method, operation in item.items():
            upper = method.upper()
            if upper not in _HTTP_METHODS or upper not in allowed_methods:
                continue
            params = ()
            if isinstance(operation, dict):
                raw_params = operation.get("parameters", [])
                if isinstance(raw_params, list):
                    params = tuple(
                        sorted(
                            {
                                p["name"]
                                for p in raw_params
                                if isinstance(p, dict) and isinstance(p.get("name"), str)
                            }
                        )
                    )
            operations.append(ApiOperation(method=upper, path=path, parameters=params))
            if len(operations) > MAX_DISCOVERED_OPERATIONS:
                raise ValueError("OpenAPI surface exceeds the discovery cap")

    operations.sort(key=lambda op: (op.path, op.method))
    schema_canonical = json.dumps(
        spec, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    surface_canonical = json.dumps(
        [[op.method, op.path, list(op.parameters)] for op in operations],
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return DiscoveredApi(
        origin=scope.origin,
        operations=tuple(operations),
        schema_sha256=hashlib.sha256(schema_canonical).hexdigest(),
        surface_sha256=hashlib.sha256(surface_canonical).hexdigest(),
    )


__all__ = ["ApiOperation", "DiscoveredApi", "MAX_DISCOVERED_OPERATIONS", "discover_openapi"]
