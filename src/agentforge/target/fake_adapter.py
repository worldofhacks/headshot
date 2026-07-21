"""Deterministic, no-network TargetAdapter fake for gateway verification + CI (P9).

It never touches the network, so it can run in CI and in the sandbox that gateway tests use.
A response is a pure function of the request (a canonical hash of the turn sequence), so
replaying the same request yields byte-identical output — exactly what deterministic gateway
and regression tests need. It can also be told to simulate a typed error for a given request,
so the gateway's backoff/queue/abort handling is exercised without a live target.

This is the fake that lets M4 (Policy Gateway) be verified *before* the live OpenEMR adapter
(M5) exists — breaking the gateway↔adapter cycle.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from agentforge.target.base import (
    AdapterError,
    TargetAdapter,
    TargetRequest,
    TargetResponse,
)


def canonical_key(request: TargetRequest) -> str:
    """Stable content hash of the request's turn sequence — the replay/identity key."""
    payload = "\x1f".join(request.turns)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class FakeTargetAdapter(TargetAdapter):
    """Deterministic record/replay fake.

    ``scripted`` maps a request key → canned output; ``errors`` maps a request key → an
    :class:`AdapterError` to raise. An unseen request gets a deterministic synthetic echo
    derived from its hash — still with zero network I/O.
    """

    name: str = "fake"
    scripted: dict[str, str] = field(default_factory=dict)
    errors: dict[str, AdapterError] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)  # keys seen, for test/observability

    def script(self, request: TargetRequest, output: str) -> FakeTargetAdapter:
        self.scripted[canonical_key(request)] = output
        return self

    def fail(self, request: TargetRequest, error: AdapterError) -> FakeTargetAdapter:
        self.errors[canonical_key(request)] = error
        return self

    def send(self, request: TargetRequest) -> TargetResponse:
        key = canonical_key(request)
        self.calls.append(key)
        if key in self.errors:
            raise self.errors[key]
        if key in self.scripted:
            return TargetResponse(
                output=self.scripted[key],
                status=200,
                metadata={"adapter": self.name, "key": key},
            )
        synthetic = f"FAKE::{key[:16]}::{len(request.turns)}turns"
        return TargetResponse(
            output=synthetic,
            status=200,
            metadata={"adapter": self.name, "key": key, "synthetic": "true"},
        )
