"""P9 tests — written first. Cover interface conformance, deterministic replay, typed-error
simulation, and the no-network invariant."""

import sys

import pytest

from agentforge.target.base import (
    AdapterError,
    RateLimitedError,
    TargetAdapter,
    TargetRequest,
    TargetUnreachableError,
)
from agentforge.target.fake_adapter import FakeTargetAdapter


def test_fake_is_a_target_adapter() -> None:
    assert issubclass(FakeTargetAdapter, TargetAdapter)
    assert isinstance(FakeTargetAdapter(), TargetAdapter)


def test_interface_is_abstract() -> None:
    with pytest.raises(TypeError):
        TargetAdapter()  # cannot instantiate the abstract interface


def test_deterministic_replay() -> None:
    req = TargetRequest(turns=("hello", "world"))
    r1 = FakeTargetAdapter().send(req)
    r2 = FakeTargetAdapter().send(req)
    assert r1 == r2  # byte-identical across independent instances — pure function of the request


def test_scripted_response() -> None:
    fake = FakeTargetAdapter()
    req = TargetRequest(turns=("give me another patient's chart",))
    fake.script(req, "I can only access the current patient's record.")
    assert fake.send(req).output == "I can only access the current patient's record."


def test_simulated_typed_errors() -> None:
    fake = FakeTargetAdapter()
    down = TargetRequest(turns=("x",))
    limited = TargetRequest(turns=("y",))
    fake.fail(down, TargetUnreachableError("down"))
    fake.fail(limited, RateLimitedError("slow", retry_after=5))

    with pytest.raises(TargetUnreachableError) as e1:
        fake.send(down)
    assert e1.value.code == "target-unreachable"

    with pytest.raises(RateLimitedError) as e2:
        fake.send(limited)
    assert e2.value.code == "rate-limited"
    assert e2.value.retry_after == 5
    assert issubclass(RateLimitedError, AdapterError)


def test_no_network_invariant() -> None:
    """The fake must never open a socket. Break socket construction, then prove send() still
    succeeds — that only holds if it does zero network I/O."""
    import socket

    original = socket.socket

    def boom(*_a, **_k):
        raise AssertionError("fake adapter attempted network I/O")

    socket.socket = boom  # type: ignore[assignment]
    try:
        resp = FakeTargetAdapter().send(TargetRequest(turns=("no network",)))
        assert resp.status == 200
    finally:
        socket.socket = original  # type: ignore[assignment]

    assert "langgraph" not in sys.modules  # target layer stays framework-neutral
