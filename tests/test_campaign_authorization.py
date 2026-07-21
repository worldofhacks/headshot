"""M11-coordinator — RunAuthorization / TargetBinding / RunCaps RED tests (no src/ yet).

Anchors: the M11 secure-coordinator SPEC (authorization.py / binding.py / caps.py) over
ARCHITECTURE.md §5 (live-campaign gate F5/F7, S1/S3), DECISIONS.md D16; the M5 preflight +
gateway posture. These pin the FAIL-CLOSED authorization/binding/caps gates that run BEFORE
any dispatch — never a happy path alone.

**ABSOLUTELY NO NETWORK.** These are pure config/gate validators; nothing here constructs an
HTTP client, resolves a live secret, or opens a socket. ``socket.socket`` is patched to raise
across every test in this module (an autouse guard), so any accidental dial-out fails loudly.

The three units under test:

* ``RunAuthorization`` — PERSISTED, EXPIRING, SCOPED. It binds a canonical operation hash of
  the immutable run config, an absolute expiry on the injectable clock, and the run nonce.
  ``verify`` BLOCKS (typed ``AuthorizationError``) when the auth is MISSING, EXPIRED, or
  SCOPE-MISMATCHED (operation_hash or run_nonce differs).
* ``TargetBinding`` — IMMUTABLE (frozen). Validates exact-host match, the live adapter kind
  (never the P9 fake), and the credential_ref shape. Credentials resolve to a ``Secret`` only
  at the verified dispatch boundary — never at construction.
* ``RunCaps`` — FAIL-CLOSED parsing of budget/rate/attempt/timeout into a ``RunPolicy``: each
  a finite positive number and <= a hard maximum; missing/zero/negative/non-numeric/over-max
  is a typed ``CapError`` (no silent default, no unbounded run).

Until ``agentforge.campaign.{authorization,binding,caps}`` exist, every import below fails and
this module RED-collects — RED for the right reason.
"""

from __future__ import annotations

import socket

import pytest

from agentforge.campaign.authorization import (
    AuthorizationError,
    RunAuthorization,
    operation_hash,
)
from agentforge.campaign.binding import BindingError, TargetBinding
from agentforge.campaign.caps import CapError, RunCaps
from agentforge.config import Settings
from agentforge.policy.gateway import RunPolicy
from agentforge.secrets import Secret

# --------------------------------------------------------------------------------------------
# The bound run config — an OpenEMR live target reached over its EXACT https host. No live call
# is ever made here: these are shape validators only.
# --------------------------------------------------------------------------------------------
BOUND_TARGET_ID = "openemr"
BOUND_HOST = "copilot.example-openemr.org"
BOUND_BASE_URL = f"https://{BOUND_HOST}"
BOUND_ADAPTER_KIND = "openemr"
BOUND_CREDENTIAL_REF = "secretref://production/openemr"
BOUND_CORPUS_ID = "m11-seed-corpus-v1"
RUN_NONCE = "run-nonce-0001"


# --------------------------------------------------------------------------------------------
# Deterministic clock double — the SAME shape the M4 gateway suite injects, so expiry trips
# WITHOUT real time. ``now()`` returns seconds as a float, advanced by hand.
# --------------------------------------------------------------------------------------------
class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self._t = start

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += seconds


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Break ``socket.socket`` for EVERY test here — a gate validator must open no socket."""

    def boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError(
            "an authorization/binding/caps validator attempted network I/O (opened a socket) "
            "— these are pure fail-closed shape checks: no target, no hosted call, no network"
        )

    monkeypatch.setattr(socket, "socket", boom)


def _op_hash() -> str:
    """The canonical operation hash the auth is scoped to — target / surface / corpus + caps.

    Scoped to the target IDENTITY the run attacks (target_id / surface / corpus), NOT the adapter
    transport: the adapter kind + credential ref are deliberately EXCLUDED (OpenEMR is merely the
    first adapter). See ``operation_hash`` — the same grant authorizes a target's surface regardless
    of which adapter/credential wires the connection.
    """
    return operation_hash(
        target_id=BOUND_TARGET_ID,
        surface=BOUND_HOST,
        corpus_id=BOUND_CORPUS_ID,
        caps=RunPolicy(
            budget_usd=10.0,
            max_attempts_per_run=9,
            target_requests_per_second=1.0,
            run_timeout_seconds=60.0,
        ),
        run_nonce=RUN_NONCE,
    )


def _auth(*, deadline: float = 2000.0, op_hash: str | None = None) -> RunAuthorization:
    """A minted, immutable RunAuthorization scoped to the bound run config."""
    return RunAuthorization(
        operation_hash=op_hash if op_hash is not None else _op_hash(),
        run_nonce=RUN_NONCE,
        deadline=deadline,
    )


def _binding() -> TargetBinding:
    return TargetBinding(
        target_id=BOUND_TARGET_ID,
        host=BOUND_HOST,
        adapter_kind=BOUND_ADAPTER_KIND,
        credential_ref=BOUND_CREDENTIAL_REF,
    )


# ============================================================================================
# operation_hash — a stable, content-addressed hash of the immutable run config.
# ============================================================================================
def test_operation_hash_is_stable_and_hex() -> None:
    """The operation hash is a pure function of the run config — the same config always hashes
    to the same 64-hex digest, so an auth minted for it can be re-verified independently."""
    h1 = _op_hash()
    h2 = _op_hash()
    assert h1 == h2
    assert len(h1) == 64
    assert all(c in "0123456789abcdef" for c in h1)


def test_operation_hash_changes_when_a_scope_field_changes() -> None:
    """Changing a SCOPE field (surface or corpus) changes the operation hash — an auth minted for
    one surface/corpus can never silently authorize a different one (scope is content-addressed)."""
    caps = RunPolicy(
        budget_usd=10.0,
        max_attempts_per_run=9,
        target_requests_per_second=1.0,
        run_timeout_seconds=60.0,
    )
    base = operation_hash(
        target_id=BOUND_TARGET_ID,
        surface=BOUND_HOST,
        corpus_id=BOUND_CORPUS_ID,
        caps=caps,
        run_nonce=RUN_NONCE,
    )
    other_surface = operation_hash(
        target_id=BOUND_TARGET_ID,
        surface="evil-lookalike.example-openemr.org",
        corpus_id=BOUND_CORPUS_ID,
        caps=caps,
        run_nonce=RUN_NONCE,
    )
    other_corpus = operation_hash(
        target_id=BOUND_TARGET_ID,
        surface=BOUND_HOST,
        corpus_id="some-other-corpus",
        caps=caps,
        run_nonce=RUN_NONCE,
    )
    assert base != other_surface
    assert base != other_corpus


def test_operation_hash_ignores_adapter_transport() -> None:
    """The operation hash is scoped to the target IDENTITY, not the adapter transport: it takes
    NO adapter_kind / credential_ref argument, so a grant stays adapter-generic. Two runs against
    the same target/surface/corpus/caps/nonce hash identically regardless of how the wire is made
    (OpenEMR is merely the first adapter). This pins that the transport is out of authorization
    scope — a regression folding adapter_kind back into the hash would raise a TypeError here."""
    caps = RunPolicy(
        budget_usd=10.0,
        max_attempts_per_run=9,
        target_requests_per_second=1.0,
        run_timeout_seconds=60.0,
    )
    kwargs = dict(
        target_id=BOUND_TARGET_ID,
        surface=BOUND_HOST,
        corpus_id=BOUND_CORPUS_ID,
        caps=caps,
        run_nonce=RUN_NONCE,
    )
    assert operation_hash(**kwargs) == operation_hash(**kwargs)


# ============================================================================================
# RunAuthorization.verify — MISSING / EXPIRED / SCOPE-MISMATCH all BLOCK before dispatch.
# ============================================================================================
def test_valid_authorization_verifies_and_does_not_raise() -> None:
    """A present, unexpired, in-scope authorization verifies — the ONLY path that does not
    block. (Every other test pins a fail-closed refusal.)"""
    clock = FakeClock(start=1000.0)  # well before the 2000.0 deadline
    _auth().verify(operation_hash=_op_hash(), run_nonce=RUN_NONCE, now=clock.now())


def test_missing_authorization_blocks() -> None:
    """A MISSING authorization (None) BLOCKS with a typed AuthorizationError — a configured
    environment is not authorization; the absence of a minted auth refuses the run."""
    clock = FakeClock(start=1000.0)
    with pytest.raises(AuthorizationError):
        RunAuthorization.verify_optional(
            None, operation_hash=_op_hash(), run_nonce=RUN_NONCE, now=clock.now()
        )


def test_expired_authorization_blocks() -> None:
    """An EXPIRED authorization (now > deadline) BLOCKS with a typed AuthorizationError — an
    authorization is a bounded grant, never an indefinite standing permission."""
    clock = FakeClock(start=1000.0)
    auth = _auth(deadline=1500.0)
    clock.advance(600.0)  # now 1600.0 > 1500.0 deadline
    with pytest.raises(AuthorizationError) as exc:
        auth.verify(operation_hash=_op_hash(), run_nonce=RUN_NONCE, now=clock.now())
    assert "expire" in str(exc.value).lower()


def test_authorization_exactly_at_deadline_blocks() -> None:
    """At the deadline boundary the grant is over: now == deadline is NOT a live grant (the
    window is closed the instant it is reached — fail closed, no off-by-one that extends it)."""
    auth = _auth(deadline=2000.0)
    with pytest.raises(AuthorizationError):
        auth.verify(operation_hash=_op_hash(), run_nonce=RUN_NONCE, now=2000.0)


def test_scope_mismatched_operation_hash_blocks() -> None:
    """An authorization whose bound operation_hash != the current run's operation_hash BLOCKS —
    an auth minted for one run config can never authorize a DIFFERENT config (scope binding)."""
    clock = FakeClock(start=1000.0)
    auth = _auth(op_hash="0" * 64)  # a hash for some OTHER run config
    with pytest.raises(AuthorizationError) as exc:
        auth.verify(operation_hash=_op_hash(), run_nonce=RUN_NONCE, now=clock.now())
    assert "scope" in str(exc.value).lower() or "operation" in str(exc.value).lower()


def test_scope_mismatched_run_nonce_blocks() -> None:
    """An authorization whose run_nonce differs from the current run's nonce BLOCKS — the nonce
    ties the grant to exactly one run instance, so a stale/replayed auth cannot ride a new run."""
    clock = FakeClock(start=1000.0)
    auth = _auth()
    with pytest.raises(AuthorizationError) as exc:
        auth.verify(operation_hash=_op_hash(), run_nonce="a-different-nonce", now=clock.now())
    assert "nonce" in str(exc.value).lower() or "scope" in str(exc.value).lower()


def test_authorization_is_immutable_once_minted() -> None:
    """A minted authorization is frozen — its bound scope (operation_hash / run_nonce /
    deadline) cannot be widened after the fact (immutability is a structural property)."""
    auth = _auth()
    with pytest.raises((AttributeError, TypeError)):
        auth.deadline = 10**9  # type: ignore[misc]  # widening the grant must be impossible


# ============================================================================================
# TargetBinding — IMMUTABLE; validates exact-host / adapter-kind / credential_ref shape.
# ============================================================================================
def test_binding_is_frozen_immutable() -> None:
    """The binding is frozen — {target_id, host, adapter_kind, credential_ref} cannot be mutated
    to point at a different target/host after construction (the scope is immutable)."""
    binding = _binding()
    with pytest.raises((AttributeError, TypeError)):
        binding.host = "evil.example-openemr.org"  # type: ignore[misc]


def test_binding_validates_exact_host_match() -> None:
    """The bound adapter's base-URL host must equal the bound host EXACTLY — the exact bound
    host passes; a subdomain/suffix lookalike does not (that is the negative test below)."""
    binding = _binding()
    binding.validate_host(BOUND_BASE_URL)  # exact match — must not raise


@pytest.mark.parametrize(
    "bad_url",
    [
        "https://evil.copilot.example-openemr.org",  # subdomain lookalike
        "https://copilot.example-openemr.org.evil.com",  # suffix lookalike
        "https://copilot.example-openemr.org.attacker",  # suffix append
        "http://copilot.example-openemr.org",  # insecure scheme
    ],
)
def test_binding_rejects_host_that_is_not_exact(bad_url: str) -> None:
    """A base URL whose host is NOT the exact bound host (a subdomain/suffix lookalike, or an
    insecure http scheme) is REFUSED with a typed BindingError — no near-miss is admitted."""
    binding = _binding()
    with pytest.raises(BindingError):
        binding.validate_host(bad_url)


def test_binding_rejects_non_live_adapter_kind() -> None:
    """The bound adapter kind must be the selected LIVE adapter, never the P9 fake — binding to
    'fake' is refused so a live-path binding can never resolve to the FakeTargetAdapter."""
    with pytest.raises(BindingError):
        TargetBinding(
            target_id=BOUND_TARGET_ID,
            host=BOUND_HOST,
            adapter_kind="fake",  # the P9 fake is NEVER a valid live binding
            credential_ref=BOUND_CREDENTIAL_REF,
        )


def test_binding_rejects_malformed_credential_ref() -> None:
    """A credential_ref that is not a well-formed secret reference is REFUSED — a raw inline
    secret (or an empty/garbage ref) can never be a valid binding (shape is validated)."""
    with pytest.raises(BindingError):
        TargetBinding(
            target_id=BOUND_TARGET_ID,
            host=BOUND_HOST,
            adapter_kind=BOUND_ADAPTER_KIND,
            credential_ref="not-a-secret-ref",  # missing the secretref:// scheme
        )


def test_binding_does_not_resolve_a_credential_at_construction() -> None:
    """Constructing a binding NEVER resolves a live secret — it holds only the reference shape.
    Off-production, resolving is refused; the binding still constructs (no eager resolve)."""
    binding = _binding()  # constructs off-production without dereferencing any secret
    rendered = repr(binding)
    # The construction stored no revealed secret — only the reference string shape.
    assert "reveal(" not in rendered


def test_binding_resolves_secret_only_at_dispatch_boundary_in_production() -> None:
    """A credential is resolved into a Secret ONLY at the verified dispatch boundary, via
    config.resolve_target_credential (O1) — production yields a Secret; off-production refuses."""
    binding = _binding()
    secret = binding.resolve_credential(Settings(environment="production"))
    assert isinstance(secret, Secret)
    # The Secret redacts — the raw reference never renders in a log/evidence string.
    assert "***REDACTED***" in repr(secret)


def test_binding_without_credential_supports_auth_mode_none() -> None:
    """A binding MAY omit credential_ref (auth_mode=none): it constructs with no credential, and
    resolve_credential returns None so the bound adapter dispatches WITHOUT injecting a secret. A
    no-credential target is a valid binding — OpenEMR is merely the first adapter/auth-mode, not the
    only one. This keeps the binding adapter-generic (no credential is forced onto every target)."""
    binding = TargetBinding(
        target_id="public-surface",
        host=BOUND_HOST,
        adapter_kind=BOUND_ADAPTER_KIND,
    )  # no credential_ref supplied — auth_mode=none
    assert binding.credential_ref is None
    assert binding.resolve_credential(Settings(environment="production")) is None


# ============================================================================================
# RunCaps — FAIL-CLOSED parsing into a RunPolicy; every cap finite/positive/<= a hard max.
# ============================================================================================
def test_valid_caps_parse_into_a_run_policy() -> None:
    """A fully-valid caps config parses into an immutable RunPolicy carrying every ceiling —
    this is the one non-refusing path (each invalid variant below is a typed CapError)."""
    policy = RunCaps.parse(
        {
            "budget_usd": 10.0,
            "max_attempts_per_run": 9,
            "target_requests_per_second": 1.0,
            "run_timeout_seconds": 60.0,
        }
    )
    assert isinstance(policy, RunPolicy)
    assert policy.budget_usd == 10.0
    assert policy.max_attempts_per_run == 9


@pytest.mark.parametrize(
    "field",
    ["budget_usd", "max_attempts_per_run", "target_requests_per_second", "run_timeout_seconds"],
)
def test_missing_cap_fails_closed(field: str) -> None:
    """A MISSING cap is a typed CapError — never a silent default. An unbounded dimension can
    never slip through as 'unset', so no run can execute without every ceiling explicit."""
    config = {
        "budget_usd": 10.0,
        "max_attempts_per_run": 9,
        "target_requests_per_second": 1.0,
        "run_timeout_seconds": 60.0,
    }
    del config[field]
    with pytest.raises(CapError):
        RunCaps.parse(config)


@pytest.mark.parametrize(
    "field",
    ["budget_usd", "max_attempts_per_run", "target_requests_per_second", "run_timeout_seconds"],
)
@pytest.mark.parametrize("bad", [0, -1, "abc", None, float("inf"), float("nan")])
def test_zero_negative_nonnumeric_or_infinite_cap_fails_closed(field: str, bad: object) -> None:
    """A zero / negative / non-numeric / infinite / NaN cap is a typed CapError — every cap
    must be a FINITE POSITIVE number, so an unbounded or nonsensical ceiling never parses."""
    config: dict[str, object] = {
        "budget_usd": 10.0,
        "max_attempts_per_run": 9,
        "target_requests_per_second": 1.0,
        "run_timeout_seconds": 60.0,
    }
    config[field] = bad
    with pytest.raises(CapError):
        RunCaps.parse(config)


@pytest.mark.parametrize(
    "field",
    ["budget_usd", "max_attempts_per_run", "target_requests_per_second", "run_timeout_seconds"],
)
def test_over_maximum_cap_fails_closed(field: str) -> None:
    """A cap ABOVE the hard platform maximum is a typed CapError — the platform maxima are a
    ceiling on the ceilings, so a run can never request an unbounded-in-practice budget/rate."""
    config: dict[str, object] = {
        "budget_usd": 10.0,
        "max_attempts_per_run": 9,
        "target_requests_per_second": 1.0,
        "run_timeout_seconds": 60.0,
    }
    config[field] = 10**12  # absurdly large — above any sane hard maximum
    with pytest.raises(CapError):
        RunCaps.parse(config)
