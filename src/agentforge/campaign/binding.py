"""TargetBinding — an IMMUTABLE binding of a run to ONE target/host/adapter/credential.

M11-coordinator (ARCHITECTURE.md §5 live-campaign gate F5/F7, S3; DECISIONS.md D16).

A :class:`TargetBinding` freezes the facts a live run must never drift on:
``{target_id, host, adapter_kind, credential_ref}``. It validates, at construction:

* the **adapter kind** is a live adapter, NEVER the P9 ``fake`` — a live-path binding can never
  resolve to the :class:`~agentforge.target.fake_adapter.FakeTargetAdapter`;
* the **auth_mode** and **credential_ref** AGREE: ``auth_mode=none`` FORBIDS a credential
  (``credential_ref=None``), while ``bearer``/``session``/``oauth`` REQUIRE a well-formed
  ``secretref://`` reference — a *missing* reference must never silently imply no-auth; and
* the **credential_ref**, when present, is a well-formed ``secretref://`` reference (a shape,
  never an inline secret). For an ``auth_mode=none`` target :meth:`resolve_credential` returns
  ``None`` and the bound live adapter dispatches without injecting a secret.

OpenEMR is merely the FIRST adapter this binding wires. The full target/adapter REGISTRY — many
targets, each with its own adapter kind / auth mode / surface — is a POST-M11 integration; its
source is the ``codex/target-agnostic-core`` branch (recorded here as the post-M11 integration
lane). Do NOT expand this binding into that registry inside the M11 timebox; this module stays
deliberately single-target and adapter-generic at its seams so the registry can graft on later
without reworking the authorization/binding contract.

At dispatch time :meth:`validate_host` enforces an EXACT-host match against the selected
adapter's base URL — no subdomain/suffix lookalike, and no insecure ``http://`` scheme is
admitted. The host must match byte-for-byte, so ``evil.copilot.example-openemr.org`` and
``copilot.example-openemr.org.evil.com`` are both refused.

Credentials resolve into a :class:`~agentforge.secrets.Secret` ONLY at the verified dispatch
boundary, via :meth:`resolve_credential` → :meth:`Settings.resolve_target_credential` (O1) →
:class:`~agentforge.policy.credentials.CredentialBinding`. Constructing a binding NEVER
dereferences a secret; off-production a resolve is refused entirely (the O1 isolation boundary).

Framework-neutral core: stdlib + config/secrets/credentials only; no web framework, no network.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from urllib.parse import urlsplit

from agentforge.config import Settings
from agentforge.policy.credentials import CredentialBinding
from agentforge.secrets import Secret

# The scheme every live target MUST be reached over — an insecure http:// target is refused.
_REQUIRED_SCHEME = "https"

# The P9 deterministic fake is NEVER a valid live binding: a live-path binding that resolved to
# the fake would be a live-to-fake fallback, which this platform forbids by construction.
_FORBIDDEN_ADAPTER_KIND = "fake"

# A well-formed credential reference is a secretref:// handle (never an inline secret value).
_CREDENTIAL_REF_SCHEME = "secretref://"

# The auth modes a binding may declare. ``none`` is a no-credential target; every other mode
# REQUIRES a matching credential reference — a missing reference must never silently imply no-auth.
_NO_AUTH_MODE = "none"
_CREDENTIAL_AUTH_MODES = frozenset({"bearer", "session", "oauth"})
_AUTH_MODES = frozenset({_NO_AUTH_MODE}) | _CREDENTIAL_AUTH_MODES

# The operation-hash marker bound for a no-credential (auth_mode=none) target — an EXPLICIT
# no-auth marker, so a no-credential run is content-addressed just as a credentialed one is.
_NO_AUTH_MARKER = "no-auth"
# The op-hash marker prefix for a credentialed target — a sha256 DIGEST of the credential
# reference (the reference is not a secret, but a digest canonically binds the exact ref without
# embedding it and keeps the marker fixed-width regardless of the ref's length).
_CREDENTIAL_MARKER_PREFIX = "cred-sha256:"


class BindingError(Exception):
    """Raised when a target binding is invalid or does not match the selected adapter.

    A dedicated, catchable type so a fail-closed binding refusal (host/adapter/credential
    mismatch) is distinguishable from an incidental bug. The message names the mismatch so the
    refusal is legible in a log or a traceback.
    """


@dataclass(frozen=True)
class TargetBinding:
    """A frozen binding of one run to one target/host/adapter/credential reference.

    Frozen so the bound facts cannot be mutated to point at a different target/host after
    construction — the scope is immutable. ``__post_init__`` validates the adapter kind and (when
    present) the credential-reference shape up front; the exact-host match is enforced at dispatch
    time against the selected adapter's base URL by :meth:`validate_host`.
    """

    target_id: str
    host: str
    adapter_kind: str
    # Optional: None binds an auth_mode=none target (no credential). A present ref is validated
    # as a secretref:// shape — a supplied credential is a reference, never an inline value.
    credential_ref: str | None = None
    # How the target is authenticated: ``none`` (no credential) or a credential mode
    # (bearer/session/oauth). The mode and the credential-reference presence must AGREE — see
    # ``__post_init__``. Defaults to ``none`` so a credential is never admitted without an
    # explicitly-declared auth mode (fail closed: a stray ref can't silently authenticate a run).
    auth_mode: str = _NO_AUTH_MODE

    def __post_init__(self) -> None:
        if self.adapter_kind == _FORBIDDEN_ADAPTER_KIND:
            raise BindingError(
                "a live binding may not bind the P9 fake adapter kind "
                f"{_FORBIDDEN_ADAPTER_KIND!r} — a live-path binding can never resolve to the "
                "FakeTargetAdapter (no live-to-fake fallback)"
            )
        if not isinstance(self.adapter_kind, str) or not self.adapter_kind.strip():
            raise BindingError(
                f"adapter_kind {self.adapter_kind!r} is not a valid live adapter kind"
            )
        self._validate_auth_mode_and_credential()

    def _validate_auth_mode_and_credential(self) -> None:
        """Enforce that ``auth_mode`` and ``credential_ref`` AGREE — the load-bearing invariant.

        * ``auth_mode`` must be a known mode.
        * ``none`` FORBIDS a credential_ref — a credential with no declared auth mode is a
          contradiction (a stray reference must not ride a run that claims to be unauthenticated).
        * ``bearer``/``session``/``oauth`` REQUIRE a well-formed ``secretref://`` credential_ref —
          a *missing* reference must never silently imply no-auth (that is the exact failure this
          guard exists to prevent). A present reference is validated for shape.
        """
        if self.auth_mode not in _AUTH_MODES:
            raise BindingError(
                f"auth_mode {self.auth_mode!r} is not a known auth mode "
                f"(one of {sorted(_AUTH_MODES)!r}) — an unrecognized mode is refused (fail closed)"
            )
        if self.auth_mode == _NO_AUTH_MODE:
            if self.credential_ref is not None:
                raise BindingError(
                    "auth_mode 'none' forbids a credential_ref — a no-auth target binds no "
                    "credential; a stray reference on a no-auth run is refused (fail closed)"
                )
            return
        # A credential auth mode REQUIRES a matching reference — never silently no-auth.
        if self.credential_ref is None:
            raise BindingError(
                f"auth_mode {self.auth_mode!r} REQUIRES a credential_ref — a missing reference "
                "must never silently imply no-auth (fail closed)"
            )
        self._validate_credential_ref(self.credential_ref)

    @staticmethod
    def _validate_credential_ref(credential_ref: str) -> None:
        """Refuse a credential_ref that is not a well-formed ``secretref://`` reference.

        A raw inline secret, an empty ref, or a garbage handle can never be a valid binding — a
        credential enters the process only as a *reference* the secret manager dereferences at
        use time, never as an inlined value.
        """
        if not isinstance(credential_ref, str) or not credential_ref.startswith(
            _CREDENTIAL_REF_SCHEME
        ):
            raise BindingError(
                f"credential_ref {credential_ref!r} is not a well-formed secret reference "
                f"(must begin with {_CREDENTIAL_REF_SCHEME!r}) — a raw inline secret or garbage "
                "ref can never be a valid binding"
            )
        tail = credential_ref[len(_CREDENTIAL_REF_SCHEME) :]
        if not tail.strip():
            raise BindingError(
                f"credential_ref {credential_ref!r} has an empty reference path — a valid "
                "reference names the secret it resolves"
            )

    def credential_marker(self) -> str:
        """The authorization-scope marker for this binding's credential (bound into the op-hash).

        Returns an EXPLICIT ``no-auth`` marker for an ``auth_mode=none`` target, or a
        ``cred-sha256:<digest>`` marker (a sha256 of the credential reference) for a credentialed
        one. Either way the marker is content-addressed: two runs that differ in auth mode /
        credential reference produce different markers, so a grant minted for one can never
        authorize the other. The raw reference is never embedded — only its digest — and no secret
        VALUE is ever involved (a ``secretref://`` reference is a handle, not a secret).
        """
        if self.credential_ref is None:
            return _NO_AUTH_MARKER
        digest = hashlib.sha256(self.credential_ref.encode("utf-8")).hexdigest()
        return f"{_CREDENTIAL_MARKER_PREFIX}{digest}"

    def host_base_url(self) -> str:
        """The canonical ``https://<host>`` base URL the bound live adapter must be built at.

        A convenience for constructing the bound adapter so its base-URL host is the exact bound
        host — :meth:`validate_host` then re-checks the constructed adapter's URL at dispatch time.
        """
        return f"{_REQUIRED_SCHEME}://{self.host}"

    def validate_host(self, base_url: str) -> None:
        """BLOCK unless ``base_url``'s host equals the bound host EXACTLY over ``https``.

        The comparison is byte-exact on the host and requires the ``https`` scheme, so a
        subdomain lookalike (``evil.copilot.example-openemr.org``), a suffix lookalike
        (``copilot.example-openemr.org.evil.com``), and an insecure ``http://`` variant are all
        refused with a typed :class:`BindingError`. No near-miss is admitted.
        """
        parts = urlsplit(base_url)
        if parts.scheme != _REQUIRED_SCHEME:
            raise BindingError(
                f"target base URL {base_url!r} must use the {_REQUIRED_SCHEME!r} scheme — an "
                "insecure scheme is refused (fail closed)"
            )
        if parts.hostname != self.host:
            raise BindingError(
                f"target base URL host {parts.hostname!r} does not EXACTLY match the bound host "
                f"{self.host!r} — a subdomain/suffix lookalike is refused (fail closed)"
            )

    def resolve_credential(self, settings: Settings) -> Secret | None:
        """Resolve the bound credential into a :class:`Secret` at the dispatch boundary (O1).

        Returns ``None`` for an ``auth_mode=none`` binding (no ``credential_ref``): the bound live
        adapter then dispatches without injecting a secret — the absence of a credential is a valid
        binding, not a failure. When a credential IS bound, resolution is delegated to a scoped
        :class:`~agentforge.policy.credentials.CredentialBinding`, which enforces the O1 isolation
        boundary: in production it returns a redacting :class:`Secret` wrapping a ``secretref://``
        handle; in local/staging it refuses with
        :class:`~agentforge.config.EnvironmentIsolationError`. The raw reference is never inlined or
        logged — only the redacting :class:`Secret` leaves this method.
        """
        if self.credential_ref is None:
            return None
        binding = CredentialBinding(target_id=self.target_id, secret_ref=self.credential_ref)
        return binding.resolve(self.target_id, settings)
