# WP-16D — Enforce governed egress for native scanner and browser processes

**Branch:** `rtg/wp16d-governed-process-egress`

**Model:** capable

**Depends on:** WP-01, WP-03, WP-08

**Implements toward (live validation pending):** process-egress foundation for RT-05 and RT-06

Read the physical permit, pinned transport, ownership verifier, native process wrapper,
outbound ledger, ZAP/browser plans, and alternate-egress findings.

**Implementation writes only**

- `src/agentforge/security_tools/process_egress.py`
- `src/agentforge/security_tools/governed_proxy.py`
- `src/agentforge/security_tools/process_sandbox.py`
- `src/agentforge/contracts/v1/governed_egress_plan.json`
- `src/agentforge/contracts/v1/governed_egress_observation.json`
- `security-tools/egress/**`

**Test writes only**

- `tests/security_tools/test_process_egress.py`
- `tests/security_tools/test_governed_proxy.py`
- `tests/security_tools/test_process_sandbox.py`
- `tests/security_tools/test_process_egress_integration.py`

## Required result

Define one frozen process-egress interface for ZAP, browsers, and native LLM tools. A child
receives no target credential, URL authority, unrestricted proxy, host network, DNS, or
environment proxy. It can address only a loopback authenticated IPC/proxy endpoint whose
immutable plan binds process/image/tool hash, target/surface/version, methods/paths/
protocols, principal, corpus, authorization, caps, expiry, and callback policy.

For each HTTP request, redirect candidate, browser navigation/subresource, SSE reconnect,
and WebSocket handshake/outbound frame, the mediator must:

1. parse a bounded canonical operation without trusting child-provided authority;
2. resolve/validate/pin through WP-03;
3. obtain a fresh WP-01 persisted permit with WP-08 revalidation and final caps;
4. resolve credentials only inside the governed transport;
5. perform the constrained send and record exact permit/send/delivery lineage.

Reject unsupported CONNECT tunnels, raw destination IPs, alternate DNS, UDP, QUIC, proxy
chaining, environment proxies, local/private/metadata escape, unregistered origins,
post-upgrade raw sockets, and opaque protocols. If a protocol cannot be mediated and
counted, that tool mode remains disabled.

Local process/container checks may exercise the interface and direct-egress denial, but are
non-evidentiary implementation prechecks. They cannot establish `process_egress_proven`.
That state requires WP-21B, WP-21C, or WP-21D to run the exact deployed private Railway
runtime and genuine pinned tool/ZAP/browser process against the exact authorized deployed
target, with direct-egress-denial attestation and one-to-one child-operation, permit,
physical-send, and ledger parity. Until then retain
`profile_validated`/`blocked_live_process_evidence`.

Tests cover process escape, proxy/credential leakage, Host/SNI drift, DNS rebinding,
redirects, CONNECT/upgrade confusion, frame/reconnect accounting, abort/expiry races,
child crash, forged acknowledgements, cap concurrency, and sanitized errors. Direct-
validate schemas; WP-19B owns final registry/package parity.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_process_egress.py tests/security_tools/test_governed_proxy.py tests/security_tools/test_process_sandbox.py tests/security_tools/test_process_egress_integration.py -q
```

No external network, target, scanner image pull, browser download, package installation,
or provider call. Any local vectors/processes validate code only and must remain
`LIVE_EVIDENCE_REQUIRED`.

**Handoff:** WP-13E, WP-17, and WP-18B must use this interface and cannot create a second
process proxy or network client.
