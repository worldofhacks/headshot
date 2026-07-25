# WP-18B — Governed WebSocket, SSE, browser, and DOM testing

**Branch:** `rtg/wp18b-browser-streaming`

**Model:** capable

**Depends on:** WP-01, WP-03, WP-11, WP-12, WP-16A, WP-16D

**Implements toward (live validation pending):** WebSocket/DOM/Clickbandit/Infiltrator portions of RT-06

**Implementation writes only**

- `src/agentforge/target/stream_surface_adapter.py`
- `src/agentforge/security_tools/streaming.py`
- `src/agentforge/security_tools/browser_harness.py`
- `src/agentforge/security_tools/dom_oracles.py`
- `src/agentforge/security_tools/clickjacking.py`
- `src/agentforge/contracts/v1/stream_test_plan.json`
- `src/agentforge/contracts/v1/browser_test_plan.json`
- `src/agentforge/contracts/v1/clickjacking_test_plan.json`

**Test writes only**

- `tests/security_tools/test_streaming.py`
- `tests/security_tools/test_browser_harness.py`
- `tests/security_tools/test_dom_oracles.py`
- `tests/security_tools/test_clickjacking.py`
- `tests/security_tools/test_browser_local_process.py`
- `tests/vectors/browser/**`

## Required result

Extend WP-12's frozen `stream_surface_adapter.py`; do not create another streaming
transport, client, DNS path, or authorization seam.

WebSocket authorization binds handshake, origin, path, subprotocol, principal, templates,
frame count/bytes, duration, extensions, and callbacks. Recheck WP-01 before handshake and
every outbound frame. Record bounded sanitized frame hashes/close codes. Deny redirect,
origin change, unsafe extension, over-limit frame, and unapproved reconnect.

SSE authorization counts initial request, reconnects, bytes, events, duration, retry, and
`Last-Event-ID`. Abort closes immediately; session changes are immutable inputs.

The browser harness runs in a disposable isolated process/container with no user profile,
Clerk session, filesystem, clipboard, downloads, extensions, service-worker persistence,
local-network/metadata access, or alternate egress. Every navigation, subresource, and
socket must remain within governed origins and enter WP-16A capture/history.
All browser/process traffic must traverse WP-16D; injected browser doubles alone cannot
establish egress isolation or an operational state.

Use fixed reviewed probes—not operator JavaScript—to observe HTML/Markdown/URL rendering,
DOM XSS sinks, `postMessage` origins, prototype pollution, unsafe navigation, stored/
reflected canaries, DOM clobbering, clickjacking headers, and downstream sinks. Generate a
fixed declarative Clickbandit-style clickjacking test plan with bounded frame/overlay/click
steps, exact origin, and no arbitrary script; execution still requires browser
authorization. Observations are evidence, not verdicts. Artifacts require synthetic
attestation, sanitation, hashes, and limits.
Owner-provided runtime instrumentation may be used only through a versioned, signed WP-12
surface/collector contract; otherwise Infiltrator-style runtime instrumentation is
truthfully `blocked_missing_contract`, not simulated. Browser/DOM/Clickbandit remain
`partial` until the deployed real-process isolation gate and applicable WP-21D live evidence
pass.

Tests cover abort during frames/reconnect, floods/compression bombs, cross-origin escape,
service workers, popup/download/file/local-network access, malicious `postMessage`,
prototype keys, DOM clobbering, stale sessions, unsafe DOM rendering, clickjacking plan
origin/overlay abuse, and browser-network/ledger parity.
Local browser checks are non-evidentiary implementation prechecks. Browser/streaming
operational status requires WP-21D to run the exact pinned isolated browser in the deployed
private runtime against the exact authorized live surface through WP-16D, with live
navigation/subresource/frame/reconnect and permit/send/ledger parity. If the pinned browser,
live surface, or authorization is unavailable, preserve `blocked_live_browser_evidence`;
never substitute a loopback page or fake target.

Direct-validate new schemas in this package; WP-19B owns final registry/package parity.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_streaming.py tests/security_tools/test_browser_harness.py tests/security_tools/test_dom_oracles.py tests/security_tools/test_clickjacking.py tests/security_tools/test_browser_local_process.py -q
```
