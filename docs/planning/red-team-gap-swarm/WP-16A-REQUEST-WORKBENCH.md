# WP-16A — Governed capture, editor, replay, history, and Comparer

**Branch:** `rtg/wp16a-request-workbench`

**Model:** capable

**Depends on:** WP-01, WP-03, WP-10, WP-12

**Implements toward (live validation pending):** core of RT-06

Read outbound telemetry, current workbench labels, target/surface contracts, authorization
workflow, PortSwigger's literal Proxy/Repeater/Comparer behavior, and RT-06.

**Implementation writes only**

- `src/agentforge/security_tools/http_message.py`
- `src/agentforge/security_tools/request_workbench.py`
- `src/agentforge/security_tools/http_diff.py`
- `src/agentforge/security_tools/workbench_repository.py`
- `src/agentforge/storage/models.py`
- `migrations/versions/<MIGRATION_REV>_request_workbench.py`
- `src/agentforge/contracts/v1/workbench_capture.json`
- `src/agentforge/contracts/v1/workbench_dispatch_operation.json`
- `src/agentforge/contracts/v1/workbench_template.json`
- `src/agentforge/contracts/v1/workbench_replay_plan.json`
- `src/agentforge/contracts/v1/workbench_observation.json`

**Test writes only**

- `tests/security_tools/test_request_workbench.py`
- `tests/security_tools/test_http_diff.py`
- `tests/security_tools/test_workbench_repository.py`

## Required result

Implement:

1. organization-scoped capture of an opaque, content-addressed, credential-free canonical
   dispatch operation plus a separately sanitized UI projection;
2. a governed internal intercept state machine before physical dispatch, with immutable
   `paused`, `dropped`, `superseded`, and `forwarded_as_new_plan` decisions;
3. immutable captured-message and derived-template records;
4. safe structured request editing and reviewed, bounded match/replace rules;
5. single-message and bounded-sequence replay plans;
6. append-only HTTP and WebSocket history and annotations;
7. byte, word, header, JSON, status, timing, and normalized semantic diffs.

Never reconstruct execution bytes from a redacted preview. The canonical operation is
created before ephemeral credential/hop-header injection, is not rendered to users, and
can be replayed only by the governed transport. The sanitized projection carries explicit
redacted/omitted markers and is the only UI/search/report input.

There is no unauthenticated public proxy listener. Intercept is an internal plan boundary:
drop sends nothing; an unchanged forward still needs a fresh WP-01 permit; any edit or
match/replace result creates a new content-addressed plan and invalidates prior approval.
No user action can forward an arbitrary raw socket request.

This is a `governed_analogue`/`partial` Proxy and Repeater, not literal Burp parity.
Bidirectional raw MITM interception, response editing, CA generation/trust, invisible/
transparent proxying, arbitrary-message replay, and unrestricted raw HTTP mutation are
explicitly unsupported.

Never reconstruct a secret. Editing creates a new content-addressed template; it never
changes a capture. Target/origin, credential, authorization, cookie, Host, routing,
hop-by-hop, transfer, and length fields are protected. Authentication changes use approved
synthetic principal-profile references.

Saving/editing cannot dispatch. Replay creates an authorization-blocked plan binding exact
template/sequence, target/surface/version, principal, corpus, caps, and expiry. Execution is
deferred to WP-20A through WP-01. Stale capture/target, changed template, abort, lease loss,
or scope mismatch must yield zero calls.

Diffs are deterministic/bounded, safe for duplicate headers/binary/large inputs, and
distinguish redacted/omitted from equal. An annotation cannot set authorization, severity,
verdict, or publication.

Tests cover cross-org reads, forged ledger refs, post-approval mutation, secret/redaction
markers, binary/large messages, duplicate headers, protected-field edits, sequence
interruption, stale versions, idempotency, and bounded diff complexity.
Also prove dispatch uses the canonical operation rather than the sanitized projection,
credential injection is ephemeral, and no redacted byte can be reconstructed.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_request_workbench.py tests/security_tools/test_http_diff.py tests/security_tools/test_workbench_repository.py tests/test_migrations.py tests/test_readiness_m1d.py -q
```

Direct-validate new schemas in this package; WP-19B owns final registry/package parity.

**Handoff:** WP-16B consumes derived templates; WP-17 consumes replay/API manifests;
WP-20A/B/C add governed execution, authenticated API, and console.
