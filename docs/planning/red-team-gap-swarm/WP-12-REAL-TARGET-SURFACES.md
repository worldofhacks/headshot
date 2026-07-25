# WP-12 — Register real, versioned LLM target surfaces

> **Horizon 2 — deferred (2026-07-25).** This package is **out of the current delivery scope** and
> nothing in it may be counted toward a coverage, capability, or closure claim. Design retained; not
> dispatched. It was never dispatched: `.tdd-swarm/reports/RTG-orchestrator.md:5-6` records the
> gap-swarm as `BLOCKED(base-precondition)`, held at Wave 0 entry. It also depends on
> [WP-11](WP-11-TRUSTED-OBSERVATIONS.md), which is likewise Horizon 2.
>
> **What does not exist at base `107c11c`:** `src/agentforge/target/surface_contracts.py`,
> `http_surface_adapter.py`, `stream_surface_adapter.py`, the whole `src/agentforge/platform/` package,
> both surface-contract schemas, and `docs/integration/OPENEMR_SURFACE_CONTRACT.md`. The
> capability-state vocabulary (`declared_unverified` / `live_validated` / `unsupported` /
> `blocked_missing_contract`) appears only inside this document's prose — it is not implemented
> anywhere. Note that [WP-18B](WP-18B-BROWSER-STREAMING.md) instructs a later lane to "extend WP-12's
> frozen `stream_surface_adapter.py`"; that file does not exist, and nothing in `src/` implements a
> target-side SSE/WebSocket surface.
>
> **The one genuinely small, genuinely valuable part is not code.** The Week 2 upload/read/RAG surfaces
> already exist in the committed catalogs with `enabled: false`
> (declared at `config/live-target-catalog.production.json:222`, `:253`, `:284`; `"enabled": false` at `:250`, `:281`, `:312`). Enabling them is a
> **target-authorization change** — a human decision requiring a fresh exact-scope grant — not an
> implementation task, and it is the highest find-power move available against the real target (RT-07).
> Track it separately from this package so it is not blocked behind Horizon 2 code.
>
> Also Horizon 2 by the owner's locked decision, and dependent on this package: the `attack-case.v2`
> schema stack and the OWASP Agentic (ASI01–ASI10) taxonomy. ASI is not in the graded requirement.
>
> See `docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md` RT-07 and its *Horizon 2* section.

**Branch:** `rtg/wp12-real-target-surfaces`

**Model:** capable

**Depends on:** WP-03, WP-08, WP-11 — **WP-11 is Horizon 2**

**Implements toward (live validation pending):** RT-07 — **still open; see the Horizon 2 note above**

Read target spec/catalog/registry/binding, the owner-provided OpenEMR Clinical Co-Pilot
surface contract if present, RT-07, and WP-11 observation interfaces. Never infer routes
from attack-case prose.

**Implementation writes only**

- `src/agentforge/target/surface_contracts.py`
- `src/agentforge/target/http_surface_adapter.py`
- `src/agentforge/target/stream_surface_adapter.py`
- `src/agentforge/target/spec.py`
- `src/agentforge/target/catalog.py`
- `src/agentforge/target/adapter_registry.py`
- `src/agentforge/platform/surface_contracts.py`
- `src/agentforge/platform/observation_points.py`
- `src/agentforge/campaign/binding.py`
- `src/agentforge/contracts/v1/target_surface_contract.json`
- `src/agentforge/contracts/v1/platform_surface_contract.json`
- `docs/integration/OPENEMR_SURFACE_CONTRACT.md`

**Test writes only**

- `tests/target/test_surface_contracts.py`
- `tests/target/test_http_surface_adapter.py`
- `tests/target/test_stream_surface_adapter.py`
- `tests/platform/test_surface_contracts.py`
- `tests/platform/test_observation_points.py`
- `tests/test_surface_authorization.py`

## Required result

Support independent, versioned capabilities for:

- chat;
- ingestion/upload/indexing;
- retrieval/query with source/scope telemetry;
- conversation memory and principal/session switching;
- tool discovery/selection/arguments/authorization/execution/side effects;
- controlled live write sandbox containing only seeded synthetic non-PHI records;
- rendered HTML/Markdown/link/downstream sinks;
- SSE/WebSocket streaming when actually supported.

Also register non-network `subject=platform` surfaces for inter-agent messages, memory/
context reads and writes, provider/tool brokerage, approval/human handoffs, and cascading-
failure containment. Each binds an exact producer, consumer, schema/version, trust
boundary, authorization/control point, pre/post WP-11 observations, caps, and reset/
rollback behavior. These surfaces use internal governed adapters only; they can never fall
back to a target `/chat` route or inherit target-dispatch authority.

Each contract binds exact route/method/protocol/content type/schema hashes, auth mode and
credential reference, target/surface version, capability state (`declared_unverified`,
`live_validated`, `unsupported`, `blocked_missing_contract`), seeded synthetic non-PHI
live-resource allowlist,
side-effect/cleanup policy, WP-11 collector/oracle refs, taxonomy refs, caps, redirect/
private-network policy, and WP-08 ownership authorization.

One authorization scope covers one exact surface; there is no wildcard multi-surface scope.
Upload/write defaults disabled and requires non-PHI bytes, exact seeded live resource
IDs/hashes, bounded types/size, pre/post observation, cleanup, and explicit permission.

If the owner contract is absent, implement staged validation and return
`DONE_WITH_CONCERNS`; never invent or activate endpoints. Chat approximations remain
`unsupported_for_surface` and cannot create evidence. Missing surface support never falls
back to `/chat`.

Tests use non-PHI contract vectors with all sockets disabled. They are implementation
prechecks only and cannot set `live_validated`, `operational`, or any coverage stage. Cover
method/path/schema drift,
smuggling, redirects, wrong principal/tenant/patient/session, write without exact resource,
stream bounds/abort, declared-versus-live state, inter-agent sender confusion, memory
poisoning, broker/handoff authority drift, cascade limits, and compatible observation
requirements. Direct-validate new schemas; WP-19B owns final registry/package parity.

Only WP-21C or WP-21D may set `live_validated`, after a successful contract handshake and
observed authorized request against the exact deployed surface through the production path.
Missing live proof is `blocked_live_surface_evidence`, never a local adapter substitute.

**Focused verifier**

```bash
python -m pytest tests/target/test_surface_contracts.py tests/target/test_http_surface_adapter.py tests/target/test_stream_surface_adapter.py tests/platform/test_surface_contracts.py tests/platform/test_observation_points.py tests/test_surface_authorization.py -q
```

**Handoff:** WP-14 binds cases only to compatible surfaces; WP-17 scans registered Web/API
surfaces; WP-20A connects adapters to the physical-dispatch gate.
