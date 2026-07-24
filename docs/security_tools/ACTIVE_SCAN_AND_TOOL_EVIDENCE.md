# Active scanning + per-tool execution evidence — engine notes & Codex handoff

Scope of this change set: the **security-tooling / scanning engines** lane only. It adds the
real (active, non-passive) scanning chain and per-tool execution evidence as **code + offline
tests, default-disabled**. No console/UI, no API render surface (except the one additive
`ToolScopeReadModel` block noted below), no Judge/Documentation, no eval-corpus, no infra.

Everything here is offline and deterministic. **Nothing in this change set sends to a target or
runs a container.** A live active scan runs only in the private Runner under a *separately minted,
owner-authorized* grant (see "Status" at the bottom).

---

## New modules (`src/agentforge/security_tools/`)

| Module | Purpose | Guardrails enforced |
|---|---|---|
| `active_authorization.py` | `ActiveScanAuthorization` — a **separate**, expiring, frozen, content-addressed grant for active scanning; `ActiveScanScope` value object; `ActiveScanCaps` fail-closed parser | A campaign `RunAuthorization` never authorizes active scanning. `operation_hash` binds origin + methods + paths + principals + image/addon/rule digests + OAST domains + caps + nonce; any change rebinds the grant. `verify()` = expiry → op-hash → nonce, fail-closed. |
| `zap_profiles.py` | Real **active** ZAP command construction (`zap-api-scan.py`) + `validate_active_scan_target` origin deny-list + pinned Automation-Framework active-rule subset | Separate from passive `zap.py` (which stays passive-only forever). Command builds **only** behind a verified grant, with the pinned image + rule digests. Denies identity-provider, cloud-metadata, private/loopback/link-local, non-https, credentialed, and non-approved origins. |
| `scan_egress.py` | WP-16D **governed egress** — fresh per-request permit + scanner↔permit↔send↔ledger parity | Every physical send crosses `reserve_permit` (abort + method/path scope + request/rate caps re-checked BEFORE the send), then `report_send` records exactly one ledger entry (returned/raised; failed sends still count). `assert_parity()` fails closed if 1:1 cannot be proven. |
| `oast.py` | WP-18A **private per-attempt OAST** for out-of-band SSRF/exfil proof | Own private OAST only (no public collaborator). Per-attempt label derived from operation hash + attempt id + scope nonce (unpredictable). Callback domain must be authorized + private; unminted/off-domain callback = escape, fail-closed. |
| `api_discovery.py` | Content-addressed, **scope-bounded** OpenAPI surface discovery | Discovered ops are intersected with the authorized scope — an op the grant did not authorize is dropped, never scanned. Order-independent surface digest; bounded parse; fail-closed on malformed spec. |
| `auth_matrix.py` | Authenticated-scan matrix (principals × auth modes) | Binds each cell to a credential **marker** (`no-auth` / `cred-sha256:<digest>`), never a raw secret; only `secretref://` / `env:` references accepted; off-scope principals refused; content-addressed. |
| `tool_runtime.py` | Per-tool **execution evidence** emitter + runtime-state machine | "No fabricated evidence" is structural: `evidenced` needs a real artifact URI + finished time; `running` cannot be finished; `error` must name a code. `derive_tool_runtime_state()` = error > running > evidenced > idle. |
| `active_preflight.py` | WP-21A **zero-call** readiness proof | Composes all of the above into a structured report (`ok` + per-check pass/fail); never raises; a socket patched to raise proves zero calls. |

Tests: `tests/security_tools/test_active_scan_authorization.py`, `test_zap_active_profiles.py`,
`test_scan_egress.py`, `test_oast.py`, `test_api_discovery.py`, `test_auth_matrix.py`,
`test_tool_runtime.py`, `test_active_preflight.py`, and the end-to-end
`test_active_scan_integration.py`.

---

## Task 4 — `ToolScopeReadModel` field spec (for Codex to render + populate)

I edited **only** the `ToolScopeReadModel` block in `src/agentforge/api/read_models.py` (nothing
else in `api/**` or `console/**`). Three **additive, defaulted** fields were added (backward
compatible — the current `postgres.py` construction stays valid until you wire population):

```python
# in ToolScopeReadModel (src/agentforge/api/read_models.py)
runtime_state: Literal["idle", "running", "evidenced", "error"] = "idle"
evidenced_finding_count: int = Field(default=0, ge=0)
last_error_code: str | None = None
```

**What they mean**

| Field | Type | Meaning |
|---|---|---|
| `runtime_state` | `"idle" \| "running" \| "evidenced" \| "error"` | Per-tool lifecycle for this surface. `idle` = no recorded run; `running` = a dispatch is in flight; `evidenced` = executed and produced a durable artifact; `error` = last dispatch failed. |
| `evidenced_finding_count` | `int ≥ 0` | Findings backed by a durable evidence artifact from this tool's runs (distinct from `recorded_finding_count`, which counts all recorded findings). |
| `last_error_code` | `str \| null` | The most recent per-tool dispatch error code, or `null`. |

**How to populate (Codex, `api/postgres.py` — out of my lane):** the security-tools lane emits one
`agentforge.security_tools.tool_runtime.ToolExecutionEvidence` per tool it exercises; its
`.to_tool_scope_fields()` returns exactly:

```json
{ "runtime_state": "...", "executed_attempt_count": N, "evidenced_finding_count": M,
  "last_error_code": null, "last_executed_at": "..." }
```

For the aggregate read-model row you can compute `runtime_state` from the existing counters +
in-flight reservations with the pure helper (import, don't reimplement — keeps one source of truth):

```python
from agentforge.security_tools.tool_runtime import derive_tool_runtime_state
runtime_state = derive_tool_runtime_state(
    running=<a reservation for this tool is in flight>,
    error_code=<last error code or None>,
    evidenced_count=<evidenced_finding_count>,
)
```

**Render (console, Codex):** show `runtime_state` as the per-tool status chip
(idle/running/evidenced/error), `evidenced_finding_count` next to the existing counters, and
`last_error_code` in the error state. The console `read-models.ts` mirror needs the three fields
added with the same defaults.

---

## Status — code-only vs. needs the Runner + owner authorization

**Code-complete and offline-tested now (no target contact):**
- The full active-scan authorization/scope/caps model and its content-addressing.
- Active ZAP command *construction* + origin deny-list + pinned image/rule subset.
- Governed egress permit/parity seam (with an injected sender).
- Private OAST minting + callback correlation logic.
- Scope-bounded API discovery + auth matrix + per-tool evidence emitter + zero-call preflight.

**Requires the private Runner + a separately minted owner-authorized `ActiveScanAuthorization`
before any real execution (WP-21D):**
- Actually *running* the constructed ZAP command against the live approved origin.
- Wiring `GovernedScanEgress`'s injected `dispatch` to a real Runner socket.
- Standing up the private OAST listener that calls `observe_callback` on real hits.
- Provisioning the synthetic test principals + seeded synthetic (non-PHI) data for the auth matrix.

None of the above can or should run from a sandbox; the code fails closed without the grant, and a
constructed command / injected-sender / passive result is never counted as active-scan evidence.
