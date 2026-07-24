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
| `workbench_decoder.py` | WP-16C Decoder — real offline encoding transforms | Base64 / ROT13 / ASCII-smuggling (Unicode Tags) / hex / URL, content-addressed; fail-closed on unknown transform / oversize; untrusted candidate input only. |
| `scan_sender.py` | The real bounded HTTPS sender (the physical send) | Default-disabled (`AGENTFORGE_ACTIVE_SCAN_ENABLED`); https + exact-origin deny-list re-checked at send; DNS resolved + every IP validated + PINNED (rebinding defense); redirects denied; bounded; SID via sealed `secretref`→`Secret`, never surfaced. Socket layer injected → tested offline. |
| `active_scan_run.py` | Runnable entrypoint (`python -m …active_scan_run`) | `--print-template` / `--mint` / run one bounded governed scan → preflight → egress+sender → parity ledger + per-tool evidence. Grant-gated + default-disabled. |

Shared, review-hardened primitives added to `active_authorization.py`: `content_digest()`
(collision-resistant, used by OAST + egress) and `path_in_scope()` (one traversal-hardened
scope matcher used by both discovery and egress — no divergence).

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

---

## Task-by-task status (against the assignment)

- **Task 1 — every-tool scan / hosted generation + two-stage loop.** Hosted Red Team generation is
  **already implemented and tested** (`agents/red_team/providers.py` `HostedProvider._generate_via_client`,
  dual-gate auth; `tests/test_red_team_hosted_generation.py`, 9 tests green — the brief's
  "raises NotImplementedError" ground-truth was stale; no such error exists). The two-stage
  building blocks are all present: Stage-1 generation without target authority (`mutate()` +
  providers → proposed input only, no credential/verdict), content-addressing into a NEW corpus
  requiring fresh authorization (`campaign/tool_profile.py` `build_reviewed_tool_corpus` →
  `fresh_authorization_required` + `operation_hash` rebinding), and the coordinator's hard-abort on
  any in-run mutation (`campaign/coordinator.py:390-394`, corpus-hash invariant). **Not added here:**
  a single named "hosted-variant → review → re-authorize → dispatch" orchestration — deliberately
  not half-wired into the concurrently-churning `campaign/` tree; every primitive it needs exists.
- **Task 2 — promote adapter-only capabilities.** The promotion pathway exists and 3 tool bundles
  (garak / promptfoo / pyrit) are already promoted into the 14-case full-scan corpus
  (`security_tools/native.py` adapters → `candidates.py` `build_tool_attack_bundle` →
  `corpus.py` `_REVIEWED_BUNDLES`). **Added here:** the workbench Decoder now produces real
  content-addressed encoding-bypass candidates (was declarative). **Remaining (documented, not
  applied):** promoting PyRIT Crescendo/TAP multi-turn, Giskard RAG/agent/GOAT/GCG, extra Garak
  probe families, and Promptfoo red-team plugins is a per-tool artifact-generation + bundle-pin +
  catalog scope-move that touches the shared, Codex-churned `corpus.py`; the exact steps are the
  `native.py`→`candidates.py`→`corpus._REVIEWED_BUNDLES` pathway above.
- **Task 3 — real active scanning.** Complete as code + offline tests (see the module table).
- **Task 4 — per-tool execution evidence + runtime state.** Complete (emitter + additive read-model
  fields + this field spec).

Adversarially reviewed (28-agent workflow): 11 confirmed findings fixed with RED regression tests
(`tests/security_tools/test_active_scan_hardening.py`) — traversal bypass, spec-URL port bypass,
hash-collision, empty-auth-matrix preflight gap, metadata deny-list gaps, abort re-check, and more.

---

## Running a real active scan

There are two ways to actually run one. **(A) GOVERNED** is the platform's real path and the only
one that produces scanner↔permit↔send↔ledger **counts** evidence. **(B) OUT-OF-BAND** is a real ZAP
active-rule signal you can run locally, but it is **NOT** governed-ledger evidence.

Both are bounded to the SAME rule subset (`FORBIDDEN_ACTIVE_RULE_IDS` — buffer/format/integer
overflow — excluded; no delete/auth-mutating/flood rules), the exact approved origin, the
rate/time/request caps, and synthetic data only. The SID resolves ONLY via the sealed
`secretref://` binding (`AGENTFORGE_CREDENTIAL_BINDINGS_JSON`) — never in an argv, an env dump, or a
log.

### The grant plan (what the owner authors — no secrets)

```bash
python -m agentforge.security_tools.active_scan_run --print-template > plan.json
# fill in plan.json (below), then:
python -m agentforge.security_tools.active_scan_run --mint --config plan.json   # prints operation_hash
# paste operation_hash + a deadline into plan.json's "authorization" block (your approval)
```

Fill-in-the-blanks template (secrets are ONLY `secretref://` handles, never values):

```json
{
  "scope": {
    "origin": "https://<exact-approved-origin>",
    "http_methods": ["GET", "POST"],
    "path_patterns": ["/api/<in-scope>", "/api/<in-scope>/*"],
    "principals": ["synthetic-anon", "synthetic-<role>"],
    "image_sha256": "c558ee87358911ab17278c70991e856f57793e115d9cd0f88ca475cf82907a1a",
    "addon_sha256s": ["<addon-sha256-64hex>"],
    "rule_sha256s": ["0b74332d02d4bf3421cc3b2857ffb6c885bf413c2993477fc97ebc3c3103885f"],
    "callback_domains": [],
    "caps": {"max_requests": 50, "requests_per_second": 2.0, "max_duration_seconds": 600.0, "max_findings": 200},
    "scope_nonce": "<fresh-random-nonce>"
  },
  "authorization": {"operation_hash": "<from --mint>", "scope_nonce": "<same nonce>", "deadline": "<epoch-seconds expiry>"},
  "approved_origin": "https://<exact-approved-origin>",
  "openapi": {"openapi": "3.0.0", "paths": {"/api/<in-scope>": {"get": {}}}},
  "auth_matrix_entries": [["synthetic-anon", "none", null], ["synthetic-<role>", "bearer", "secretref://<runner-binding>"]],
  "credential_ref": null,
  "auth_header": "Cookie"
}
```

**Fields only the OWNER supplies:** `origin` / `approved_origin` (exact approved target),
`path_patterns` + `http_methods` (what may be probed), `rule_sha256s` (the pinned subset digest
above), `caps` (request/rate/time bounds), `scope_nonce` (fresh per scan), and
`authorization.deadline` (expiry). `operation_hash` is computed by `--mint`, not hand-authored.

### (A) GOVERNED — run in the Railway private Runner (the "counts" evidence)

Runs the entrypoint with the real `BoundedHttpsSender`; every physical send crosses a fresh permit
and lands in the parity ledger, and per-tool evidence is emitted. Never run this from a sandbox.

1. Deploy: the **private** Runner service on Railway (not the public console) with egress to the
   approved origin only. Confirm `/ready` is green.
2. Set on the Runner service (secrets in Railway variables, never in the repo/argv):
   - `AGENTFORGE_ACTIVE_SCAN_ENABLED=1`
   - `AGENTFORGE_CREDENTIAL_BINDINGS_JSON={"secretref://<runner-binding>":"<ENV_VAR_NAME>"}`
   - `<ENV_VAR_NAME>=<the synthetic session id>`  (sealed Railway secret; resolved only in-process)
3. Copy the approved `plan.json` to the Runner.
4. Run:
   ```bash
   python -m agentforge.security_tools.active_scan_run --config plan.json
   ```
5. Read the JSON report: `preflight_ok`, the `ledger` (one entry per permitted send —
   scanner↔permit↔send↔ledger parity), `parity_ok`, and `evidence` (`runtime_state=evidenced`,
   `executed_attempt_count`). This is the governed-ledger evidence.

Fail-closed: without the enable flag, a valid unexpired in-scope grant, an exact-origin match, and a
public-unicast DNS answer, it refuses before any send.

### (B) OUT-OF-BAND — pinned ZAP active-rule Docker command (real signal, NOT governed evidence)

Run locally from a networked machine authorized to reach the target. This is a **real ZAP active
scan** bounded to the same pinned image + rule subset + caps, but it does **NOT** flow through the
governed permit/ledger, so its output is a **real signal, NOT governed-ledger evidence**. The SID,
if needed, is provided to ZAP via a replacer config resolved on the running host — never on the argv.

```bash
# Rules: 40018,40019 (SQLi) 40012,40014 (XSS) 90020 (OS cmd) 90019 (code) 40046 (SSRF) \
#        6 (path traversal) 7 (RFI) 90034 (cloud metadata). Overflow/DoS rules are OFF.
docker run --rm \
  --network=agentforge-zap-isolated --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --pids-limit=256 --memory=2g --cpus=2 \
  ghcr.io/zaproxy/zaproxy@sha256:c558ee87358911ab17278c70991e856f57793e115d9cd0f88ca475cf82907a1a \
  zap-api-scan.py \
  -t https://<exact-approved-origin>/api/openapi.json -f openapi \
  -J active.json -T 10 \
  -z "-config ascan.policy.default.enabled=false \
      -config ascan.policy.40018.enabled=true -config ascan.policy.40019.enabled=true \
      -config ascan.policy.40012.enabled=true -config ascan.policy.40014.enabled=true \
      -config ascan.policy.90020.enabled=true -config ascan.policy.90019.enabled=true \
      -config ascan.policy.40046.enabled=true -config ascan.policy.6.enabled=true \
      -config ascan.policy.7.enabled=true -config ascan.policy.90034.enabled=true"
```

> The exact argv (identical to the above, with per-rule strength/threshold) is what
> `zap_profiles.active_scan_argv(scope, grant, ...)` returns under a verified grant — build it from
> the plan to avoid drift.
