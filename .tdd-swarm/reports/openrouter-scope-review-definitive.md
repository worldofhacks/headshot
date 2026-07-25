# Definitive independent TDD re-review — OpenRouter four-role amendment

**Disposition: REVIEW_PASS**

Planning review only. No application/test code, credential, authorization, network/provider/target call, spend, deployment, or git state was changed.

## Final repair closure

| finding | result |
|---|---|
| Critical — live grant and reviewed smoke were not mechanically bound | **Closed.** T-F05c is a bounded deterministic code ticket with two source files, one unique test file, and separate Test/Test-review/Implement/Code-review/Security prompts. Its exact public `--check-only` CLI reads `campaign.json` itself; caller-selected expected review hashes are forbidden. It derives and compares the canonical smoke-manifest hash and unequal Evidence/Security review hashes, invokes the T-F04h review logic, and composes rather than replaces the existing campaign authorization, binding, caps, target-preflight, and Policy Gateway checks. |
| Critical — exact live-target authorization fields had regressed from T-F05b | **Closed.** T-F05c/T-F05b now require exact staging target/surface/scheme-host-port/allowlist+hash, corpus ID/hash, synthetic fixture IDs/hashes and `synthetic_only:true`, release/current-deployment/target version, current four-role configuration and provider/prompt/rubric/criteria/policy/catalog/data-policy hashes, aggregate/per-role physical calls/retries/input-output-reasoning tokens/USD/rate/concurrency/timeout/wall-clock/abort caps, expiry/operation nonce, launcher/distinct approver permissions, and SMART credential-reference/session-lease generation/not-before/expiry/target binding. Any mismatch is exit 4 before mutation, secret resolution, adapter construction, calls, or spend. |
| Important — smoke manifests were overwriteable/partially publishable | **Closed.** T-F04d owns the dual-output CLI and frozen deterministic tests for fixed-root absent leaves, component no-follow checks, create-exclusive same-directory staging, full writes/fsyncs, no-replace publication, canonical byte/hash identity, recoverable commit state, inode/token-scoped cleanup, and rejection of pre-existing paths, symlinks, escapes, reused IDs, failures, crashes, unequal outputs, and uncommitted half-sets. T-F04e no longer copies either manifest and reviewers accept only the committed identical pair. |
| Minor — T-F04c idempotency identity was undefined | **Closed.** The canonical full-four-role input is schema-versioned and role-sorted; the identity is domain + release SHA + full-input SHA-256, with actor/session audit-only. Same release/input returns the original set, same release/changed input conflicts without mutation, and a different release permits a later staged version. |

## T-F05c boundedness and reachability

- Unique source scope: `src/agentforge/campaign/live_preflight.py` and `scripts/preflight_live_campaign.py`.
- Unique frozen test scope: `tests/test_live_campaign_preflight.py`.
- Exactly five role prompts exist and preserve separation of powers, three-attempt caps, exact inputs/outputs, no network/spend/target action, and no main merge/push.
- T-F05c depends only on landed deterministic interfaces T-F04h/T-F05a and may proceed without a live grant using injected local fixtures.
- T-F04e/T-F05c/T-F06a wave-8 scopes are disjoint. T-F05b is correctly moved behind T-F05c in wave 9.
- T-F05b Execute and Evidence Review both invoke the exact T-F05c public command. The command accepts no caller-provided expected smoke/review hashes; those expectations come from `campaign.json`.
- T-F05b additionally requires the still-valid Policy Gateway grant/lease/caps immediately before every physical dispatch.

## Preserved four-role controls

- Four authorization-selected OpenRouter model IDs and sealed credential references are pairwise distinct; no proposed model ID is hard-coded as a runtime default.
- Judge and Red Team remain independent across credential reference, requested/returned model, family, prompt/rubric-or-criteria, expected upstream and actual upstream identity.
- Strict repository schemas, exact returned identity, no fallback, deterministic oracle precedence, fail-closed calibration, and typed terminal states remain required.
- Every physical attempt reserves worst-case calls, input/output/reasoning tokens, USD, retry and concurrency capacity atomically before dispatch; reconciliation, missing accounting, price drift, reasoning growth and shared abort remain covered.
- T-F04h retains explicit `OPERATIONAL_SCHEMAS` ownership, `SUCCESS_SCHEMAS` exclusion, root/package/wheel parity and generic conformance.
- T-F04e remains target-free, synthetic, authorization-bound, and split across distinct executor, Evidence Reviewer and Security Reviewer principals with create-only records.
- Deterministic T-F04h/T-F04d/T-F05c work remains independent of external T-F03b/T-F04b/T-F04e authorization.

## Structural checks

- Parsed all 33 `T-F*` ticket frontmatters: zero missing dependencies; every dependency points to an earlier wave.
- `TICKETS.md` matches all 33 ticket wave assignments.
- Zero same-wave exact file/test-scope collisions.
- All 54 expected prompts exist for T-F03a through T-F05c; the amended T-F04c/d/f/g/h/T-F05c code tickets each have five role prompts and unique test scopes.
- Prompt contract checks found zero missing model/worktree/branch/status/attempt/no-main/no-push clauses.
- No readiness-report proposed model ID appears in the reviewed tickets, prompts, index, or manifest.
- The public chain is complete: configuration staging → read-only hosted preflight → reserved four-role execution → immutable dual publication → offline manifest/review verification → `campaign.json` live preflight → T-F05b.

## External gates

Exact model/credential selection, immutable smoke/Judge/Red-Team authorizations, distinct reviewer assignments, the live `campaign.json` grant, current deployment/SMART lease evidence, and target authority remain explicit human/external prerequisites. Their absence correctly blocks operational calls; it is not a planning defect.

**Final: REVIEW_PASS — Critical 0, Important 0, Minor 0.**
