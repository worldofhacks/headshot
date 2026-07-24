# T-F16b repaired Test Agent report

Status: `DONE_WITH_CONCERNS`

Freeze status: `NOT_FROZEN` — this repaired candidate requires a fresh independent test-design
review before Implementation Agent dispatch.

## Four-status contract

- Test status: `RED` — `51` feature assertions fail cleanly at the absent operation-flow boundary;
  the one inherited chat/work-unit regression control passes.
- Baseline status: `GREEN` — the network-disabled repository baseline excluding only this RED
  scope passes `1227` tests with `3` skipped and the pre-existing network-dependent wheel test
  deselected.
- Focused preservation status: `GREEN` — existing gateway/work-unit controls pass `36` tests.
- Static/spec status: `GREEN` — Ruff lint/format, Python compilation, diff checks, and the T-F00
  criterion mapper pass.
- Wrapper status: `BLOCKED(DEPENDENCY)` — this T-F16a-derived branch still lacks T-F00's in-tree
  `.tdd-swarm/run-local-gates.sh`; the available constituent gates were executed directly.

## Provenance and ownership

- Worktree: `/Users/quietguy/Documents/Dev/Gauntlet/wt-T-F16b`
- Branch: `ticket/T-F16b-physical-operation-gateway`
- Repair input/review commit: `f08942eaf033ad1769034df293e026eb3360c8a1`
- Previously reviewed candidate:
  - SHA-256: `3e5c37ee54e9e7fdc321c51fba1e108c8755cb0e82dedf8127043ef46183fafa`
  - Git blob: `20b40610c149a0a47dec1f794f589f45ee3e17b6`
- Repaired candidate:
  - SHA-256: `1db1a755e8616ffd780e8fcfc75d3d4860839919df0405ebf9eb267cf9350eaf`
  - Git blob: `8535b226c98505eb1b6c2edbe56c40b6ab4dd155`
- Test Agent writes are limited to:
  - `tests/test_surface_operation_gateway.py`
  - `.tdd-swarm/reports/T-F16b-test.md`

No product, migration, policy, catalog, credential, fixture, target, deployment, or owner artifact
was edited. Injected senders and the migrated throwaway PostgreSQL fixture are the only runtime
surfaces; no socket, provider, target, or external network is used.

## Review-finding closure

| Prior finding | Repaired behavioral contract |
|---|---|
| Durable coordinator/PostgreSQL work-unit integration absent | A public `SecureCampaignCoordinator.execute_operation_flow` path now must use the actual persisted authorization scope, exact bound adapter kind/host, and Runner-style `pre_dispatch_gate -> work_unit_reserver -> sender -> work_unit_observer` composition. Real-PostgreSQL retry-success, terminal-failure, and lease-revocation cases prove a reservation row exists and is unobserved before every sender entry, then becomes exactly-once `raised`/`returned`; failure rows survive, duplicate replay conflicts, direct mutation is trigger-rejected, and scope/binding mismatches send zero requests. |
| Budget/cap/rate/run-timeout could be one-time checks | Deterministic races make concurrent spend, persisted capacity authorization, retry timing, and the run deadline become insufficient only after the first admitted physical attempt. Each stops before another operation send with exactly one charged and observed trace and no second reservation. A separate two-operation flow makes budget insufficient between logical operations and forbids the later send. |
| Non-retryable/unexpected failure accounting absent | A retry-capable read raises both `TargetSessionExpiredError` and an unexpected `RuntimeError`. Each consumes exactly one gate, send, charge, and `raised` observation at retry index zero; neither retries nor advances the flow. |
| Canonical 67-attempt mix only asserted | One flow executes upload once, thirty polls with one failure/retry each, then report/preview/readback with one failure/retry each. It requires exact class counts `1 + 60 + 2 + 2 + 2`, `67` gates/sends/charges/traces, retry-index reset per logical operation, `34` success trace references, and refusal of the flow's attempted 68th send. The existing deficient-66 preflight case still requires zero upload calls. |
| Hostile exception sanitization absent | Transport and retry-gate exceptions carry both canaries, a session-shaped value, and more than 4 KiB of hostile text. Typed terminal reason, error `str`/`repr`, cause rendering, traces, and durable rows must remain bounded and contain none of it. Gate failure creates no additional send/reservation. |
| Brittle `inspect.getsource` spelling constraint | All source inspection was removed. A socket-construction poison, poisoned legacy adapter, transport-free flow object, and four behavioral sender paths (success, retry-success, typed terminal, unexpected terminal) prove only the injected one-operation sender is reached and every reached path is metered. |

The durable fixture deliberately uses a three-unit synthetic authorized run. The current synthetic
catalog cap is below the document workflow's `67`; the complete 67 mix is therefore exercised
separately at the gateway boundary rather than inventing unrelated catalog authority.

## Repaired RED map

| Criterion | Intentional RED coverage |
|---|---|
| AC-1 | Canonical `34/67` preflight projection; zero-send refusal for physical, budget, timeout, authorization, lease, or trace capacity; complete runtime `67` mix and no 68th send |
| AC-2 | Per-attempt coordinates/context; retry-time budget/capacity/rate/timeout races; later-operation race; exact success, typed failure, unexpected failure charging/observation; scope-bound durable coordinator rows |
| AC-3 | Closed dynamic segment, host/query/traversal/encoding/method/class/template refusal, logical ceiling, and full mixed transition sequence |
| AC-4 | Zero-retry ambiguous upload, fail/fail/succeed retry-two, document retry-one ceiling, non-retryable/unexpected no-retry, exact mixed retry reset |
| AC-5 | Stop-before-later-operation behavior, preserved immutable durable rows, oversized response handling, hostile exception/cause sanitization, bounded terminal count/references |
| AC-6 | Understatement cannot reduce policy reservation; public coordinator reachability; socket/legacy transport poison across all outcome paths; inherited atomic/sequential chat coordinates and hashes |

## RED evidence

Focused command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  /Users/quietguy/Documents/Dev/Gauntlet/Adversarial\ Machine/.venv/bin/python \
  -m pytest -o addopts='' -q --tb=short tests/test_surface_operation_gateway.py
```

Result: exit `1`; `52` collected, `51` intentional assertion failures, `1` inherited regression
pass, `0` collection/setup errors. Every RED failure names the same absent public feature:
`SurfaceOperation`, `SurfaceOperationResponse`, `OperationFlowAborted`, and
`PolicyGateway.execute_operation_flow`.

## Preserved baseline evidence

Network-disabled repository baseline:

```text
PIP_NO_INDEX=1 PYTHONDONTWRITEBYTECODE=1 env -u PYTHONPATH <venv-python> -c \
  'import sys, pytest; sys.path.insert(0, "src"); raise SystemExit(pytest.main(
  ["-o", "addopts=", "-q", "--ignore=tests/test_surface_operation_gateway.py",
   "-k", "not wheel_installed_outside_repo_validates_corpus"]))'
```

Result: exit `0`; `1227 passed, 3 skipped, 1 deselected`, with only the existing Starlette
`httpx` deprecation warning. The prior independent review also recorded the complete baseline as
`1228 passed, 3 skipped`; the one offline deselection is solely the pre-existing build-frontend
wheel test.

Existing gateway/work-unit preservation:

```text
PIP_NO_INDEX=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src <venv-python> \
  -m pytest -o addopts='' -q tests/test_gateway.py tests/test_work_unit_accounting.py
```

Result: exit `0`; `36 passed`.

## Static, spec, and integrity evidence

- Ruff check: pass.
- Ruff format check: pass.
- Python compilation: pass.
- `git diff --check`: pass.
- No `inspect`, `getsource`, TODO/FIXME/HACK, skip, debug print, or product-file edit.
- T-F00 criterion mapper:
  `spec-lint: T-F16b maps 6 acceptance criteria across 1 pytest-collected scopes`.
- Secret scan: `secret scan clean (855 files)`.
- Staged gitleaks: no leaks found in the exact two-file candidate.

The missing wrapper remains an upstream dependency:

```text
bash .tdd-swarm/run-local-gates.sh tickets/T-F16b.md \
  cda81d87a3ff44bceb66492588c37c5ee033b50a
bash: .tdd-swarm/run-local-gates.sh: No such file or directory
```

The Test Agent does not copy or implement T-F00 outside its two-file ownership.
