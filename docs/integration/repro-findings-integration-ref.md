# Integration reference — red-team reproduction pack (for m)

**Payload-free by design.** This note carries no exploit content — no attack inputs, no vulnerability
narratives — only integration metadata. m (GPT lane) can act on it **without opening** the reproduction
files. The exploit content lives under `docs/red-team/reproductions/` and `evals/repro-controls/`; do
not open those to integrate.

## What to integrate

| Field | Value |
|---|---|
| Branch | `redteam/repro-findings-evidence-0022` |
| Base | 0022 tip `c8033ec` (`agent/governed-0022-four-role`) |
| Diff shape | **purely additive** — new files only; no edits to any existing tip file |
| Supersedes | `redteam/repro-findings-evidence` @ `b54835c` (was based on stale `8ce852b`) |

Because the diff is additive-only against `c8033ec`, it merges without touching platform code.

## Files added (paths only)

```
docs/red-team/reproductions/README.md
docs/red-team/reproductions/RECONCILIATION.md
docs/red-team/reproductions/R1-prompt-injection-system-prompt-leak.md
docs/red-team/reproductions/R2-cross-patient-exfiltration.md
docs/red-team/reproductions/R3-unbounded-consumption-dos.md
docs/red-team/reproductions/EVIDENCE_LINEAGE.md
docs/red-team/reproductions/REPRODUCTION_RUNBOOK.md
docs/integration/repro-findings-integration-ref.md   (this file)
evals/repro-controls/headshot-repro-controls-v1.json
evals/repro-controls/README.md
scripts/validate_repro_controls.py
tests/test_repro_controls.py
```

## Pre-validation status (green)

- `python3 scripts/validate_repro_controls.py --corpus-dir <rtg>/evals/workloads/live-100-cases` → **exit 0**
- `pytest tests/test_repro_controls.py` → **4 passed**
- `ruff check` + `ruff format --check` on the added Python → **clean** (markdown is out of the format gate's scope)
- Additive-only; no existing test or module is modified, so the tip suite is unaffected.

## Canonical report-ID scheme (this pack is canonical)

`AF-VULN-2026-0725-007` (R1), `-008` (R2, flagship), `-009` (R3) — one monotonic sequence continuing
`docs/vulnerabilities/` after 001–006. g's `RTG_RT2_REPRODUCTION_DESIGN.md` is **design input only**;
its proposed `0725-001/002/003` are **not** a second lineage. Full mapping:
`docs/red-team/reproductions/RECONCILIATION.md`.

## Separate preconditions (NOT in this branch — flagged, not blocking the merge)

This pack is design/pre-registration; **execution** additionally needs g's `rtg/wp11-wp14` work, which
is **not on the 0022 tip**:

- corpus `headshot-live-100-v1` (manifest sha `07d649d482dd1f59a70e2b7238506e59eacddb8f39b56c419ccc6aab52ca252d`, content-stable),
- consumption-oracle wiring (`ResourceLimitOracle` from the gateway meter),
- the `attempt_result.resource_measurements` migration — integrates as **`0023`** on this lineage
  (head is `0022`; note `0018` here is `provider_call_lineage`),
- the caps envelope (`logical=100 / physical=121 / retries=0 / budget=50 / timeout=3600 / rps=0.5`).

Merging this branch does not require any of the above; running the reproduction does.

## Attestation

- **No secrets, no SIDs, no credentials, no real PHI.** Synthetic canary tokens and synthetic patient
  ids only; no live target URL in any added file. Safe for the secret-scan gate.
- Honesty invariants are machine-enforced (`scripts/validate_repro_controls.py`, `tests/test_repro_controls.py`):
  count only `EXPLOIT_CONFIRMED`; oracle/canary/human the only confirm authority; negative controls
  bind the same instrument; nothing manufactured.
