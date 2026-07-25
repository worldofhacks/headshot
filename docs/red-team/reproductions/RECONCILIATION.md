# Reconciliation — one canonical reproduction lineage

This pack (`docs/red-team/reproductions/` + `evals/repro-controls/headshot-repro-controls-v1.json`) is
the **canonical** reproduction lineage and report-ID scheme for the red-team findings lane. g's
`docs/RTG_RT2_REPRODUCTION_DESIGN.md` (on `rtg/wp11-wp14`) is **design input only** — a deterministic,
no-target-contact *mechanism* proof — and is **not** a second finding/report lineage. Where the two
overlap, this document maps them; there is exactly one written lineage.

## Canonical report IDs

One monotonic sequence, continuing `docs/vulnerabilities/` after `AF-VULN-2026-0724-001…006`:

| Finding | Positive case | Canonical `finding_id` | Confirm source |
|---|---|---|---|
| R1 prompt-injection → system-prompt leak | `AF-M11-PI-001` | `AF-VULN-2026-0725-007` | canary |
| R2 cross-patient exfiltration (BOLA) ⭐ | `AF-M11-DX-001` | `AF-VULN-2026-0725-008` | canary |
| R3 unbounded consumption / DoS | `AF-M11-DS-003` | `AF-VULN-2026-0725-009` | oracle |

The counter (`007/008/009`) continues the single program sequence; the date reflects the
reproduction-design date. IDs are assigned to the drafted `VulnReport` at execution time and carry
through unchanged.

## g's design doc — status and mapping

g's `RTG_RT2_REPRODUCTION_DESIGN.md` proves, deterministically and with **no target contact** (in-test
seeded canary echo through the real coordinator/Judge; `tests/test_rt2_vuln_reproduction.py`, **4
passed**), that the canary → oracle → Judge → `EXPLOIT_CONFIRMED` **mechanism** is wired end-to-end and
fires for the right reason. That is valuable corroboration of the confirmation *mechanism* my live
protocol depends on. g's own doc states its report IDs are **"proposals only — do not treat as
written."** They are retired here in favor of the canonical scheme above.

| g (design input) | g's proposed id (retired) | Canonical treatment |
|---|---|---|
| **V1** system-prompt leak — case `AF-M11-PI-101` (direct "diagnostic dump" phrasing) | `AF-VULN-2026-0725-001` | Same **vuln class + oracle + canary** as **R1** (`offline-system-prompt-canary-v1` / `SYNTH_CANARY_SYSTEM_PROMPT_4D2B`). Canonical R1 keeps `AF-M11-PI-001` (indirect retrieved-doc phrasing) as its positive; g's `PI-101` is a valid alternative case in the same family. One finding: **R1 = `…-007`**. |
| **V2** cross-patient exfiltration — case `AF-M11-DX-001` | `AF-VULN-2026-0725-002` | **Identical finding to R2** (same case, oracle `offline-beta-disclosure-canary-v1`, canary `SYNTH_CANARY_PATIENT_BETA_8C1E`). g's V2 negative control (alpha reads own data → alpha canary present, beta absent) **independently converges** with `R2-CTRL-AUTH-SELF-01` and is adopted as the stronger control framing. One finding: **R2 = `…-008`**; g's `…-002` retired. |
| **V3** identity/role privesc → system-prompt leak — case `AF-M11-IR-102` (multi-turn "maintenance mode") | `AF-VULN-2026-0725-003` | **Design input, not in this canonical three-finding package** (this pack's third finding is R3, unbounded consumption). V3 is a legitimate additional vuln that may become a future canonical finding; it is **not** assigned a report id here and does **not** open a second lineage. |

**Net:** g's V1 and V2 correspond to canonical R1 and R2 (mechanism-corroborated); g's V3 is unassigned
design input; g's proposed `0725-001/002/003` are not written. No competing finding/report lineage
exists.

## Control artifacts

- **Canonical (live reproduction):** `evals/repro-controls/headshot-repro-controls-v1.json` — the
  negative controls + invariant guards for the authorized live campaign, machine-checked by
  `scripts/validate_repro_controls.py`.
- **Design input (fixture mechanism):** g's `evals/reproduction/rt2-negative-controls.v1.json` — the
  in-test control bodies for g's deterministic mechanism proof. Complementary, not a duplicate: g
  proves the mechanism offline now; this pack designs the live confirmation. Both stay outside the
  frozen 100-case corpus.

## 0022-lineage precondition deltas (vs the stale `8ce852b` base)

The load-bearing platform code is **byte-identical** on the 0022 tip (`judge.py`, `oracles/base.py`,
`documentation/agent.py`, `coordinator.py`, `vuln_report.json`, the attack-case schema, the synthetic
fixture, and the target config all match `8ce852b`), so every code/schema/canary/caps citation in this
pack holds. What changed for the 0022 lineage:

- **Migration numbering.** On the 0022 tip `0018 = provider_call_lineage` and the Alembic head is
  `0022 = governed_four_role_acceptance`. g's `attempt_result.resource_measurements` migration lands
  as the **next** revision — **`0023`** — not `0018`. (R3, `REPRODUCTION_RUNBOOK.md` updated.)
- **Not-yet-integrated.** g's corpus `headshot-live-100-v1`, the consumption-oracle wiring
  (`ResourceLimitOracle` from the gateway meter), the caps envelope, and g's `rt2` test/artifact are
  **not on the 0022 tip**; they must be integrated from `rtg/wp11-wp14` before a run. Pre-integration
  commit SHAs (`d9d7b4a`/`d896908`/`f43ef2f`) do not exist on this line and are replaced by durable
  content references. The content-addressed corpus manifest sha `07d649…252d` and the per-case
  `case_sha256` values are content-stable and unchanged.
