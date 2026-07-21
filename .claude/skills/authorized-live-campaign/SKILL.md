---
name: authorized-live-campaign
description: Gate and govern a live adversarial campaign against a real allowlisted target. Use this ONLY when a human explicitly launches a live run — it verifies target authorization, allowlist membership, synthetic-data-only, scoped credentials, budget and rate caps, monitoring, and a hard abort before any attack reaches the target, and captures the full trace. Live attacks are never implicit; this skill is invoked manually, on purpose, by a person.
disable-model-invocation: true
---

# Authorized Live Campaign

A live campaign fires real adversarial traffic at a real system. That is always an intentional human act,
never something a model does incidentally — which is why this skill is **not model-invocable**
(`disable-model-invocation: true`) and exists as a manual gate. The runtime enforcement is code in the
Policy Gateway (ARCHITECTURE.md §5, DECISIONS.md D14/F5), independent of how a run was triggered; this
skill is the human-facing checklist that must pass before anyone opens the gate.

## When this runs
Explicit, manual invocation only — a human is launching a live run. Loading this skill must **never** by
itself authorize or start a campaign; it only walks the gate.

## The gate (every item must pass — a run without all of them is a failed run)
1. **Target authorization** — the target is one the operator is authorized to attack, recorded.
2. **Allowlist validation** — the target resolves to an allowlist entry; anything off-allowlist is denied.
3. **Synthetic-data-only** — assert no real PHI; fixtures are synthetic.
4. **Scoped credentials** — credentials are bound to *this* target only; cross-target use is impossible by
   construction. Secrets are referenced, never inline.
5. **Budget cap + rate cap** — hard ceilings; the cost governor throttles and the queue absorbs backpressure.
6. **Timeout + monitoring** — the run is time-bounded and fully traced (per-agent cost + inter-agent order).
7. **Hard abort** — an abort path halts the campaign immediately and durably.

## After the run
Full trace capture is retained for audit; the run is attributable to its launcher. Publishing any critical
finding or applying any remediation is a **separate** human approval gate (two-person rule — the approver
must differ from the launcher).

## Key rule
No live attack runs without passing this gate. The skill flag is a convenience that stops *implicit*
invocation; the real control is the Policy Gateway's runtime enforcement, which applies no matter how the
run was triggered (Claude, a direct call, or cron). Never weaken the gate to save time.
