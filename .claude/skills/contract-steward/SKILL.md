---
name: contract-steward
description: Own the lifecycle of an inter-agent message contract in this repo — define or change a JSON-Schema boundary (Orchestrator→RedTeam, RedTeam→PolicyGateway, ExecutionRecorder→Judge, Judge→Documentation, Judge→Regression), add or evolve the typed error taxonomy, or bump a schema version. Use this WHENEVER an inter-agent message shape moves, an Evidence Envelope / AttemptResult / Verdict field is added or changed, a new error type is introduced, or a producer/consumer stops conforming — even if the change "looks trivial." A silently drifted schema breaks an agent handoff without failing loudly, so route every contract edit through here. NOT for generating the implementation plan (that is tasks-gen) and NOT for diagnosing a failing eval (that is eval-triage).
---

# Contract Steward

Inter-agent contracts are the platform's load-bearing seams. They are **versioned, framework-neutral
JSON Schemas** in `contracts/v1/` so the build-vs-configure stack choice can never force a rewrite
(ARCHITECTURE.md §4, DECISIONS.md D10/D14/D18). This skill fires a multi-step checklist every time an
interface moves, because a drifted schema fails an agent handoff quietly instead of loudly.

## When this runs
"define/change an agent contract", "bump the schema", "add an error type", any edit to an inter-agent
message shape, or a contract test going red.

## The checklist (do every step — skipping one is how drift enters)

1. **Locate the boundary.** Name the exact producer→consumer pair and the schema file in `contracts/v1/`.
   The physical boundaries are: `Orchestrator→RedTeam: CampaignDirective` · `RedTeam→PolicyGateway:
   AttackAttempt` · `ExecutionRecorder→Judge: AttemptResult` (the Judge's **authoritative** evidence) ·
   `Judge→Documentation: Verdict` · `Judge→Regression: RegressionAdmissionCandidate`.

2. **Classify the change.** *Additive/optional* (new optional field, new enum value at the end) is
   backward-compatible. *Breaking* (removed/renamed field, tightened type, new required field, removed
   enum value) is not. Decide this explicitly — do not guess.

3. **Preserve the trust invariants (D14/D18).** The **Evidence Envelope** keeps per-field trust labels:
   `trusted` fields are code-populated (`oracle_results[]`, `canary_hits[]`, `policy_decision`,
   `expected_safe_behavior`, `ground_truth_ref`) and MUST reject a value whose provenance is `hostile`;
   the transcript is `hostile` data. The **AttemptResult** carries `content_hash` + `{campaign_run_id,
   attempt_id}`. The **Verdict** is schema-validated with enumerated states, confidence, and typed reason
   codes. Never let a schema change make an attacker-controlled field able to populate a `trusted` field.

4. **Version discipline for a breaking change (all three, or the run fails):** bump the version, write a
   **migration note** (what changed, how to migrate existing records), and update the **both-sided
   contract tests**. A breaking change without all three is a failed run.

5. **Both-sided contract tests.** Every boundary asserts the **producer** and the **consumer** each
   conform to the published schema (`tests/contract/`). Add/adjust the example payloads for both sides.

6. **Run the deterministic checks** (shared by this skill and CI so guidance and enforcement can't drift):
   schema compatibility / breaking-change detection, and producer- + consumer-side conformance.

## Trust boundary of this skill
This skill **detects and reports** an incompatible change and prepares the version bump + migration note.
It does **not** decide whether a breaking change is *acceptable* — that is a human approval gate. Surface
the finding; let a human ratify the break.

## Key rule
A breaking change without a version bump **and** a migration note **and** updated contract tests is a
failed run. Schemas stay framework-neutral so no stack decision forces a rewrite.
