# ADR-0003 — The synthetic-data gate keys on attestation, not environment

- **Status:** Accepted; implemented
- **Date:** 2026-07-25
- **Deciders:** platform author (owner decision to lock the demo to staging)
- **Applies to:** `PolicyGateway._enforce_synthetic_data` — the O1 synthetic-data control
- **Does not apply to:** the two-person Clerk campaign gate, the AD-04 model-confirmation guard, the
  oracle/canary/human confirm authority, or the human publication gate. None of those change.

## Context

The platform must never be pointed at a target holding real data. That is the O1 control, and it is
one of the hard gates: *"No real PHI — synthetic fixtures only."*

The gate implemented that rule by proxy. It refused any live (`http://` / `https://`) target unless
`environment == "production"`:

```
if self.settings.environment == "production":
    return
if target_id.startswith(_LIVE_SCHEMES):
    raise AbortError("... only production may reach a live target")
```

The reasoning was that production is where the attested-synthetic target lives, so environment stood
in for "this target's data is safe to attack."

The proxy is wrong in **both** directions, and we hit both:

1. **It refuses a safe target — but only for a URL-shaped target id.** The gate raises solely when
   `target_id.startswith(("http://", "https://"))`. The runner binds `scope.target_id`, which is a
   *catalog id* (`clinical-copilot-week2`), so for every catalog-resolved target the gate never fired
   at all.

   > **Correction (2026-07-25, same day).** This ADR and the commit that introduced it originally
   > claimed that because every Railway service runs `AGENTFORGE_ENVIRONMENT=staging`, "no live
   > campaign could dispatch at all". **That was wrong.** The gate is unreachable for catalog-id
   > targets, so it was never the thing blocking a campaign. The real blockers are elsewhere — the
   > deployed catalog omits two targets, and its `safety_caps` lack the
   > `logical_case_limit`/`physical_request_limit`/`target_retries_per_turn` the live-100 exact-cap
   > contract requires. The narrowing below is still correct and still worth having (defect 2 is
   > real, and the gate had no test coverage), but it did **not** unblock anything, and it should not
   > be cited as having done so.
2. **It admits an unsafe target.** In production the gate returns early and performs *no* attestation
   check. A live target with real data would have been dispatched to without objection — the precise
   thing O1 exists to prevent.

The obvious fix — flipping the deployment to `production` — was rejected. It requires a Clerk
production instance (`auth/config.py` demands a `pk_live_` publishable key when
`environment == "production"`, and the deployment holds `pk_test_`), and `ControlPlaneStore` refuses
targets whose environment differs from its own, so Web, Runner and Scheduler would all have to move
together. That is a larger, riskier change than the control actually needs, and it would not fix
defect 2.

## Decision

**Key the gate on the fact it cares about: a verified synthetic-data attestation.**

Outside production, a live target is admitted only when its allowlist entry carries
`synthetic_attested=True`. That flag is set from the target's own validated catalog spec —
`synthetic_data_only is True` **and** a non-empty `synthetic_data_attestation_ref`, both enforced by
`TargetSpec` validation and re-checked by the runner's `synthetic_data_attestation_missing` preflight
blocker. The composition root re-derives it at the point of use rather than trusting that an earlier
check passed. Anything without that attestation is refused exactly as before.

`AllowlistEntry.synthetic_attested` **defaults to `False`**. Every construction path that has not
established the attestation keeps the strict no-live-target behaviour. Admitting a live target is
opt-in and evidence-backed, never assumed.

Production's early return is retained unchanged, so this is purely a narrowing of the refusal set —
no target that was previously admitted becomes refused.

## Consequences

- The gate now expresses a synthetic-data rule rather than an environment rule, and would admit an
  attested-synthetic target reached by URL from staging. **It does not by itself make any campaign
  runnable** — see the correction above; for catalog-id targets the gate was already a no-op.
- The control is now *stronger* in intent: it asserts something about the target's data rather than
  about which box the request came from.
- **Known gap, deliberately not closed here:** production still returns early without checking
  attestation, so defect 2 above survives in production. Closing it means removing the early return
  so every environment requires attestation. That is the right end state, but it would refuse any
  production target whose catalog entry lacks the attestation, and that blast radius was not worth
  taking inside the demo window. Tracked as follow-up.
- Five tests lock the behaviour from both sides
  (`tests/test_gateway.py`): an unattested live target is still refused in staging; an attested one is
  admitted; an entry that never set the flag fails closed; production is unchanged; a non-live target
  is unaffected. **The gate previously had no direct test coverage at all.**

## Honest note on scope

This changes a security control to make a demo run. The justification is that the target's data is
genuinely synthetic and attested as such in a validated, content-addressed catalog spec — so the
control's *intent* is preserved and its precision improved. It is not a relaxation for convenience:
an unattested live target is refused in staging exactly as it was before.
