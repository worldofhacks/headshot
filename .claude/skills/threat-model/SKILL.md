---
name: threat-model
description: Maintain the living THREAT_MODEL.md for the target under test — map or deepen its attack surface across the six mandated categories, attach measured evidence from live probing, and keep the OWASP mapping versioned. Use this WHENEVER the user says "threat model", "map the attack surface", "deepen the threat model", when a new target is added, or when a live campaign has produced findings that should update per-category risk. This DESCRIBES THE TARGET, not the platform. NOT for authoring individual attack eval cases (that is adversarial-eval-lifecycle) and NOT for calibrating the Judge (that is judge-calibration).
---

# Threat Model

`THREAT_MODEL.md` is the target's attack-surface map and a graded hard gate. It opens with a ~500-word
summary and covers the six mandated categories; it describes the **target** (the OpenEMR Clinical
Co-Pilot is target #1), never the platform. Existing defenses are marked **to-be-probed** until observed
— never assumed. No real PHI is referenced anywhere.

## When this runs
"threat model", "map/deepen the attack surface", a target change, or new live findings to fold in.

## Inputs
The PRD, the target surface (endpoints, tools, auth) observed from the running target, and existing
eval/campaign results.

## Output — `THREAT_MODEL.md`
1. **~500-word summary:** key findings, highest-risk categories, and how the platform prioritizes coverage.
2. **The six categories**, each with **surface · impact · exploit difficulty · existing defenses
   (to-be-probed until observed)** and a qualitative risk score:
   - direct / indirect / multi-turn prompt injection
   - PHI leakage / cross-patient exposure / authorization bypass
   - state corruption / context poisoning
   - tool misuse / parameter tampering / recursive calls (the only category with autonomous *action*)
   - DoS / cost amplification
   - identity / role exploitation
3. **OWASP mapping, versioned (DECISIONS.md D15).** Web tags are **OWASP Top 10:2021** (the set the PRD
   enumerates — it lists SSRF standalone, which exists only in 2021); LLM tags are OWASP LLM Top 10 (2025).
   Store every mapping as a structured tag `{framework, version, id, name}`, never a bare `A10`. Include
   the 2021↔2025 crosswalk.
4. **Coverage priority** that feeds the Orchestrator, re-evaluated each run from observability.

## Discipline
- **Never assert an unobserved defense as present.** Mark it *to-be-probed*; the eval suite confirms or
  refutes it empirically. This honesty is the CISO move.
- A category the target cannot currently express is marked *modeled-but-not-exercisable*, with the reason.
- The exact auth mode and API shape may be open questions pending inspection; they change *how* attacks are
  delivered, not *which* categories apply — do not block on them, do not invent them.
