# Simulated Scan Triage

> **SIMULATED SCAN — triage exercise only. These findings are synthetic fixture data, NEVER real target evidence. Publication stays blocked pending human approval.**

Reproduce with `python -m agentforge.security_tools.triage_cli tests/fixtures/security_tools/simulated_scan.json`. 12 findings normalized through the shared adapter parser (`evidence_provenance=simulated`).

| id | severity | OWASP | confidence | disposition | rationale |
| --- | --- | --- | --- | --- | --- |
| sim-001 | critical | A01:2021 | 0.98 | remediate | High-confidence exploitable defect; open a fix and re-test after patch. |
| sim-002 | high | A03:2021 | 0.94 | validate | Plausible exploit path; route to Judge for independent confirmation before action. |
| sim-003 | high | LLM01:2025 | 0.88 | remediate | High-confidence exploitable defect; open a fix and re-test after patch. |
| sim-004 | medium | A05:2021 | 0.84 | defer | Real but low-urgency hardening item; schedule behind higher-severity work. |
| sim-005 | medium | LLM05:2025 | 0.81 | document | Observation worth recording for coverage; no immediate exploit to chase. |
| sim-006 | low | A09:2021 | 0.71 | document | Observation worth recording for coverage; no immediate exploit to chase. |
| sim-007 | info | A04:2021 | 0.62 | defer | Real but low-urgency hardening item; schedule behind higher-severity work. |
| sim-008 | low | LLM02:2025 | 0.79 | validate | Plausible exploit path; route to Judge for independent confirmation before action. |
| sim-009 | medium | A10:2021 | 0.86 | remediate | High-confidence exploitable defect; open a fix and re-test after patch. |
| sim-010 | info | A06:2021 | 0.15 | false_positive | Scanner artifact refuted on review; reject so it cannot inflate the corpus. |
| sim-011 | high | LLM06:2025 | 0.93 | validate | Plausible exploit path; route to Judge for independent confirmation before action. |
| sim-012 | low | A07:2021 | 0.68 | false_positive | Scanner artifact refuted on review; reject so it cannot inflate the corpus. |

## False-positive justifications

- **sim-010** — Dependency flagged at confidence 0.15 against a version the pinned lockfile never ships; the vulnerable code path is not reachable in the target, so the alert is a false positive.
- **sim-012** — Authentication observation duplicates an already-enforced control; manual review confirms the guard is present and the reported gap does not exist, so the alert is a false positive.
