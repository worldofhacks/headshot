# Live OWASP ZAP passive-baseline evidence

This directory preserves the normalized, publication-gated evidence from the passive
OWASP ZAP baseline against the deployed OpenEMR Clinical Co-Pilot target.

## Scope and safety

- Exact target: `https://agent-production-9f62.up.railway.app`
- Mode: unauthenticated passive baseline only; no active attack rules
- Data: public responses and synthetic fixtures only; no patient data
- Guardrail: exact-origin allowlist; off-origin redirects were not scanned
- Limits: depth 5, at most 10 children, 2-minute spider, 5-minute total run
- Authorization: [AUTHORIZATION.md](AUTHORIZATION.md)

## Results

| Finding | Severity | Mapping | Publication |
| --- | --- | --- | --- |
| Strict-Transport-Security Header Not Set | Low | OWASP Web A04:2021 | Blocked pending human approval |
| X-Content-Type-Options Header Missing | Low | OWASP Web A05:2021 | Blocked pending human approval |
| Re-examine Cache-control Directives | Info | OWASP Web A04:2021 | Blocked pending human approval |

The result is intentionally stated narrowly: this passive baseline found three
hardening observations, not a confirmed exploit.

## Evidence integrity

- Raw artifact: [zap-target.json](zap-target.json)
- Raw SHA-256: `89f10c9445a98a324d80d38f5ed12db4e6e05885441b0da00598a8634b88edac`
- Normalized findings: [findings.json](findings.json)
- Tool: `zap@2.17.0`
- Provenance: `live_target`
- Run nonce: `zaptarget-passive-baseline-0001`
- Run metadata: [run.json](run.json)
- Artifact metadata: [artifact.json](artifact.json)

Each record conforms to the platform's versioned security-tool evidence contract and
remains `unvalidated` / `blocked_pending_human_approval` until independently reviewed.
