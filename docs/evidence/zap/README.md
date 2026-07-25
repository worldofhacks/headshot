# Live OWASP ZAP passive-baseline evidence

This directory preserves the normalized, publication-gated evidence from the passive
OWASP ZAP baseline against the deployed OpenEMR Clinical Co-Pilot target.

## Scope and safety

- Exact target: `https://agent-production-9f62.up.railway.app`
- Mode: unauthenticated passive baseline only; no active attack rules
- Data: public responses and synthetic fixtures only; no patient data
- Guardrail: exact-origin allowlist; off-origin redirects were not scanned
- Limits (as configured, **not corroborated by any artifact** — see *Known limits* below): depth 5,
  at most 10 children, 2-minute spider, 5-minute total run
- Authorization: [AUTHORIZATION.md](AUTHORIZATION.md)

## Known limits (recorded 2026-07-25)

The artifact in this directory is real and hash-verified. Three things it is **not**, stated here so
the evidence is not over-read:

1. **It did not run through the platform's own governed command path.**
   `passive_baseline_argv` (`src/agentforge/security_tools/zap.py:83-109`) hardcodes
   `--network={ZAP_ISOLATED_NETWORK}` at `:89`, where `ZAP_ISOLATED_NETWORK = "agentforge-zap-isolated"`
   (`zap.py:17`); CI creates that network `--internal` (`.github/workflows/ci.yml:222`). So the
   constructor pins any scan onto a network that, as the project creates it, has no route to a public
   origin. This scan was produced outside that constructor — it is evidence about the target, not
   evidence that the platform's ZAP integration can scan an authorized live origin.
2. **The authorization record is free-form prose.** [AUTHORIZATION.md](AUTHORIZATION.md) carries no
   approver identity, no `operation_hash`, and no expiry, unlike a campaign authorization.
3. **`target_id: openemr-copilot` is not a registered entry in the trusted target catalog**, so this
   run is not bound to a catalog-resolved scope.

Two data defects for the owning lane, left in place rather than edited because they are artifact
contents: `findings.json` carries dangling `"artifact_locator": "tmp/sec/zaptarget/zap-target.json#finding=N"`
values (the correct path is the one in `artifact.json`, `docs/evidence/zap/zap-target.json`), and
`run.json` records `started_at == finished_at` — a zero-length window whose stamps post-date ZAP's own
generation time by 93 s, which is why the configured limits above cannot be corroborated.

This directory is the authoritative account of the live passive baseline.
[`docs/evidence/ato/SECURITY_TOOL_EVIDENCE.md`](../ato/SECURITY_TOOL_EVIDENCE.md) previously
contradicted it by recording the live-target scan as blocked; that drift is resolved there as of
2026-07-25.

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
