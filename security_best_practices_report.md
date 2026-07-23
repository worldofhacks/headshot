# Headshot Security Best-Practices Review

Date: 2026-07-23

## Scope

This review covers the new agent runtime, model configuration, security-tool scope planning,
campaign execution, evidence persistence, and console projections. It does not claim a new live
target scan or hosted-model execution.

## Controls confirmed

- All target traffic still crosses the authenticated policy gateway and exact configured surface.
- The Red Team selects only cases already present in the authorized immutable corpus.
- The Judge remains independent of attack generation and gives deterministic oracle/canary
  evidence precedence.
- Critical publication and regression admission remain human-gated.
- Agent activity stores bounded structured detail plus input/output hashes, not raw prompts,
  transcripts, target credentials, or secrets.
- Deterministic agent engines report zero measured model cost and unknown token counts instead of
  inventing estimates.
- Hosted model choices are allowlisted by role and provider, append-only, audited, and staged
  pending a separate corpus/calibration authorization. They do not silently become active.
- ZAP is passive, exact-origin, separately authorized, and credential-free. Semgrep is presented
  as Headshot platform assurance rather than black-box target evidence.
- Tool status is separated into `in_campaign`, `companion_scan`, `platform_assurance`,
  `adapter_available`, and `not_applicable`; adapter presence is not presented as execution.

## Remaining risks and gaps

### Medium — Hosted model execution is intentionally not active

The console can safely stage a hosted Red Team or Documentation model, but the hosted execution
client is not implemented as an active campaign path. Activating it requires provider telemetry,
token and price capture, output validation, corpus re-authorization, and Judge calibration.

### Medium — Giskard is adapter-compatible but absent from the pinned full-scan corpus

Giskard scenarios and result artifacts can be imported and normalized, but no Giskard case is
currently in the authorized 14-case campaign. Keep the UI label at `adapter_available` until a
reviewed case is added, hashed, authorized, and executed.

### Medium — ZAP remains a companion workflow

ZAP findings can be normalized into the common finding contract, but a passive live-origin
baseline needs its own scan authorization and durable launch workflow. Do not imply that launching
an LLM campaign also launches ZAP.

### Medium — Target authoring remains catalog-controlled

The current trusted target catalog is safer than accepting arbitrary browser-supplied URLs, but it
limits usability. A future target wizard should create a draft, resolve and pin the exact origin,
block private/identity-provider destinations, test a credential-free readiness request, require
review, and only then publish an immutable target version.

### Low — Provider costs depend on authoritative observations

The deterministic four-agent runtime correctly records zero model spend. Nonzero hosted-model cost
must come from provider usage plus a versioned price source; missing token or price observations
must remain null/unavailable rather than estimated.

### Operational — Credential hygiene

No newly reviewed runtime path persists secrets in agent detail or UI projections. Any credentials
previously pasted into chat or shared outside the secret manager should be rotated and stored only
in deployment-managed secret variables.

## Recommended next security increment

Implement the reviewed target-onboarding workflow and a separately authorized companion-scan
executor. Then add one pinned Giskard candidate and a hosted-model calibration fixture, proving both
through the same immutable authorization, evidence, independent-Judge, cost, and audit contracts
before changing their UI status.
