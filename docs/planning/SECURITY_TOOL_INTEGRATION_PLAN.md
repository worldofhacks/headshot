# Security-tool integration plan

Date: 2026-07-21

Scope: Headshot/AgentForge platform source, deterministic local fake target, Railway staging Web,
and separately authorized live-target origins only.

## Trust boundary

Scanner output is untrusted evidence. It is never an `AttemptResult`, a Judge verdict, verified
campaign Coverage, or publication authority. The additive v1 contracts `SecurityToolRun`,
`ToolFinding`, `ScanArtifact`, and `ToolExecutionError` bind every normalized result to an exact tool
version, configuration digest, run nonce, target/surface, provenance, timestamps, raw-artifact hash,
OWASP mapping, reproduction locator, validation state, and human-publication gate.

Tool batches enter `security_tool_runs`, `scan_artifacts`, `security_tool_findings`, and
`tool_execution_errors` atomically. These repositories are append-only by database trigger. The
repository independently recomputes the artifact digest and checks all run/finding bindings before
insert. `security_tool_findings.human_publication_state` is database-constrained to
`blocked_pending_human_approval`.

Compatibility classification: the four schemas are additive v1 boundaries and the new
`AttemptResult` fields are optional additions. No existing required field or meaning was removed, so
this is backward-compatible and needs no contract-version bump. Both producer examples and consumer
required-field tests were extended; a breaking future change still requires a new version and migration
note.

## Execution boundary

- Commands are argument arrays with `shell=False`.
- The tool process gets a fresh HOME/TMPDIR and an explicit non-secret environment; parent secrets,
  cookies, Clerk material, database URLs, and target credentials are not inherited.
- CPU, address-space, file-size, descriptor, wall-clock, and captured-output limits are applied.
- Inputs are checked-in configuration and read-only source paths; artifacts are sanitized before
  persistence. No tool may apply an automatic fix.
- CI artifacts are retained for 14 days. Durable records store SHA-256 and sanitized bytes only.

## Tool integrations

### Semgrep

Pin `1.170.0`. Scan platform Python and TypeScript only (`src`, `console/src`, `migrations`, and
`scripts`) with checked-in `.semgrep.yml`, metrics disabled, and no hosted configuration. Run the
same deterministic rules twice to emit JSON and SARIF. `ERROR` matches fail CI; `WARNING` matches are
retained for validation. Rule metadata supplies deterministic OWASP Web 2021 and confidence values.
The parser normalizes the original artifact hash; no autofix command exists in CI.

### OWASP ZAP

Pin ZAP `2.17.0` by the Linux/amd64 image digest recorded in `security-tools/toolchain.lock.json`.
Only `zap-baseline.py` is constructed. The integration permits:

1. HTTP loopback or the exact fake hostname inside an internal Docker-only network;
2. one exact approved HTTPS Railway staging Web origin;
3. one exact approved HTTPS live-target origin with a separate ZAP authorization reference.

Identity-provider hosts, credential-bearing URLs, paths supplied as origins, unallowlisted hosts,
production, and active scan commands are rejected. The baseline is capped at one spider minute, two
total minutes, depth five, ten children, one scanner thread, 200 reported requests, 2 GiB RAM, two
CPUs, and 256 processes. Every reported URL is revalidated against the exact approved origin.
Platform-staging and live-target scans remain gated until the exact origin and, for a live target,
the separate authorization are persisted.

ZAP plugin IDs map deterministically to the repository's OWASP Web 2021 anchor. Unknown plugin IDs
remain visible under insecure design (`A04:2021`); they are not silently discarded.

### Promptfoo

Pin `0.121.19` and validate `security-tools/promptfoo/promptfooconfig.yaml` under Node 24. The provider
is a checked-in deterministic offline replay fixture. The config records `owasp:llm`, `owasp:api`,
`mitre:atlas`, and `nist:ai:measure` metadata. It uses no cloud service or hosted model. Promptfoo is
not the Judge and does not claim an `owasp:web` preset.

### Garak, PyRIT, and Giskard

The v1 adapter seam parses a documented interchange artifact and normalizes it through the same
contracts, duplicate checks, and publication gate. Garak is a breadth probe/seed source; PyRIT is a
multi-turn attack orchestrator and never verdict authority; Giskard RAGET is a RAG-specific seed
source. Fixture-based contract tests are checked in. Their status is **adapter integrated, execution
deferred** until a pinned offline invocation is completed and its raw output is evidenced.

### Dependency and secret scanning

Gitleaks `8.30.1`, npm's lockfile audit, and pip-audit `2.10.1` run as CI gates. Exact tool pins and
the ZAP architecture digest are in `security-tools/toolchain.lock.json`. Container/package and
frontend bundle gates remain part of the main pipeline.

## Simulated triage exercise

`tests/fixtures/security_tools/simulated_scan.json` contains 12 clearly synthetic findings across
critical, high, medium, low, and informational severities, including two intentional false
positives. Dispositions exercise validate, remediate, defer, document, and false-positive paths. A
Postgres integration test ingests this artifact through the same normalizer and append-only evidence
repository and proves all publication states remain human-blocked. Its provenance is `simulated`; it
cannot count as target evidence.

## Evidence and rollout

Local and CI evidence is recorded in `docs/evidence/ato/SECURITY_TOOL_EVIDENCE.md`. Railway staging
and any live-target scan require their own exact scope validation. A finding may move into the
campaign-facing finding workflow only after independent validation and a distinct authorized human
decision.
