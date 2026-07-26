# Headshot LLM Security Workbench

Verified: 2026-07-22.

Headshot implements the Burp-style workflow that is useful for a governed black-box LLM target; it
does not claim that the commercial PortSwigger Burp Suite product is installed. PortSwigger's own
tool inventory defines the reference workflow as target mapping, intercepting and logging traffic,
replay, automated customized attacks, scanning, decoding, comparison, sequencing, and optional
out-of-band/browser-specific tools:
<https://portswigger.net/burp/documentation/desktop/tools>.

## Capability map

| Reference workflow | Headshot implementation | Execution boundary |
|---|---|---|
| Dashboard + Target | Targets, Campaigns, Coverage | Versioned ready targets and enabled surfaces only |
| Proxy + Logger + Inspector | PostgreSQL target/agent ledgers, campaign-correlated Langfuse projection, sanitized Traces inspector | Every target request and all four agent roles are recorded; only hashes, sizes, timing, usage, cost, and status leave the Runner for Langfuse |
| Repeater | Regression replay | Versioned corpus plus fresh exact-scope authorization; no arbitrary raw resend |
| Intruder | Garak, PyRIT, Giskard and Promptfoo candidate/mutation toolchain | Five reviewed Garak/PyRIT/Promptfoo candidates join the 14-attempt full scan; Giskard remains analysis-only until it emits an explicit attack; PolicyGateway applies rate, attempt, timeout and cost caps |
| Scanner | Exact-origin passive ZAP plus independent Judge | Scanner findings are advisory and publication remains human-gated |
| Decoder | PyRIT Base64, ROT13 and ASCII-smuggling converters | Offline candidate transformation only |
| Comparer | Attempt evidence, independent Verdict and resilience history | Attack generation cannot approve its own result |
| Sequencer | Multi-turn lineage, scope hashes and nonce replay protection | Conversation ordering is content-addressed and replay-safe |
| Collaborator | Synthetic exfiltration canaries | No public callback listener or uncontrolled off-origin traffic is exposed |
| DOM/IAST/browser helpers | Not claimed for the black-box chat surface | Use separately authorized tooling if those surfaces enter scope |

The public Configuration screen renders this same server-owned map. The Traces screen exposes
organization-scoped target and agent observations: bounded request/response previews stay in
PostgreSQL, while the console also shows content hashes, per-role p50/p95 latency, measured agent
spend, tokens, Langfuse delivery proof, and deterministic passive signals. Queued observations are
shown as awaiting remote verification; only the authenticated exact query-back verifier can
atomically mark them exported/observed. Signals are not findings and cannot replace the independent
Judge.

## Authorization and evidence invariants

- There is one target exit: the PolicyGateway. Neither the workbench nor an imported tool opens a
  second network path.
- Repeater- and Intruder-style execution uses `headshot-full-scan-v1`, changes the baseline corpus
  identity, and requires a fresh approval
  bound to target, surface, corpus hash, nonce, rate, attempts, timeout, and cost.
- The target and agent ledgers store sanitized content and hashes. Raw prompts, target responses,
  credentials, and evidence bodies never reach Langfuse; the browser receives only bounded,
  organization-scoped projections.
- ZAP is passive and exact-origin. Active DAST, public out-of-band callbacks, DOM testing, and
  instrumented-runtime testing are explicitly not claimed.
- Tool output remains `scan_only`; publication of every finding/report stays
  `blocked_pending_human_approval` until an authorized human decision.

This design follows the assignment's requirement to combine deterministic validation, replay,
fuzzing, and protocol analysis with the multi-agent evaluator rather than treating a static payload
list or a single scanner as the platform.
