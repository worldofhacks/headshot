# Offline LLM security toolchain

Verified: 2026-07-22. The tools in this document are CI/tooling dependencies, not Railway runtime
dependencies. They receive no target URL, target credential, Clerk material, database URL, or real
PHI. Synthetic prompts only.

## Authority boundary

Native tool output is untrusted. An adapter may create a `ToolAttackCandidate` or a `ToolFinding`
with `scan_only` provenance. It cannot create authorization, `AttemptResult`, trusted evidence,
Coverage, or a verdict. Only the Policy Gateway dispatches an explicitly reviewed candidate, and
only the independent Judge adjudicates trusted gateway evidence. Critical publication remains
blocked pending human approval.

The approved `m11-seed-corpus-v1` remains the nine-case authored baseline. The deployed Web and
Runner now prepare `headshot-full-scan-v1`: those nine cases plus five explicitly reviewed,
contract-validated candidates from the pinned Garak, PyRIT, and Promptfoo artifacts. The exact 14
attempts receive a distinct content hash and corpus ID, so no existing nine-case campaign grant can
authorize the expanded scan. The native tools remain isolated CI/tooling dependencies; only their
reviewed, content-hashed candidate bundles are packaged into the Railway runtime.

## Implemented and evidenced scope

| Tool | Native offline execution | Imported output | Adapter-only / not executed |
|---|---|---|---|
| Garak 0.15.1 | `dan.Dan_11_0`, one generation, `test.Repeat`, seed 42 | completed attempt prompts and eval totals from JSONL | other probe families and any target execution |
| PyRIT 0.14.0 | Base64, ROT13, and ASCII-smuggling converters | converter results and native `AttackResult` JSON; success is advisory | Crescendo, TAP, Skeleton Key, scorers, and target orchestration |
| Giskard Scan 1.0.0b3 | packaged prompt-injection scenario loader | explicit scenario interactions and scan-result exports | LLM-generated interactions, GOAT, Crescendo, GCG, and target scan |
| Promptfoo 0.121.19 | one pre-authored offline eval through a local file provider | result/test-case JSON; responses are discarded | remote red-team generation and remote-only plugins |

Giskard's packaged LLM01 scenario currently contains a generator template rather than a resolved
attack message, so the evidenced run truthfully imports zero candidates. The adapter will import an
explicit interaction if a later authorized, offline scenario resolution supplies one.

At runtime, each tool-generated attempt has an `AF-M11-TOOL-*` case ID containing the first 12
hex characters of its provenance hash. The complete tool/version/technique/candidate/provenance
record is part of the schema-validated authored case and its content hash. Every attempt—authored or
tool-generated—uses the same Policy Gateway, recorder, independent Judge, and publication gate.

Promptfoo runs with `PROMPTFOO_DISABLE_REMOTE_GENERATION=true`,
`PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true`, and telemetry disabled. ZAP 2.17.0 and Semgrep
1.170.0 remain the web and source scanners described in the main security-tool evidence record.
The operational Headshot LLM Security Workbench composes their governed capabilities into a
Burp-style intercept, inspect, replay, fuzz, scan, compare, decode and sequence workflow. The
commercial Burp product itself is not installed or claimed; see `LLM_SECURITY_WORKBENCH.md`.

## Reproduction and artifacts

Run from the repository root on Linux with Python 3.12, Node, npm, curl, and `sha256sum`:

```bash
bash scripts/run_offline_llm_tools.sh
```

The script creates isolated virtual environments under its temporary work directory and writes
native artifacts plus `adapter-summary.json` under `LLM_TOOL_ARTIFACT_DIR`. Both CI systems run the
same script and retain sanitized artifacts for 14 days. Exact pins and the verified Giskard wheel
digest are in `security-tools/toolchain.lock.json`.

## Import limits and provenance

- 10 MiB per native artifact and bundle; 2,000 native records; 500 findings; 200 candidates.
- 32 turns per candidate and 20,000 UTF-8 bytes per turn.
- Malformed records and mismatched tool, version, artifact, candidate, or provenance hashes fail
  closed. Duplicate candidate content is removed at native import and rejected at bundle review.
- Candidate IDs are content-addressed. `source_artifact_sha256` and a canonical
  `provenance_sha256` bind origin and semantics; mutation lineage carries both candidate ID and
  provenance hash.
- Parsers read prompts/interactions and ignore Garak outputs, PyRIT target responses/scores, and
  Promptfoo provider responses when constructing candidates.

These controls make the toolchain a candidate/advisory source, never a second dispatch or verdict
path.
