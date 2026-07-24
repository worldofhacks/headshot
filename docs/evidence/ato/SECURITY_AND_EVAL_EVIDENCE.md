# Security, eval, and synthetic-data evidence

## Evidence summary

| Evidence family | What is present | What it proves | What it does not prove |
|---|---|---|---|
| Source/platform tests | Unit, contract, auth, migration, queue, policy, runner, console, browser, container, and security-tool suites | Controls are testable and CI has defined gates | The moving exact final commit passed or is deployed |
| Active eval seeds | 9 schema-valid active cases across data exfiltration, prompt injection, and tool misuse | Structured boundary/invariant coverage and OWASP mappings | A final-release live result; active seed records remain `NOT_EXECUTED` |
| Draft evals and ground truth | Security-owner corpus/calibration work exists on its separate branch | A model calibration run met its documented thresholds for the identities it recorded | Final exact-route identity matches, human enablement, or model decision authority |
| Historical target artifacts | Prior response/manifests under `evals/results/` | The named historical workflow produced retained artifacts | Current deployed four-agent/Langfuse execution |
| Platform security tools | Pinned Semgrep, pip-audit, npm audit, Gitleaks, Promptfoo, Garak, PyRIT, Giskard, and isolated ZAP evidence | Historical local/CI scanner execution under the recorded scope | An exact final-release scan or an authorized live-origin active scan |
| Vulnerability reports | Report set and owner-maintained index | The reports exist for review | Independent reproduction, publication approval, or final release linkage unless each report says so |
| Langfuse live review | Exact deployed release/migration predates the candidate | The UI's unavailable state is truthful | Physical-attempt tracing or end-to-end query-back acceptance |
| Performance/load | No final report or frozen 100-case corpus in this candidate | Nothing | A 100-case live baseline, throughput, bottleneck, or owner-authored bottleneck/recommendation |

## Fresh local corpus validation

During assembly of this packet, the inspected source baseline produced:

```text
valid corpus: 16 authored cases (9 active, 7 draft, 0 retired),
30 ground-truth labels, 6 categories, 1 fixtures
no duplicate input sequences: 9 cases
```

Commands:

```bash
PYTHONPATH=src python -m agentforge.evals validate-corpus evals
PYTHONPATH=src python -m agentforge.evals detect-duplicate-sequence evals/seeds
```

The active nine-case corpus covers three categories and every active seed carries the synthetic
fixture ID, `contains_real_phi: false`, a boundary/invariant test-design classification, and structured
OWASP tags. The exact mapping is
[`../OWASP_COVERAGE_MATRIX.md`](../OWASP_COVERAGE_MATRIX.md).

Every active seed currently retains `execution_status: NOT_EXECUTED`. That authoring-state field is
authoritative for the seed record and is not overwritten by a historical manifest. Final-release
results must be separate recorder/Judge records tied to the exact campaign, release, corpus hash, and
Langfuse reconciliation.

The security owner's latest calibration branch is not a frozen 100-case campaign corpus. Its
model-Judge run passed the owner's documented agreement/false-negative/false-positive/abstention/ECE
thresholds for the identities captured there, but `human_approved=false` and
`runtime_enabled=false`. More importantly, those identities do not exactly match the candidate's
`google-vertex/global` Judge route and `atlas-cloud/fp8` Red Team route. The release therefore treats
the model Judge as advisory/fail-closed and gives deterministic oracles decisive precedence. This
does not block the campaign; it prevents model-only safety claims.

## Synthetic-data controls

The release gate requires all of the following:

- a versioned synthetic fixture with explicit provenance and `contains_real_phi=false`;
- an exact corpus hash bound into the human-approved operation hash;
- a target/surface/version whose authorization is limited to synthetic testing;
- target credential resolution only on the private Runner;
- deterministic canary/oracle references where the target can actually be seeded;
- an honest `INDETERMINATE`/human escalation path where deterministic observation is unavailable;
- no credential, session value, raw clinical context, attack body, or target response in Langfuse;
- no real PHI in repository artifacts, logs, screenshots, reports, or demo material; and
- abort with preserved partial evidence if the target, fixture, credential lease, caps, or provenance
  changes.

The fixture and corpus validators are in
[`../../../src/agentforge/evals/`](../../../src/agentforge/evals/), while the exact authorization
binding is in [`../../../src/agentforge/campaign/`](../../../src/agentforge/campaign/).

## Platform scan evidence

The retained detailed evidence is
[`SECURITY_TOOL_EVIDENCE.md`](SECURITY_TOOL_EVIDENCE.md). Its historical pinned run reports:

- Semgrep: zero findings/errors in the recorded platform-source scope;
- pip-audit: zero known vulnerabilities in the recorded resolved graph;
- npm audit: zero vulnerabilities in the recorded console graph;
- Gitleaks: zero leaks in the authoritative recorded pass;
- Promptfoo: one deterministic offline case passed with no hosted model call;
- Garak, PyRIT, and Giskard: bounded offline/native slices only;
- ZAP: four expected header warnings against an isolated fake fixture, not Headshot or the live
  Clinical Co-Pilot; and
- live-origin ZAP: **blocked** until its own exact authorization exists.

The evidence is dated and branch-scoped. It must not be represented as the scan result for the final
release commit. GitHub CI must rerun the security-tools and secret-scan jobs on the exact release, and
the resulting run/artifacts must be recorded without credential-bearing output.

## Vulnerability evidence

The owner-maintained report index is
[`../../vulnerabilities/README.md`](../../vulnerabilities/README.md). This packet links it without
restating, changing, or upgrading the reports' conclusions, including owner-controlled reports
004–006. Publication, remediation, and regression admission remain separate human/deterministic
gates.

## Langfuse and agent evidence

The implemented source writes every agent execution to PostgreSQL before projecting typed Langfuse
observations. A role execution is an AGENT; every physical hosted invocation is one child
`provider.openrouter.attempt` GENERATION. It records parent/run/attempt identity, order, configured
and observed provider/model endpoint, latency, safe input/output hashes, token fields when supplied,
physical sequence/retries/errors, provider request/event identity, and provider-reported/measured
cost when available. The logical hosted-runtime child is metadata-only for token/cost accounting, so
physical usage is counted once. Missing billing fields remain unavailable.

The current live review records deployed release `23490ea` and schema `0013`; it predates the
candidate physical lineage. Therefore there are no reconciliation totals to report for the reviewed
`0018` source. Staging Langfuse credentials/environment variables have been prepared without
triggering a deployment, and no key is recorded here. Final acceptance requires exact remote
query-back using
`scripts/verify_langfuse_campaign.py`; an SDK flush is not evidence.

## Fresh selected local tests

The following selected groups passed while this packet was assembled:

```text
tests/contract
tests/auth/test_permissions.py
tests/auth/test_config.py
tests/test_campaign_authorization.py
tests/test_agent_langfuse_migration.py
tests/test_hosted_agent_execution_lineage.py
tests/test_verify_langfuse_campaign.py
```

The candidate base's full backend run recorded **1,617 passed, 3 skipped** after the exact-route and
physical-tracing changes. Focused hosted/provider/trace tests also passed. Later integration edits
make those results historical branch evidence, not a substitute for a fresh complete suite or
authoritative GitHub CI on the final SHA.

## Unavailable final evidence

- exact final-commit scanner artifacts and CI URLs;
- a security-owner frozen 100-case corpus hash, final authorized campaign ID, and evidence ID;
- reviewed role/global hosted-call ceilings compatible with the exact 100-case workload and retry
  policy (the current closed 56-call maximum cannot satisfy the 400-call pre-retry reservation);
- an exact-runtime-identity model-Judge enablement (the model remains advisory without it);
- complete ordered deployed agent execution rows;
- Langfuse expected, observed, missing, extra, token, cost, and error totals;
- provider billing reconciliation;
- platform CPU, memory, queue, DB, storage, and end-to-end performance baselines; and
- an authorized live-load result and security-owner-supplied bottleneck/recommendation.

These remain unavailable/blocked rather than being inferred from local tests, old manifests, or
simulated data.
