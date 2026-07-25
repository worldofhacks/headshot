# Security-tool ATO evidence

Evidence date: 2026-07-22 (America/New_York)

Branch: `codex/m1d-live-console-railway`

Artifact policy: hashes and sanitized summaries are retained here; temporary raw reports are not
committed.

## Verified execution evidence (local run mirroring CI)

Evidence date: 2026-07-21 (America/New_York). The following six tools were executed locally
against the same pinned versions, configuration, and scope the CI `security-tools` job runs
(GitHub `.github/workflows/ci.yml` and GitLab `.gitlab-ci.yml`). All runs were deterministic
and offline.

> **Two corrections to this paragraph, 2026-07-25 (base `107c11c`).**
>
> **(1) "ZAP ran against an isolated internal-network fake target only" is false.** A separately
> authorized **passive** baseline also ran against the real Co-Pilot target
> `https://agent-production-9f62.up.railway.app`, and unlike the fixture run its raw report **is
> committed** — [`docs/evidence/zap/zap-target.json`](../zap/zap-target.json), sha256 `89f10c94…`,
> `scan_provenance: live_target`. No **active** scan of any origin was ever authorized or run; that is
> the claim this paragraph should have been making.
>
> **(2) The `tmp/sec/` artifacts are not on disk and never were committed.** `tmp/` does not exist at
> this base and no `tmp/` path is tracked by git, so `tmp/sec/SHA256SUMS.txt` cannot be consulted and
> **none of the SHA-256 values in the table below can be verified from this repository.** They are
> retained as a record of a local run, not as evidence. The table's status column is corrected
> accordingly. Every row whose only backing is a `tmp/sec/` path is `unreproducible as recorded`; the
> commands are re-runnable from the pinned CI configuration, but a hash for an absent file is not
> evidence.

| Tool | Version (pinned) | Command / scope | Result | Artifact (relative path) | SHA-256 | Status |
|---|---|---|---|---|---|---|
| Semgrep | 1.170.0 | `semgrep scan --config .semgrep.yml --error --metrics=off --json` over `src`, `console/src`, `migrations`, `scripts` | 0 findings, 0 errors, **file count disputed — see the Semgrep discrepancy note** | `tmp/sec/semgrep.json` (**untracked; not on disk**) | `7c5dbd50…` **or** `151c4a7c…` — this document records two different SHA-256 values for the same artifact | **unreproducible as recorded** |
| Semgrep (SARIF) | 1.170.0 | same scan, `--sarif` output | 0 findings | `tmp/sec/semgrep.sarif` | `f14703448432ec0409a986d1d65a9a44f7dadffd499ac3a04a48241b1c7b0f85` | unreproducible as recorded (artifact absent) |
| pip-audit | 2.10.1 | `pip-audit . --strict --format=json` (project dependency graph) | 0 known vulnerabilities | `tmp/sec/pip-audit.json` | `7095098a7ddbddbb17e07cd21b65f81034f52c1f51eabfe27effe99497023ced` | unreproducible as recorded (artifact absent) |
| npm audit | npm CLI (console/) | `npm audit --audit-level=high --json` in `console/` | 0 vulnerabilities (info/low/moderate/high/critical all 0) | `tmp/sec/npm-audit.json` | `a979997e33539f5e0aa0ad2e31d04f4ab22a2daae57d998cff40f55f799cb65c` | unreproducible as recorded (artifact absent) |
| gitleaks | 8.30.1 | `gitleaks git . --redact --report-format json` | 0 leaks | `tmp/sec/gitleaks.json` | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` | unreproducible as recorded (artifact absent) |
| Promptfoo | 0.121.19 | `validate` => "Configuration is valid"; `eval` => 1/1 PASS (offline, deterministic) | prompt-injection instruction-override test returns `REFUSED_OFFLINE_FIXTURE`, no model call | `tmp/sec/promptfoo-eval.json` | (`tmp/sec/SHA256SUMS.txt` is absent; validate-txt `75cbb16e…`) | unreproducible as recorded (artifact absent) |
| OWASP ZAP | 2.17.0 (image digest `sha256:c558ee87358911ab17278c70991e856f57793e115d9cd0f88ca475cf82907a1a`) | passive baseline (`zap-baseline.py -m 1 -T 2 -I`) against isolated internal-network fake target `http://agentforge-zap-fake:8765` | 4 alerts (CSP not set, missing anti-clickjacking header, server version leak, X-Content-Type-Options missing), 8 instances | `tmp/sec/zap/zap.json` (**untracked; not on disk**) | `0eb37e27…` (unverifiable — artifact absent) | unreproducible as recorded; **fixture host, never evidence about a real target**. Re-runnable in CI, pinned by digest |

The Promptfoo config (`security-tools/promptfoo/promptfooconfig.yaml`) carries
`framework_mappings: owasp:llm, owasp:api, mitre:atlas, nist:ai:measure`. OWASP **Web** category
mapping is done by the platform's own deterministic validator over ZAP output, not by Promptfoo
(ADR-0001 F12). The four ZAP alerts are expected fake-server header findings — they are **scan
evidence about the fixture host, not target findings**, and normalize to OWASP Web A04/A05 with
publication state `blocked_pending_human_approval`.

### Every referenced security tool — status classification

Using only the permitted status labels: `operational and evidenced` /
`adapter integrated, execution deferred` / `evaluated and rejected` / `blocked pending
authorization`, plus two added 2026-07-25 because the original four could not express what the
artifacts on disk actually support: **`executed and evidenced (outside the platform's own command
path)`** — the run happened and its raw artifact is committed, but it was not produced by the
platform's committed constructor — and **`unreproducible as recorded`** — the recorded result cannot
be verified from this repository because its artifact is absent or its recorded values conflict. Note
that `unreproducible as recorded` is a statement about *this repository's evidence*, not about the
tool: every such row names a pinned command that is re-runnable from the CI configuration.

| Tool | Role | Status | Backing evidence |
|---|---|---|---|
| Semgrep 1.170.0 | SAST on platform code | unreproducible as recorded | `tmp/sec/semgrep.json`/`.sarif` **absent**; re-runnable via the CI `security-tools` job |
| pip-audit 2.10.1 | Python dependency audit | unreproducible as recorded | `tmp/sec/pip-audit.json` **absent**; re-runnable via the CI `security-tools` job |
| npm audit | Frontend dependency audit | unreproducible as recorded | `tmp/sec/npm-audit.json` **absent**; re-runnable via the CI console audit gate |
| gitleaks 8.30.1 | Secret scan | unreproducible as recorded | `tmp/sec/gitleaks.json` **absent**; re-runnable via the CI `secret-scan` gate. The recorded pass covered 73 of the current 205 revisions |
| Promptfoo 0.121.19 | Deterministic eval-runner + OWASP LLM/API/ATLAS/NIST mapping | unreproducible as recorded | `tmp/sec/promptfoo-eval.json` **absent**; re-runnable via the CI `security-tools` job |
| OWASP ZAP 2.17.0 | Web-layer DAST (OWASP Web half) | **split** — fixture baseline `unreproducible as recorded` (`tmp/sec/zap/zap.json` absent; fixture host is never target evidence); live-target passive baseline `executed and evidenced (outside the platform's own command path)` | fixture: re-runnable via CI `security-tools`. Live: `docs/evidence/zap/zap-target.json`, committed and hash-verified |
| NVIDIA Garak 0.15.1 | Breadth candidate source | operational and evidenced (bounded slice) | native `garak.report.jsonl` + adapter summary from `scripts/run_offline_llm_tools.sh`; CI `security-tools` job |
| Microsoft PyRIT 0.14.0 | Converter/multi-turn candidate source (never verdict authority) | operational and evidenced (bounded slice) | native converter + undetermined `AttackResult` JSON; CI `security-tools` job |
| Giskard Scan 1.0.0b3 | Agent/RAG scenario source | **adapter integrated, execution deferred** | Adapter and bridge exist, but `security-tools/reviewed/` holds **no `giskard.bundle.json`** — only garak, promptfoo and pyrit. Giskard contributes **zero** candidates to any runtime workload; its packaged scenario yields none by design. Do not present it as evidenced. |
| Headshot LLM Security Workbench 1.0.0 | Burp-style LLM intercept/replay/fuzz/scan/compare workflow | operational and evidenced | `outbound_http_requests`; Langfuse trace IDs; `tests/security_tools/test_workbench.py` |
| Burp Suite Pro / DAST / Enterprise | Commercial web DAST | evaluated and rejected | ADR-0001 §D (`docs/adrs/0001-build-vs-configure.md:70`) |
| Lakera Red / HiddenLayer / Robust Intelligence (Cisco AI Defense) | Commercial LLM red-team platforms | evaluated and rejected | ADR-0001 §D (`docs/adrs/0001-build-vs-configure.md:64`) |
| ZAP live-target passive baseline | Authorized-origin passive DAST | **executed and evidenced (outside the platform's own command path)** | native ZAP report committed at `docs/evidence/zap/zap-target.json`, sha256 `89f10c94…`, 7910 bytes, ZAP-stamped 2026-07-22 03:33:23 UTC; 3 alerts / 5 instances, all publication-blocked. See the drift note below for its three limits. |
| ZAP Railway **staging** self-scan | Deployed-origin DAST | not run; blocked pending separate authorization | staging deployment is verified at `https://web-staging-8e30.up.railway.app`, but no ZAP authorization was granted and no artifact exists |
| ZAP **active** scan (any origin) | Authorized-origin active DAST | blocked pending authorization | requires separately persisted exact ZAP authorization; campaign approval is insufficient. Chain is code-complete, default-disabled, never executed (`docs/security_tools/ACTIVE_SCAN_AND_TOOL_EVIDENCE.md`) |

**Garak / PyRIT / Giskard — confirmed bounded status.** Pinned native execution now runs in isolated
CI and locally: one Garak offline probe, three PyRIT converters plus native `AttackResult`, and the
Giskard packaged prompt-injection loader. Their native parsers are in
`src/agentforge/security_tools/native.py`; exact operational and adapter-only scope is maintained in
`src/agentforge/security_tools/catalog.py` and `docs/security/LLM_TOOLCHAIN.md`. No tool receives a
target URL or credential. Giskard's packaged generator template resolves no attack interaction and
therefore truthfully yields zero candidates. Framework orchestrators and target execution are not
claimed.

**Burp product / Headshot workbench.** ADR-0001 §D records why the commercial product is not
installed, while `docs/security/LLM_SECURITY_WORKBENCH.md` records the operational Headshot
alternative. The commercial exclusion rests on cumulative grounds:
(1) licensing/purchase cost exceeds the approved $50–200 OSS path (commercial LLM red-team
platforms are sales-only, $10k–$200k+); (2) closed execution and reporting limit contract-level
provenance and cannot be governed under the platform's own allowlist / cost caps; (3) vendor
governance cannot enforce the two-person approval and exact-origin policy; and (4) Burp
duplicates capabilities now composed in the LLM Security Workbench from the bounded passive ZAP
integration, request ledger, governed replay/mutation, and custom multi-agent evaluator.
Adopting a commercial "adversarial testing platform" *is* the reusable platform the assignment
asks us to build. A future separately authorized manual assessment may revisit Burp; it is not
installed or purchased here (`docs/adrs/0001-build-vs-configure.md:64-75`).

**Scanner output is evidence, never verdict or publication authority.** Every normalized finding
is stamped `"human_publication_state": "blocked_pending_human_approval"` in
`src/agentforge/security_tools/normalization.py:127`, is carried as `source_kind="security_tool"` with
`evidence_provenance="scan_only"` (or `"simulated"`), and never receives an independent-Judge
verdict from the scanner. The persistence layer **rejects** any scanner finding that does not already assert
`human_publication_state == "blocked_pending_human_approval"`
(`src/agentforge/security_tools/repository.py:79-85`, raising
`SecurityToolEvidenceError("scanner output cannot assert publication authority")`), and
simulated/scan-only rows are excluded from campaign Coverage. *(Corrected 2026-07-25: the previous
cite `api/postgres.py:330` was wrong, and `postgres.py:2671` — the only occurrence of that literal in
that module — is in the **read** projection and is immediately overridden by `:2672-2679`. There is no
insert-time re-stamp in `postgres.py`; the control is a refusal in the repository layer, which is
stronger.)* The contract tests assert this
invariant for both the deferred adapters and the simulated corpus
(`tests/security_tools/test_security_tools.py:143,252`).

## Status matrix

| Capability | Status | Evidence |
|---|---|---|
| Semgrep platform-source scan | **unreproducible as recorded** | Pinned `1.170.0`; JSON and SARIF completed with zero findings/errors across 111 tracked platform files — but this document also records 112 files and a second JSON SHA-256 for the same artifact, and the artifact itself is untracked. See the Semgrep discrepancy note. |
| Promptfoo offline configuration | **unreproducible as recorded** | Pinned `0.121.19`; Node `v25.3.0`; `Configuration is valid.`; no model or hosted provider used — recorded artifact `tmp/sec/promptfoo-eval.json` and its hash in `tmp/sec/SHA256SUMS.txt` are absent; re-runnable via the CI `security-tools` job |
| pip-audit project resolution | **unreproducible as recorded** | Pinned `2.10.1`; 38 resolved dependencies; zero known vulnerabilities — recorded artifact `tmp/sec/pip-audit.json` is absent; re-runnable via the CI `security-tools` job |
| ZAP local fake passive baseline | **unreproducible as recorded** | Pinned `2.17.0` image digest; isolated internal network `agentforge-zap-isolated` (created `--internal` at `.github/workflows/ci.yml:222`), fixture container `agentforge-zap-fake` (`:229`), scan target `http://agentforge-zap-fake:8765` (`:246`); 4 warnings normalized and human-blocked. Its stated artifact `tmp/sec/zap/zap.json` **does not exist on disk and no `tmp/` path is tracked by git** — the run is reproducible from `.github/workflows/ci.yml`, but nothing in this repository evidences it. Also, per the project's own rule, a fake/fixture host is never evidence about a real target. |
| ZAP Railway staging self-scan | **not run; blocked pending separate authorization** | The verified staging origin is `https://web-staging-8e30.up.railway.app`; no ZAP authorization was granted and no artifact exists |
| ZAP live-target passive baseline | **executed and evidenced (outside the platform's own command path)** | Raw native ZAP report committed at `docs/evidence/zap/zap-target.json`, sha256 `89f10c94…` (recomputed 2026-07-25, matches `artifact.json`, `run.json` and `findings.json` byte-for-byte); `byte_length` 7910 matches the file; 3 alerts / 5 instances against `https://agent-production-9f62.up.railway.app`; every finding `blocked_pending_human_approval` |
| ZAP **active** scan (any origin) | **blocked pending authorization** | Requires a separate persisted exact ZAP authorization; campaign approval is not sufficient. Never executed. |
| Garak 0.15.1 bounded slice | **operational and evidenced** | Native JSONL: 9 records, 1 candidate, 1 advisory in the 2026-07-22 local mirror; the same script runs in GitHub CI, while GitLab remains a passive source mirror |
| PyRIT 0.14.0 bounded slice | **operational and evidenced** | Native JSON: 3 converter candidates and an undetermined `AttackResult`; never verdict authority |
| Giskard Scan 1.0.0b3 bounded slice | **adapter integrated, execution deferred** | One packaged LLM01 scenario loaded; **0 explicit candidates and 0 findings** — no `giskard.bundle.json` exists in `security-tools/reviewed/`, so nothing enters any workload. Total tool-generated candidates ever imported: 5 (1 garak, 3 pyrit, 1 promptfoo, **0 giskard**) |
| Burp/commercial security platforms | **evaluated and rejected** | ADR-0001 records cost, licensing, closed-architecture, governance and ZAP/custom-platform redundancy rationale |

## Semgrep

Command boundary: checked-in `.semgrep.yml`, metrics disabled, platform source paths only, no hosted
registry configuration, no autofix. The CI equivalent adds explicit wall, per-file, and artifact-size
caps.

```text
semgrep 1.170.0
rules: 4
tracked targets scanned: 111
findings: 0
configuration errors: 0
JSON SHA-256: 151c4a7cdbc62e9a910fa30d8231b91f361bcb71caf7c3635ef426fdf7ef27bc
SARIF SHA-256: f14703448432ec0409a986d1d65a9a44f7dadffd499ac3a04a48241b1c7b0f85
```

Two pre-evidence configuration attempts failed closed: Semgrep rejected floating-point YAML metadata,
then rejected `tsx` as a language alias. Confidence metadata is now string-encoded and TypeScript is
the supported language selector. Neither failed attempt is reported as a scan.

## pip-audit

The project-path audit resolved the package declared by `pyproject.toml`; it did not substitute the
temporary scanner environment as the application dependency graph.

```text
pip-audit 2.10.1
exit: 0
dependencies: 38
known vulnerabilities: 0
JSON SHA-256: 7095098a7ddbddbb17e07cd21b65f81034f52c1f51eabfe27effe99497023ced
```

No `--fix` action was used.

## Promptfoo

`security-tools/promptfoo/promptfooconfig.yaml` uses only the local
`file://offline-provider.cjs` deterministic provider. Validation completed under a compatible local
Node runtime. The output included npm deprecation notices from transitive packages; it made no model,
Promptfoo Cloud, or hosted-provider call.

```text
promptfoo: 0.121.19
node: v25.3.0
validation exit: 0
result: Configuration is valid.
validation-output SHA-256: 9d2703f9e66092374268eaae5a2892f7644847438a2c2593a99ef28d0c1e8ac9
```

Promptfoo metadata covers `owasp:llm`, `owasp:api`, `mitre:atlas`, and `nist:ai:measure`.
OWASP Web mapping remains the deterministic ZAP parser's job. Promptfoo is not the Judge.

## OWASP ZAP local fake scan

The successful run used image
`ghcr.io/zaproxy/zaproxy@sha256:c558ee87358911ab17278c70991e856f57793e115d9cd0f88ca475cf82907a1a`
with `--platform linux/amd64`. The scanner and checked-in static fake target shared an internal
Docker-only network. The fake container exposed no host port and both containers dropped all
capabilities. The scanner filesystem was read-only except bounded tmpfs mounts and its report mount.

```text
profile: local_fake
exact origin: http://agentforge-zap-fake:8765
active scan: disabled
exit: 0
alerts: 4
alert instances: 8
reported URLs: exact origin plus /robots.txt and /sitemap.xml on the same origin
report SHA-256: 0eb37e27e1134cc570f487db68252290f71ef2dd0b297b94459b4eef635ba6d1
normalized findings: 4
normalized OWASP Web 2021 mappings: A04, A05
publication state: blocked_pending_human_approval
```

Warnings were expected fake-server header findings: anti-clickjacking, content type options, server
version disclosure, and CSP. They are scan evidence, not target findings. An earlier read-only run
failed before ZAP started because its HOME lacked a writable tmpfs; a second attempt failed before any
target request because Docker Desktop host networking did not expose loopback. The internal-network
run supersedes both and is the only run counted above.

## Normalization, persistence, and triage

Targeted contract/security-tool tests passed. The 12-finding simulated artifact covers every
severity, five disposition paths, and two false positives. It was normalized and inserted atomically
into the append-only Postgres tool-evidence tables; a direct mutation was rejected by the database
trigger. Every row retained `simulated` provenance and
`blocked_pending_human_approval`. Simulated and scan-only rows are excluded from campaign Coverage.

## Secret and dependency gates

Gitleaks `8.30.1` reported zero findings across 73 committed-history revisions **as of the pass that
produced this document**. History has since grown to 205 revisions at base `107c11c`, so roughly a
third of the current history is covered by that result; it must be re-run before release. Its
raw-directory pass identified two generic-key heuristics only inside ignored generated Clerk vendor
bundles under `console/dist`; no matched value was printed or retained. The authoritative
staged/branch/history passes and frontend production-bundle check will be recorded after final staging
and rebuild.

## Reconciliation notes (2026-07-25, base `107c11c`)

Three defects in this document were found by an independent read of the artifacts on disk and are
corrected above rather than silently rewritten. Full analysis:
[`docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md`](../../security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md)
RT-14.

**ZAP evidence/status drift — resolved, and it ran in both directions.** This document previously
recorded the live-target ZAP scan as *blocked pending authorization* while
[`docs/evidence/zap/README.md`](../zap/README.md) recorded exactly that scan as executed. The ZAP
directory is the correct side: the raw native report is committed and its sha256 recomputes to
`89f10c9445a98a324d80d38f5ed12db4e6e05885441b0da00598a8634b88edac`, matching all three metadata
records byte-for-byte. **The less obvious half of the drift, which no document had recorded:** the
*fake-target* baseline this document called "operational and evidenced" has **no artifact on disk at
all** — `tmp/sec/zap/zap.json` is untracked and absent. The only committed raw ZAP artifact in this
repository is the live one.

Three limits on that live scan, now stated here and in the ZAP directory, because they are what a
reviewer will ask first:

1. **It did not run through the platform's own governed command path.**
   `passive_baseline_argv` (`src/agentforge/security_tools/zap.py:83-109`) hardcodes
   `--network={ZAP_ISOLATED_NETWORK}` at `:89`, where `ZAP_ISOLATED_NETWORK = "agentforge-zap-isolated"`
   (`zap.py:17`). That network is created `--internal` by CI (`.github/workflows/ci.yml:222`), not by the
   constructor — so the constructor pins the scan onto a network that, as CI creates it, has no route to
   a public origin. The live scan was therefore produced outside that constructor.
2. **Its authorization record is free-form prose** — no approver identity, no `operation_hash`, no
   expiry — unlike a campaign authorization.
3. **Its `target_id` (`openemr-copilot`) is not a registered entry in the trusted target catalog.**

Two data-level defects in the ZAP directory are recorded for the owning lane and **not** changed here,
because they are artifact contents rather than prose: `findings.json` carries dangling
`"artifact_locator": "tmp/sec/zaptarget/zap-target.json#finding=N"` values while `artifact.json`
correctly points at `docs/evidence/zap/zap-target.json`; and `run.json` has
`started_at == finished_at` — a zero-length window whose stamps post-date ZAP's own generation time
by 93 s — so the recorded scan limits (depth 5, ≤10 children, 2-minute spider, 5-minute run) are not
corroborated by any artifact.

**Semgrep discrepancy — flagged, not resolved.** This document states two mutually exclusive results
for the same Semgrep pass: **112 files scanned** with JSON sha256 `7c5dbd50…`, and **111 tracked
targets scanned** with JSON sha256 `151c4a7c…`. The artifact is untracked and absent from disk, so
neither value can be verified from this repository and neither was chosen. Both status rows are
downgraded to *unreproducible as recorded*. The fix is to re-run the pinned scan and record one
result with one hash; do not pick a number.

**Three broken code cites corrected.** `normalization.py:134` → `:127` (the file is 133 lines);
`api/postgres.py:330` → `:2671`; `tests/security_tools/test_security_tools.py:65,144` → `:143,252`.
The invariants those cites support are all real — only the anchors had drifted.

## Remaining deployment evidence

The GitHub `security-tools` job will reproduce JSON/SARIF Semgrep, project pip-audit, offline
Promptfoo validation, and isolated passive ZAP artifacts. Railway staging self-scan remains human- and
deployment-gated. **No Clerk domain was scanned in this evidence pass, and no active scan of any
origin was authorized or run.** A passive live-target baseline *was* run against
`https://agent-production-9f62.up.railway.app`; its artifact is committed under
[`docs/evidence/zap/`](../zap/).
