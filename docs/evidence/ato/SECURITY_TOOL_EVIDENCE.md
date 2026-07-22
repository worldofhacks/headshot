# Security-tool ATO evidence

Evidence date: 2026-07-22 (America/New_York)

Branch: `codex/m1d-live-console-railway`

Artifact policy: hashes and sanitized summaries are retained here; temporary raw reports are not
committed.

## Verified execution evidence (local run mirroring CI)

Evidence date: 2026-07-21 (America/New_York). The following six tools were executed locally
against the same pinned versions, configuration, and scope the CI `security-tools` job runs
(GitHub `.github/workflows/ci.yml` and GitLab `.gitlab-ci.yml`). All runs were deterministic
and offline; ZAP ran against an isolated internal-network fake target only. Raw artifacts and
their SHA-256 sums live under `tmp/sec/` (see `tmp/sec/SHA256SUMS.txt`); these are working
artifacts, not committed evidence.

| Tool | Version (pinned) | Command / scope | Result | Artifact (relative path) | SHA-256 | Status |
|---|---|---|---|---|---|---|
| Semgrep | 1.170.0 | `semgrep scan --config .semgrep.yml --error --metrics=off --json` over `src`, `console/src`, `migrations`, `scripts` | 0 findings, 0 errors, 112 files scanned | `tmp/sec/semgrep.json` | `7c5dbd506a4cada7f81a396471eb9413f722bf73d1ce16dcb6c26e339288376e` | operational and evidenced |
| Semgrep (SARIF) | 1.170.0 | same scan, `--sarif` output | 0 findings | `tmp/sec/semgrep.sarif` | `f14703448432ec0409a986d1d65a9a44f7dadffd499ac3a04a48241b1c7b0f85` | operational and evidenced |
| pip-audit | 2.10.1 | `pip-audit . --strict --format=json` (project dependency graph) | 0 known vulnerabilities | `tmp/sec/pip-audit.json` | `7095098a7ddbddbb17e07cd21b65f81034f52c1f51eabfe27effe99497023ced` | operational and evidenced |
| npm audit | npm CLI (console/) | `npm audit --audit-level=high --json` in `console/` | 0 vulnerabilities (info/low/moderate/high/critical all 0) | `tmp/sec/npm-audit.json` | `a979997e33539f5e0aa0ad2e31d04f4ab22a2daae57d998cff40f55f799cb65c` | operational and evidenced |
| gitleaks | 8.30.1 | `gitleaks git . --redact --report-format json` | 0 leaks | `tmp/sec/gitleaks.json` | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` | operational and evidenced |
| Promptfoo | 0.121.19 | `validate` => "Configuration is valid"; `eval` => 1/1 PASS (offline, deterministic) | prompt-injection instruction-override test returns `REFUSED_OFFLINE_FIXTURE`, no model call | `tmp/sec/promptfoo-eval.json` | (see `tmp/sec/SHA256SUMS.txt`; validate-txt `75cbb16e3fefa29dc7484c2d25b30ad1b9aab724347110f9e2683c8f097facf5`) | operational and evidenced |
| OWASP ZAP | 2.17.0 (image digest `sha256:c558ee87358911ab17278c70991e856f57793e115d9cd0f88ca475cf82907a1a`) | passive baseline (`zap-baseline.py -m 1 -T 2 -I`) against isolated internal-network fake target `http://agentforge-zap-fake:8765` | 4 alerts (CSP not set, missing anti-clickjacking header, server version leak, X-Content-Type-Options missing), 8 instances | `tmp/sec/zap/zap.json` | `0eb37e27e1134cc570f487db68252290f71ef2dd0b297b94459b4eef635ba6d1` | operational and evidenced (local isolated fake-target baseline; also runs in CI, pinned by digest) |

The Promptfoo config (`security-tools/promptfoo/promptfooconfig.yaml`) carries
`framework_mappings: owasp:llm, owasp:api, mitre:atlas, nist:ai:measure`. OWASP **Web** category
mapping is done by the platform's own deterministic validator over ZAP output, not by Promptfoo
(ADR-0001 F12). The four ZAP alerts are expected fake-server header findings — they are **scan
evidence about the fixture host, not target findings**, and normalize to OWASP Web A04/A05 with
publication state `blocked_pending_human_approval`.

### Every referenced security tool — status classification

Using only the four permitted status labels: `operational and evidenced` /
`adapter integrated, execution deferred` / `evaluated and rejected` / `blocked pending
authorization`.

| Tool | Role | Status | Backing evidence |
|---|---|---|---|
| Semgrep 1.170.0 | SAST on platform code | operational and evidenced | `tmp/sec/semgrep.json`/`.sarif`; CI `security-tools` job |
| pip-audit 2.10.1 | Python dependency audit | operational and evidenced | `tmp/sec/pip-audit.json`; CI `security-tools` job |
| npm audit | Frontend dependency audit | operational and evidenced | `tmp/sec/npm-audit.json`; CI console audit gate |
| gitleaks 8.30.1 | Secret scan | operational and evidenced | `tmp/sec/gitleaks.json`; CI `secret-scan` gate |
| Promptfoo 0.121.19 | Deterministic eval-runner + OWASP LLM/API/ATLAS/NIST mapping | operational and evidenced | `tmp/sec/promptfoo-eval.json`; CI `security-tools` job |
| OWASP ZAP 2.17.0 | Web-layer DAST (OWASP Web half) | operational and evidenced (isolated fake-target baseline; also runs in CI, pinned by digest) | `tmp/sec/zap/zap.json`; CI `security-tools` job |
| NVIDIA Garak 0.15.1 | Breadth candidate source | operational and evidenced (bounded slice) | native `garak.report.jsonl` + adapter summary from `scripts/run_offline_llm_tools.sh`; CI `security-tools` job |
| Microsoft PyRIT 0.14.0 | Converter/multi-turn candidate source (never verdict authority) | operational and evidenced (bounded slice) | native converter + undetermined `AttackResult` JSON; CI `security-tools` job |
| Giskard Scan 1.0.0b3 | Agent/RAG scenario source | operational and evidenced (packaged-scenario slice) | native packaged LLM01 scenario export; CI `security-tools` job |
| Burp Suite Pro / DAST / Enterprise | Commercial web DAST | evaluated and rejected | ADR-0001 §D (`docs/adrs/0001-build-vs-configure.md:70`) |
| Lakera Red / HiddenLayer / Robust Intelligence (Cisco AI Defense) | Commercial LLM red-team platforms | evaluated and rejected | ADR-0001 §D (`docs/adrs/0001-build-vs-configure.md:64`) |
| ZAP Railway staging / live-target self-scan | Deployed-origin DAST | blocked pending authorization | requires separately persisted exact ZAP authorization; campaign approval is insufficient |

**Garak / PyRIT / Giskard — confirmed bounded status.** Pinned native execution now runs in isolated
CI and locally: one Garak offline probe, three PyRIT converters plus native `AttackResult`, and the
Giskard packaged prompt-injection loader. Their native parsers are in
`src/agentforge/security_tools/native.py`; exact operational and adapter-only scope is maintained in
`src/agentforge/security_tools/catalog.py` and `docs/security/LLM_TOOLCHAIN.md`. No tool receives a
target URL or credential. Giskard's packaged generator template resolves no attack interaction and
therefore truthfully yields zero candidates. Framework orchestrators and target execution are not
claimed.

**Burp / commercial — why rejected.** ADR-0001 §D records the exclusion on cumulative grounds:
(1) licensing/purchase cost exceeds the approved $50–200 OSS path (commercial LLM red-team
platforms are sales-only, $10k–$200k+); (2) closed execution and reporting limit contract-level
provenance and cannot be governed under the platform's own allowlist / cost caps; (3) vendor
governance cannot enforce the two-person approval and exact-origin policy; and (4) Burp
duplicates the bounded passive ZAP integration plus the platform's custom multi-agent evaluator.
Adopting a commercial "adversarial testing platform" *is* the reusable platform the assignment
asks us to build. A future separately authorized manual assessment may revisit Burp; it is not
installed or purchased here (`docs/adrs/0001-build-vs-configure.md:64-75`).

**Scanner output is evidence, never verdict or publication authority.** Every normalized finding
is stamped `"human_publication_state": "blocked_pending_human_approval"` in
`normalization.py:134`, is carried as `source_kind="security_tool"` with
`evidence_provenance="scan_only"` (or `"simulated"`), and never receives an independent-Judge
verdict from the scanner. The Postgres persistence layer re-stamps
`publication_status = "blocked_pending_human_approval"` on insert (`src/agentforge/api/postgres.py:330`),
and simulated/scan-only rows are excluded from campaign Coverage. The contract tests assert this
invariant for both the deferred adapters and the simulated corpus
(`tests/security_tools/test_security_tools.py:65,144`).

## Status matrix

| Capability | Status | Evidence |
|---|---|---|
| Semgrep platform-source scan | **operational and evidenced** | Pinned `1.170.0`; JSON and SARIF completed with zero findings/errors across 111 tracked platform files |
| Promptfoo offline configuration | **operational and evidenced** | Pinned `0.121.19`; Node `v25.3.0`; `Configuration is valid.`; no model or hosted provider used |
| pip-audit project resolution | **operational and evidenced** | Pinned `2.10.1`; 38 resolved dependencies; zero known vulnerabilities |
| ZAP local fake passive baseline | **operational and evidenced** | Pinned `2.17.0` image digest; isolated internal network; 4 warnings normalized and human-blocked |
| ZAP Railway staging self-scan | **blocked pending authorization** | Exact deployed staging origin and deployment verification are not yet recorded |
| ZAP live-target scan | **blocked pending authorization** | Requires a separate persisted exact ZAP authorization; campaign approval is not sufficient |
| Garak 0.15.1 bounded slice | **operational and evidenced** | Native JSONL: 9 records, 1 candidate, 1 advisory in the 2026-07-22 local mirror; same script runs in both CIs |
| PyRIT 0.14.0 bounded slice | **operational and evidenced** | Native JSON: 3 converter candidates and an undetermined `AttackResult`; never verdict authority |
| Giskard Scan 1.0.0b3 bounded slice | **operational and evidenced** | One packaged LLM01 scenario loaded; 0 explicit candidates and 0 findings, as expected for the unresolved generator template |
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

Gitleaks `8.30.1` reported zero findings across 73 committed-history revisions. Its raw-directory
pass identified two generic-key heuristics only inside ignored generated Clerk vendor bundles under
`console/dist`; no matched value was printed or retained. The authoritative staged/branch/history
passes and frontend production-bundle check will be recorded after final staging and rebuild.

## Remaining deployment evidence

The GitHub `security-tools` job will reproduce JSON/SARIF Semgrep, project pip-audit, offline
Promptfoo validation, and isolated passive ZAP artifacts. Railway staging self-scan remains human- and
deployment-gated. No live target or Clerk domain was scanned in this evidence pass.
