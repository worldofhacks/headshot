# Security-tool ATO evidence

Evidence date: 2026-07-21 (America/New_York)

Branch: `codex/m1d-live-console-railway`

Artifact policy: hashes and sanitized summaries are retained here; temporary raw reports are not
committed.

## Status matrix

| Capability | Status | Evidence |
|---|---|---|
| Semgrep platform-source scan | **operational and evidenced** | Pinned `1.170.0`; JSON and SARIF completed with zero findings/errors across 111 tracked platform files |
| Promptfoo offline configuration | **operational and evidenced** | Pinned `0.121.19`; Node `v25.3.0`; `Configuration is valid.`; no model or hosted provider used |
| pip-audit project resolution | **operational and evidenced** | Pinned `2.10.1`; 38 resolved dependencies; zero known vulnerabilities |
| ZAP local fake passive baseline | **operational and evidenced** | Pinned `2.17.0` image digest; isolated internal network; 4 warnings normalized and human-blocked |
| ZAP Railway staging self-scan | **blocked pending authorization** | Exact deployed staging origin and deployment verification are not yet recorded |
| ZAP live-target scan | **blocked pending authorization** | Requires a separate persisted exact ZAP authorization; campaign approval is not sufficient |
| Garak v1 adapter seam | **adapter integrated, execution deferred** | Fixture parser, normalization, duplicate rejection, provenance and contract tests pass; no pinned invocation claimed |
| PyRIT v1 adapter seam | **adapter integrated, execution deferred** | Fixture parser, normalization, duplicate rejection, provenance and contract tests pass; never verdict authority |
| Giskard v1 adapter seam | **adapter integrated, execution deferred** | Fixture parser, normalization, duplicate rejection, provenance and contract tests pass; no pinned invocation claimed |
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
