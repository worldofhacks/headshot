# WP-13F — Deepen static analysis and ingest CI security evidence

**Branch:** `rtg/wp13f-static-ci-tools`

**Model:** capable

**Depends on:** WP-09, WP-13E

**Implements toward (live validation pending):** Semgrep and CI-tool portion of RT-05

Read existing Semgrep rules/process wrappers, `scripts/check.sh`, pip-audit/npm-audit/
Gitleaks execution, both CI configurations, WP-09 status semantics, and RT-05.

**Implementation writes only**

- `security-tools/semgrep/**`
- `security-tools/toolchain.lock.json`
- `src/agentforge/security_tools/semgrep.py`
- `src/agentforge/security_tools/adapters/semgrep.py`
- `src/agentforge/security_tools/adapters/ci_security.py`
- `src/agentforge/security_tools/catalog.py`
- `src/agentforge/evidence/status.py`
- `src/agentforge/contracts/v1/static_security_artifact.json`
- `scripts/run_static_security_tools.sh`
- `scripts/check.sh`
- `.github/workflows/ci.yml`
- `.gitlab-ci.yml`
- `docs/security/STATIC_SECURITY_TOOLCHAIN.md`

**Test writes only**

- `tests/security_tools/test_semgrep_depth.py`
- `tests/security_tools/test_ci_security_artifacts.py`
- `tests/vectors/security_tools/static_ci/**`

## Required result

Pin and validate an offline Semgrep profile that retains existing rules and adds reviewed,
framework-aware/taint coverage for FastAPI and React authorization boundaries, SSRF and
URL-to-client flows, secret/log sinks, dangerous HTML/Markdown rendering, SQL construction,
subprocess/shell use, unsafe deserialization, path traversal, and security-control bypass.
Every rule has positive, negative, sanitizer, source, and sink test vectors; noisy or
unsupported rules are disabled with a reviewed rationale, never silently counted.
These rule vectors validate configuration only and cannot establish that the tool executed
on the release.

Normalize current Semgrep, pip-audit, npm-audit, and Gitleaks outputs into immutable,
content-addressed advisory artifacts. Bind tool/version, configuration/rule/lockfile hash,
commit, CI provider/job, timestamps, exit semantics, target classification, artifact hash,
and attestation/signature state. Redact secrets and hostile snippets before platform
ingestion. A missing, skipped, stale, unsigned, truncated, parse-failed, or tool-error
artifact cannot become “passed.”

Keep GitHub and GitLab commands, versions, policies, and artifact retention equivalent.
Use only already pinned/local tools; no package installation, registry lookup, rule
download, network, target, or provider call. Scanner output cannot authorize traffic,
become a Judge verdict, close LLM behavioral coverage, publish, or remediate.

Tests cover taint paths and sanitizers, rule/config drift, SARIF/JSON parser bombs, path/
symlink escape, duplicate precedence, malicious snippets, secret redaction, partial/
skipped/error status, forged CI metadata, GitHub/GitLab parity, deterministic hashes, and
installed-wheel schema lookup. WP-19B owns final schema registry compatibility.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_semgrep_depth.py tests/security_tools/test_ci_security_artifacts.py tests/test_evidence_status.py -q
bash scripts/run_static_security_tools.sh --offline --check-config
python scripts/check_evidence_status.py --check
```

If a pinned local tool is unavailable, validate test vectors/configuration and report its
execution evidence blocked; never download it.

A `VERIFIED_RELEASE_CONTROL` static/CI status requires fresh genuine GitHub and GitLab job
artifacts for the exact deployed SHA, exact pinned binaries/configuration, complete outputs,
and verified attestations. WP-21B reconciles those release-control facts; local test vectors
never substitute. This status never establishes target behavior or LLM/Web coverage.

**Handoff:** WP-20C displays each tool stage independently; WP-22 verifies approved fresh
artifacts without equating static/CI success to live LLM safety.
