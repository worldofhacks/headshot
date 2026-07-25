# Security-evidence talking points (read aloud, ~1 page)

Presenter script for the MVP. Every claim here is backed by a file or a verified local run. Paths
are relative to the repo root.

---

## 1. Six pinned security tools in CI, all green on their own code

"We run **six pinned security tools** in CI. They are deterministic and offline, and on their last
recorded pass every one returned **zero findings against our own code and dependencies**.

> **Two corrections before this is said out loud (2026-07-25).**
> **(a) Not "on both remotes".** `CLAUDE.md` and `AGENTS.md` at this base make GitHub Actions the sole
> CI gate and GitLab a passive exact mirror with project CI/CD disabled. Say "in GitHub Actions CI",
> and if asked about the dual-remote law, say the push law holds but only one CI system gates.
> **(b) Not "zero findings" unqualified.** ZAP recorded 4 alerts on the fixture host and 3 on the live
> target. "Zero findings" is true only of the SAST/dependency/secret tools over our own code.

- **Semgrep 1.170.0** (SAST on our own code) — 0 findings *on its last recorded pass; that artifact is not committed, so the result is not verifiable from the repo — offer to re-run it.* *(Say "zero findings," not a file count:
  our ATO evidence records both 111 and 112 files and two different artifact hashes for the same
  pass, so the count is disputed until it is re-run. Don't quote a number you can't back.)*
- **pip-audit 2.10.1** — 0 known Python vulnerabilities.
- **npm audit** in `console/` — 0 vulnerabilities at every level.
- **gitleaks 8.30.1** — 0 secret leaks across the history it covered. *(That pass covered 73
  revisions; history is now 205, so it needs a re-run before release.)*
- **Promptfoo 0.121.19** — offline config valid, 1/1 prompt-injection eval PASS, no model call.
- **OWASP ZAP 2.17.0** (pinned by image digest) — **two distinct baselines, and the difference
  matters:** a CI passive baseline against an isolated internal-network fake target (4 expected
  header alerts on the fixture host — a fixture is never evidence about a real system), **and** a
  separately authorized passive baseline against the real Co-Pilot target, whose native report is
  committed and hash-verified at `docs/evidence/zap/zap-target.json` — 3 alerts, all
  publication-blocked.

*Do not say "none on any real target."* A real authorized target was passively scanned and the
artifact is in the repository. Say instead: "no **active** scan has been authorized or run against
any origin."

Show on screen: the `security-tools` job in **`.github/workflows/ci.yml`** and the matching
`security-tools` job in **`.gitlab-ci.yml`**. A contract test —
**`tests/deployment/test_ci_contract.py`** — fails the build if *either* CI system drops a
scanner or changes a pinned version (`test_github_ci_runs_every_pinned_security_scanner`,
`test_gitlab_ci_runs_every_pinned_security_scanner`, `test_both_ci_systems_pin_the_same_security_tool_versions`).
So the tooling can't silently rot on one remote."

**Do not point at `tmp/sec/`.** That directory does not exist at this base and no `tmp/` path is
tracked by git, so those SHA-256 sums cannot be verified from the repository — see the corrections at
the top of `docs/evidence/ato/SECURITY_TOOL_EVIDENCE.md`. Point instead at the two things that *are*
committed: the pinned CI job in `.github/workflows/ci.yml`, and
`docs/evidence/zap/zap-target.json` (the one raw scanner artifact in the repo, hash-verified).

---

## 2. OWASP coverage — every mandated category, union-guarded

"Our attack corpus is **9 hand-authored seeds, 3 categories × 3** — data exfiltration, prompt
injection, tool misuse — all mapped to the **OpenEMR Clinical Co-Pilot**. Every mandated OWASP
category is seeded:

- **OWASP Web 2021 mandated set** `{A01, A03, A04, A06, A07, A09, A10}` — all carried.
- **OWASP LLM 2025 mandated set** `{LLM01, LLM02, LLM03, LLM05, LLM06}` — all carried.

And this isn't a static claim — it's **guarded by a test**. `_REQUIRED_WEB` / `_REQUIRED_LLM`
live in `src/agentforge/api/postgres.py:124-126`, and
`tests/evals/test_validation.py::test_repository_corpus_union_covers_every_mandated_owasp_category`
imports those exact sets and asserts the corpus union covers them. Six categories have a **single
carrier seed**, so deleting or retagging that seed turns the test red. Every case is tagged
**boundary, invariant, or regression** — 3 invariants, 6 boundaries — never happy-path only."

Show on screen: **`docs/evidence/OWASP_COVERAGE_MATRIX.md`** (Tables A/B/C) and the union test.

---

## 3. The 10+-finding triage exercise (clearly simulated)

"We also ran the mandated multi-finding triage exercise. **`docs/triage/SIMULATED_SCAN_TRIAGE.md`**
walks **12 simulated findings** across every severity, all five disposition paths
(validate / remediate / defer / document / false_positive) and two justified false positives. It
is **reproducible** — run:

```
python -m agentforge.security_tools.triage_cli tests/fixtures/security_tools/simulated_scan.json
```

I ran that just now; it re-renders the exact table byte-for-byte and exits 0. The header of both
the doc and the output says **SIMULATED SCAN — synthetic fixture data, never real target
evidence** (`evidence_provenance=simulated`)."

---

## 4. Scanner output is evidence, not publication authority

"Critically: **a scanner never publishes and never renders a verdict.** Every normalized finding
is stamped `human_publication_state = "blocked_pending_human_approval"`
(`src/agentforge/security_tools/normalization.py:127`), carried as `source_kind="security_tool"`
with `evidence_provenance="scan_only"` (or `"simulated"`). The persistence layer **refuses** any
scanner finding that does not already carry that block
(`src/agentforge/security_tools/repository.py:79-85`), and simulated / scan-only rows are excluded from
campaign coverage. The independent Judge — not the scanner — issues verdicts, and findings stay
**human-gated** before publication. Garak and PyRIT have bounded native offline slices with committed bundles;
**Giskard's adapter is integrated but contributes zero candidates** — there is no
`giskard.bundle.json` in `security-tools/reviewed/`, so do not present it as evidenced. Total
tool-generated candidates ever imported: **5** (1 garak, 3 PyRIT, 1 Promptfoo, 0 Giskard). Multi-turn orchestrators and every tool-to-target path remain
adapter-only and are not claimed as live runs.
Commercial platforms (Burp, Lakera, HiddenLayer, Robust Intelligence) are **evaluated and
rejected** in ADR-0001."

---

## 5. Tool subprocess hardening

"When we do execute a tool, it runs through one hardened path —
**`src/agentforge/security_tools/process.py`**, `run_bounded_tool`:

- **Argument arrays, no shell** — `subprocess.Popen(list(argv), ..., shell=False)`, and empty /
  non-string argv is rejected (`process.py:64-65,84-94`).
- **Pinned versions** — every scanner is version-pinned in GitHub CI; `test_ci_contract.py` also
  statically guards command parity with the checked-in GitLab mirror configuration, which is not run.
- **Isolated tmp / HOME** — a fresh `TemporaryDirectory`; `HOME` and `TMPDIR` point there, never
  the caller's (`process.py:74-83`).
- **Bounded resources** — CPU seconds, address space, file size, descriptor count (64), wall-clock
  timeout, and captured-output cap, via `setrlimit` in a `preexec_fn` and a communicate timeout
  (`process.py:29-45,95-102`).
- **Env allowlist** — only `{LANG, LC_ALL, NO_COLOR, PATH, PYTHONPATH}` cross the boundary; any
  other key raises before launch, so no credentials leak into a scanner
  (`process.py:13,69-72`); `stdin` is `DEVNULL` and the child gets a new session.
- **Sanitized logs & typed errors** — gitleaks runs `--redact`; failures surface as a typed
  `ToolProcessError('timeout' | 'output_limit', ...)` rather than an opaque crash
  (`process.py:16-19,97-102`)."

---

### One-line close

"Six green pinned scanners in GitHub Actions CI, contract-tested against the checked-in mirror
configuration so they cannot be dropped; every
mandated OWASP Web and LLM category seeded and union-guarded by a test; a reproducible simulated
triage exercise; and a hard rule enforced in code that scanner output is evidence, never
publication authority — findings stay human-gated."
