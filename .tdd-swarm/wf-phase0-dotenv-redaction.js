export const meta = {
  name: 'phase0-dotenv-redaction',
  description: 'Env-isolate Settings.from_env dotenv loading + add a redacted Secret type (defense-in-depth) before M2, via TDD + independent reviewer + security',
  phases: [
    { title: 'Tests', detail: 'RED: dotenv env-isolation (8 cases) + secret redaction' },
    { title: 'Implement', detail: 'GREEN: config.py from_env + secrets.py' },
    { title: 'Review', detail: 'independent reviewer ∥ security, adversarial' },
  ],
}

const REPO = '/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine'

const SPEC = `
REPO: ${REPO}   BRANCH: ticket/dotenv-isolation-redaction (already checked out)
PACKAGE: src-layout, package = agentforge (pytest pythonpath=["src"]). Python 3.12.
Activate the venv for every command: \`cd "${REPO}" && . .venv/bin/activate && <cmd>\`.
Ruff config in ruff.toml (line-length 100, select E,F,I,UP,B,SIM). Run \`ruff check .\` and \`ruff format --check .\`.

WHAT THIS CHANGE DOES (two things, one ticket):

(1) ENV-ISOLATED DOTENV LOADING in src/agentforge/config.py — Settings.from_env().
   The current code loads .env.local/.env on EVERY from_env() regardless of environment,
   which means staging/production would read a stray dotenv file, and a dotenv file
   containing AGENTFORGE_ENVIRONMENT=production could promote a local process. Both are
   security defects. Correct behavior REQUIRED:
     - Read AGENTFORGE_ENVIRONMENT from the REAL process environment FIRST (os.environ),
       defaulting to "local".
     - VALIDATE that value BEFORE loading any file (unknown value raises ValueError and
       loads NOTHING).
     - Load .env.local and .env ONLY when the process-level environment == "local".
       staging and production skip dotenv loading ENTIRELY.
     - A dotenv file's AGENTFORGE_ENVIRONMENT must NEVER change the deployment environment
       (a file cannot elevate local -> staging/production). The deployment environment is
       decided by the process env alone.
     - Precedence for every OTHER variable in local mode: process env > .env.local > .env > defaults.
     - Missing files are a safe no-op.
   INTENDED IMPLEMENTATION (follow this design; it is correct and passes the cases):
     from_env(): environment = os.environ.get(_ENVIRONMENT_ENV_VAR, "local");
                 validate environment against _ALLOWED_ENVIRONMENTS BEFORE loading (raise
                 ValueError if unknown); if environment == "local": cls._load_local_dotenv();
                 return cls(environment=environment).
     _load_local_dotenv(): lazy \`from dotenv import dotenv_values\` (ImportError -> return).
                 Build merged dict by reading dotenv_values(".env") then dotenv_values(".env.local")
                 so .env.local overrides .env (skip None values). Then merged.pop(AGENTFORGE_ENVIRONMENT
                 key, None) so a FILE can NEVER set the deployment environment. Then for each
                 remaining key,value: os.environ.setdefault(key, value)  (process env WINS).
   Keep __post_init__ validation (defense in depth for direct construction). Do NOT weaken
   the O1 resolve_target_credential invariant or _TARGET_ID_RE; leave them intact.

(2) A REDACTED SECRET TYPE in a NEW module src/agentforge/secrets.py — defense-in-depth so
   secrets are represented as redacted types and never leak through repr/str/logs/errors/traces.
   Framework-neutral (stdlib only). Provide:
     - class Secret: wraps a raw string value. __repr__, __str__, __format__(spec) ALL return a
       fixed redaction marker (e.g. "Secret(***REDACTED***)" for repr, "***REDACTED***" for str/format)
       and NEVER the raw value — so f-strings, %-format, str(), repr(), and logging all redact.
       .reveal() -> str returns the raw value (this is the ONLY way to get it — used solely by the
       component authorized to make the call, at the call boundary). __eq__ compares wrapped values
       without exposing them; define __hash__ consistently; __bool__ reflects truthiness of the value.
       Guard against accidental leakage: do not put the raw value in any dunder that stringifies.
     - redact_mapping(data: Mapping) -> dict: returns a copy where (a) any value that is a Secret
       is replaced by its redaction marker, and (b) any key whose lowercased name contains a sensitive
       hint (key, token, secret, password, cookie, credential, authorization, api_key) has its value
       masked. Use this before logging any settings/config mapping — "never log a complete config object".
     - looks_like_provider_key(s: str) -> bool: SECONDARY control only. Detects known provider key
       prefixes (sk-, sk-or-, sk-ant-, sk-proj-, and a Together-style hex heuristic). Document in a
       comment that prefix matching is a backstop, NOT the primary control — the redaction tests /
       Secret type are the primary control. Do not raise from it.
   NOTE: today Settings holds NO secret fields (only environment), so there is nothing to redact in
   Settings itself yet — this module is the FOUNDATION that M4/M8/M9 will use to hold provider/target
   credentials as Secret values and to redact structured logs. Keep it small and dependency-free.

CONSTRAINTS (all agents):
- Secrets NEVER printed/logged/inlined. Tests use FAKE sentinel values only (e.g. "sk-FAKE-not-real-000",
  "sentinel-shh-123") — never any real-looking captured key.
- Do NOT read, print, cat, or enumerate .env.local or os.environ dumps. Do NOT weaken .gitignore.
- Framework-neutral: config.py and secrets.py import NO web framework and NO secret manager; dotenv is
  imported LAZILY inside _load_local_dotenv only (a bare \`import agentforge.config\` must not need dotenv).
`

// ---- Stage 1: Test Agent (owns tests; freezes them) ---------------------------------
phase('Tests')
const TEST_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    test_files: { type: 'array', items: { type: 'string' } },
    deleted_files: { type: 'array', items: { type: 'string' } },
    dotenv_case_count: { type: 'integer' },
    redaction_case_count: { type: 'integer' },
    red_confirmed: { type: 'boolean' },
    red_evidence: { type: 'string' },
    notes: { type: 'string' },
  },
  required: ['test_files', 'dotenv_case_count', 'redaction_case_count', 'red_confirmed', 'red_evidence'],
}
const testResult = await agent(
  `You are the TEST AGENT. Write failing (RED) tests ONLY — do NOT write or edit any src/ code.
${SPEC}

TASK:
- REPLACE the stale tests/test_config_dotenv.py: DELETE it (its assertions encode the OLD, wrong behavior
  where a .env.local could set environment=production) and create tests/test_config_env_isolation.py with
  these EXACT dotenv cases (use tmp_path + monkeypatch.chdir + monkeypatch.delenv/setenv; never touch the
  real repo .env files):
    1. local mode loads .env and .env.local (a probe var from each file resolves via os.environ afterward).
    2. a real process env var overrides BOTH files (setenv PROBE=proc; files set PROBE=file; expect proc).
    3. .env.local overrides .env for a shared probe var.
    4. staging ignores both files: setenv AGENTFORGE_ENVIRONMENT=staging; files present with a probe;
       probe is ABSENT from os.environ after from_env(); environment == "staging".
    5. production ignores both files (same as 4 with production).
    6. a dotenv file CANNOT elevate the environment: process env has NO AGENTFORGE_ENVIRONMENT (delenv);
       .env.local sets AGENTFORGE_ENVIRONMENT=production; from_env().environment == "local" (default), and
       os.environ AGENTFORGE_ENVIRONMENT is not left set to production by the file.
    7. a sentinel secret in a dotenv file is ABSENT from staging AND production: setenv staging (then a
       second sub-case production); .env.local has SECRET_SENTINEL=<fake>; assert os.environ has no SECRET_SENTINEL.
    8. missing files are a safe no-op: chdir to an empty tmp dir, setenv local, from_env() works, no raise.
  Also add a case asserting from_env raises ValueError for an unknown AGENTFORGE_ENVIRONMENT (e.g. "prod")
  and that NO file was loaded for it (a probe var stays absent).
- Create tests/test_secrets_redaction.py for the Secret type + helpers, using FAKE sentinels:
    * repr(Secret(s)), str(Secret(s)), format(Secret(s)), f"{Secret(s)}", and "%s" % Secret(s) all EXCLUDE
      the raw sentinel and show the redaction marker.
    * Secret(s).reveal() == s (call boundary returns the raw value).
    * two Secrets with equal values are ==, unequal values are !=; hash is consistent for equal values.
    * redact_mapping masks a Secret value AND a plain str under a sensitive-looking key (e.g. "api_key",
      "OPENROUTER_API_KEY", "session_cookie"), while leaving a non-sensitive key (e.g. "environment") intact.
    * looks_like_provider_key returns True for fake "sk-..."/"sk-or-..."/"sk-ant-..." sentinels and False for
      an ordinary string.
- Run \`. .venv/bin/activate && python -m pytest tests/test_config_env_isolation.py tests/test_secrets_redaction.py -q\`
  and CONFIRM RED (import errors for agentforge.secrets and/or assertion failures are expected — the impl doesn't exist yet).
- Run \`ruff format tests/test_config_env_isolation.py tests/test_secrets_redaction.py\` and \`ruff check tests/...\`
  so the frozen tests are lint-clean.
- Do NOT modify any file under src/. Do NOT modify pyproject.toml, ruff.toml, or .env.example.
Return the structured result.`,
  { label: 'test:dotenv+redaction', phase: 'Tests', schema: TEST_SCHEMA },
)

// ---- Stage 2: Impl Agent (src only; cannot edit tests) ------------------------------
phase('Implement')
const IMPL_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    impl_files: { type: 'array', items: { type: 'string' } },
    tests_untouched: { type: 'boolean' },
    ruff_clean: { type: 'boolean' },
    pytest_summary: { type: 'string' },
    green_confirmed: { type: 'boolean' },
    design_notes: { type: 'string' },
  },
  required: ['impl_files', 'tests_untouched', 'ruff_clean', 'pytest_summary', 'green_confirmed'],
}
const implResult = await agent(
  `You are the IMPLEMENTATION AGENT. Make the frozen RED tests GREEN by editing ONLY src/ files.
${SPEC}

The TEST AGENT has written and frozen tests/test_config_env_isolation.py and tests/test_secrets_redaction.py.
You MUST NOT create, edit, delete, or reformat ANY file under tests/. If a test looks wrong, STOP and say so
in design_notes rather than editing it.

TASK:
- Edit src/agentforge/config.py: rewrite Settings.from_env() and replace _load_dotenv with _load_local_dotenv
  per the INTENDED IMPLEMENTATION in the spec (process-env-first, validate-before-load, local-only loading,
  dotenv_values merge with .env.local over .env, pop AGENTFORGE_ENVIRONMENT so a file can't elevate,
  os.environ.setdefault so process env wins). Update the from_env/_load docstrings to describe the new
  isolation precisely. Keep resolve_target_credential + _TARGET_ID_RE + __post_init__ intact.
- Create src/agentforge/secrets.py with Secret, redact_mapping, looks_like_provider_key per the spec.
- Run the FULL suite: \`. .venv/bin/activate && python -m pytest -q\`. ALL tests must pass (the pre-existing
  M1a suite too). Run \`ruff check .\` and \`ruff format --check .\` — both clean.
- Verify you touched NO tests/ file: \`git status --porcelain tests/\` must be empty. Report tests_untouched.
Return the structured result with the exact pytest summary line (e.g. "NN passed, M skipped").`,
  { label: 'impl:dotenv+redaction', phase: 'Implement', schema: IMPL_SCHEMA },
)

// ---- Stage 3: independent Reviewer ∥ Security (adversarial) -------------------------
phase('Review')
const REVIEW_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    verdict: { type: 'string', enum: ['approve', 'changes_requested'] },
    findings: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        properties: {
          severity: { type: 'string', enum: ['critical', 'important', 'minor'] },
          location: { type: 'string' },
          problem: { type: 'string' },
          fix: { type: 'string' },
        },
        required: ['severity', 'location', 'problem', 'fix'],
      },
    },
    summary: { type: 'string' },
  },
  required: ['verdict', 'findings', 'summary'],
}
const [review, security] = await parallel([
  () => agent(
    `You are an independent CODE REVIEWER. Review the uncommitted diff on branch ticket/dotenv-isolation-redaction
in ${REPO} (\`cd "${REPO}" && git --no-pager diff\` and read src/agentforge/config.py + src/agentforge/secrets.py
+ the two new test files). Judge correctness, clarity, and whether the tests genuinely prove the env-isolation
behavior (not tautologies). Confirm the dotenv precedence (process > .env.local > .env > defaults), that a file
cannot elevate the environment, and that staging/production skip loading. Flag any test that would pass even if
the isolation were broken. Report only real issues with confidence. ${SPEC}`,
    { label: 'review:reviewer', phase: 'Review', schema: REVIEW_SCHEMA },
  ),
  () => agent(
    `You are an independent SECURITY REVIEWER. Adversarially audit the uncommitted diff on branch
ticket/dotenv-isolation-redaction in ${REPO}. Threat-model the change:
  - Can a dotenv file on a staging/production box be read or influence config? (must be NO)
  - Can a dotenv file promote a local process to staging/production via AGENTFORGE_ENVIRONMENT? (must be NO)
  - Does the Secret type leak the raw value through ANY path: __repr__, __str__, __format__, f-string,
    %-format, exception messages, logging.debug of a dict containing it, or json? Try to construct a leak.
  - Does redact_mapping miss any sensitive key or fail to mask a Secret nested in a dict?
  - Are there real secrets anywhere in the tests (there must be ONLY fake sentinels)?
  - Is dotenv still imported lazily (a bare import agentforge.config must not require dotenv)?
Report concrete leak vectors with a severity and a fix. Do NOT print .env.local or os.environ. ${SPEC}`,
    { label: 'review:security', phase: 'Review', schema: REVIEW_SCHEMA },
  ),
])

return {
  test: testResult,
  impl: implResult,
  review,
  security,
}
