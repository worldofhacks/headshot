export const meta = {
  name: 'packaging-schemas',
  description: 'Step 4: package the contract + eval-authoring schemas into the wheel (single authoritative copy each) and resolve them via importlib.resources, so corpus validation works OUTSIDE a repo checkout. TDD + reviewer + security.',
  phases: [
    { title: 'Tests', detail: 'RED: importlib.resources resolution + wheel-outside-repo validation' },
    { title: 'Implement', detail: 'GREEN: relocate schemas into package + resolvers + package-data + CI' },
    { title: 'Review', detail: 'reviewer ∥ security' },
  ],
}

const REPO = '/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine'
const SPEC = `
REPO (main repo): ${REPO}   BRANCH: ticket/packaging-schemas (off swarm/mvp-live-gate; has M2/M4/M6a/M9 + the
cherry-picked M11 corpus). venv at ${REPO}/.venv — activate for EVERY command:
  \`cd "${REPO}" && . .venv/bin/activate && <cmd>\`. Python 3.12; Postgres 16 UP. DO NOT git commit/push
(the orchestrator integrates). Gates: \`ruff check .\`, \`ruff format --check .\`, \`python -m pytest -q\`.

PROBLEM (the Codex handoff identified it): both authoritative schema sets are resolved by REPO-RELATIVE path,
so a wheel install OUTSIDE a repo checkout cannot find them:
- src/agentforge/contracts/registry.py: contracts_dir() = Path(__file__).parents[3] / 'contracts' / 'v1'.
- src/agentforge/evals/validation.py: _REPO_ROOT = Path(__file__).parents[3]; _SCHEMA_DIR = _REPO_ROOT/'evals'/'schemas'.
Neither contracts/v1 (7 files) nor evals/schemas (3 files) is under a package, so neither is wheel-packaged.

GOAL: package both schema sets into the wheel, resolve via importlib.resources, keep EXACTLY ONE authoritative
copy of each (no dual copy that can drift), and prove corpus validation works with NO repo checkout on disk.

DESIGN (build to this):
1. RELOCATE (single authoritative copy — MOVE, do not copy):
   - contracts/v1/*.json  ->  src/agentforge/contracts/v1/*.json   (7 files; delete the repo-root contracts/v1)
   - evals/schemas/*.json ->  src/agentforge/evals/schemas/*.json  (3 files; delete the repo-root evals/schemas)
   Use plain filesystem moves; the orchestrator will git-commit (git detects the renames). Do NOT leave a
   second copy at the repo root.
2. registry.py — resolve via importlib.resources, PRESERVING the AGENTFORGE_CONTRACTS_DIR override:
     override = os.environ.get('AGENTFORGE_CONTRACTS_DIR'); if override -> read (Path(override)/f'{name}.json').read_text()
     else -> importlib.resources.files('agentforge.contracts').joinpath('v1', f'{name}.json').read_text()
   Read the schema TEXT via the Traversable's .read_text() (works zipped or unzipped); json.loads it. Keep the
   public API (SUCCESS_SCHEMAS, load_schema, validator_for, validate, is_valid, and — if you keep contracts_dir()
   for the override case — make it clearly the override-only path). The contract tests (tests/contract) use the
   registry, so they MUST stay green transparently.
3. validation.py — replace _REPO_ROOT/_SCHEMA_DIR with importlib.resources:
     files('agentforge.evals').joinpath('schemas', schema_name).read_text()  (json.loads it). No parents[3].
4. pyproject.toml [tool.setuptools.package-data] — add (keep the existing storage/observability *.sql entries):
     "agentforge.contracts" = ["v1/*.json"]
     "agentforge.evals" = ["schemas/*.json"]
   Ensure setuptools.packages.find still discovers the packages (they already are agentforge subpackages).
5. Update the now-stale doc comments that say the schemas live at the repo root (registry.py docstring,
   contracts/__init__.py, validation.py header) to say they are packaged and importlib.resources-resolved.
6. CI (.github/workflows/ci.yml) — ADD (preserving every existing step/job — test + secret-scan):
   - a wheel-package step: build the wheel, install it into a FRESH venv in a temp dir OUTSIDE the repo, then
     run \`python -m agentforge.evals validate-corpus <corpus>\` and \`detect-duplicate-sequence\` against the
     corpus copied into that temp dir — proving schema resolution needs no repo checkout.
   - a container validation smoke step: after \`docker build\`, \`docker run\` the image to validate a corpus
     (or invoke the validator) — proving the schemas ship in the image. Keep it lightweight + deterministic.

FILE SCOPE (impl): src/agentforge/contracts/ (registry.py + the relocated v1/*.json), src/agentforge/evals/
(validation.py + the relocated schemas/*.json), pyproject.toml, .github/workflows/ci.yml, and a small
scripts/ helper if the CI steps need one. Do NOT change any inter-agent schema CONTENT (byte-for-byte move
only), any src/agentforge/{policy,observability,agents,storage} code, or the corpus DATA (evals/seeds,
evals/ground-truth, evals/fixtures, evals/results stay at the repo root — they are input data, passed by path).

FILE SCOPE (tests, Test Agent owns): tests/test_packaging.py (NEW). Do NOT edit existing tests except where a
test hard-codes a repo-relative schema path that the move breaks (if any exists, fix ONLY that path — the
contract tests should NOT need changes since they use the registry).

TESTS (Test Agent writes first, RED):
- resolution test: with the process CWD changed to a temp dir (monkeypatch.chdir) and AGENTFORGE_CONTRACTS_DIR
  unset, registry.is_valid('verdict', <valid>) and validation schema loading STILL work — proving resolution is
  package-based, not CWD/repo-relative.
- wheel-outside-repo test: build the wheel (\`pip wheel . --no-deps -w <tmp>\`), create a fresh venv in a temp
  dir, install ONLY the wheel (+ jsonschema), copy the corpus (evals/seeds+ground-truth+fixtures+schemas? NO —
  schemas are in the wheel; copy only the DATA) into the temp dir, and run the installed console
  \`python -m agentforge.evals validate-corpus <tmp>/corpus\` from a CWD OUTSIDE the repo — assert exit 0 and a
  'valid corpus' result. This is the definitive proof; mark it slow if needed but it MUST run in CI.
- (container smoke may be a CI step rather than a pytest test — coordinate with the Impl agent.)

CONSTRAINTS: exactly ONE authoritative copy of each schema set (the packaged one). No secret/PHI. No network.
The AGENTFORGE_CONTRACTS_DIR override must still work. Full suite + contract tests stay green.
`

phase('Tests')
const TEST_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  test_files: { type: 'array', items: { type: 'string' } }, red_confirmed: { type: 'boolean' },
  red_evidence: { type: 'string' }, notes: { type: 'string' } }, required: ['test_files', 'red_confirmed', 'red_evidence'] }
const testResult = await agent(
  `You are the TEST AGENT for the packaging fix. Write failing (RED) tests ONLY in tests/test_packaging.py:
the importlib.resources resolution test (CWD-independent) and the wheel-build-install-OUTSIDE-repo corpus
validation test, per the SPEC. They are RED today because resolution is repo-relative + the schemas are not
packaged. Run \`. .venv/bin/activate && python -m pytest tests/test_packaging.py -q\` and CONFIRM RED. Make them
ruff-clean. Do NOT move files or edit src. Return the structured result.
${SPEC}`,
  { label: 'test:packaging', phase: 'Tests', schema: TEST_SCHEMA })

phase('Implement')
const IMPL_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  impl_files: { type: 'array', items: { type: 'string' } }, moved: { type: 'array', items: { type: 'string' } },
  single_copy_confirmed: { type: 'boolean' }, tests_untouched: { type: 'boolean' }, ruff_clean: { type: 'boolean' },
  pytest_summary: { type: 'string' }, green_confirmed: { type: 'boolean' }, wheel_outside_repo_proof: { type: 'string' },
  design_notes: { type: 'string' } }, required: ['impl_files', 'single_copy_confirmed', 'tests_untouched', 'ruff_clean', 'pytest_summary', 'green_confirmed', 'wheel_outside_repo_proof'] }
const implResult = await agent(
  `You are the IMPLEMENTATION AGENT for the packaging fix. Make the frozen RED tests GREEN per the DESIGN:
relocate both schema sets INTO the package (single authoritative copy; delete the repo-root originals), fix the
registry + validator resolvers to importlib.resources (preserve AGENTFORGE_CONTRACTS_DIR override), add the two
package-data lines, update stale doc comments, and add the CI wheel + container-smoke steps (preserving every
existing step). Do NOT edit tests/. Do NOT change schema CONTENT (byte-for-byte move). Do NOT touch policy/
observability/agents/storage code or the corpus DATA.
${SPEC}
Verify: (1) NO second copy of any schema remains at the repo root (\`ls contracts/v1 evals/schemas\` should not
exist). (2) \`python -m pytest -q\` FULL suite green incl. tests/contract (transparent via registry) and the new
packaging tests. (3) ruff clean. (4) build the wheel and confirm \`unzip -l\` shows agentforge/contracts/v1/*.json
+ agentforge/evals/schemas/*.json inside it. (5) \`git status --porcelain tests/\` shows no impl changes to tests.
Put the exact wheel-outside-repo validation transcript in wheel_outside_repo_proof. Return the structured result.`,
  { label: 'impl:packaging', phase: 'Implement', schema: IMPL_SCHEMA })

phase('Review')
const REVIEW_SCHEMA = { type: 'object', additionalProperties: false, properties: {
  verdict: { type: 'string', enum: ['approve', 'changes_requested'] },
  findings: { type: 'array', items: { type: 'object', additionalProperties: false, properties: {
    severity: { type: 'string', enum: ['critical', 'important', 'minor'] }, location: { type: 'string' },
    problem: { type: 'string' }, fix: { type: 'string' } }, required: ['severity', 'location', 'problem', 'fix'] } },
  summary: { type: 'string' } }, required: ['verdict', 'findings', 'summary'] }
const [review, security] = await parallel([
  () => agent(
    `Independent CODE REVIEWER for the packaging fix in ${REPO} (git --no-pager diff; read registry.py,
validation.py, pyproject.toml, ci.yml, tests/test_packaging.py). Verify: exactly ONE authoritative copy of each
schema set (packaged; repo-root copies removed — no dual copy that can drift); resolution is importlib.resources
(no parents[3]); AGENTFORGE_CONTRACTS_DIR override preserved; schema CONTENT unchanged (byte-for-byte move); the
wheel actually contains the JSON; the wheel-outside-repo test genuinely runs without a repo checkout; contract
tests + full suite stay green. Run the suite + build the wheel. Report real issues only. ${SPEC}`,
    { label: 'review:packaging', phase: 'Review', schema: REVIEW_SCHEMA }),
  () => agent(
    `Independent SECURITY REVIEWER for the packaging fix in ${REPO}. Audit: (a) does relocation preserve the
schema content exactly (a silent edit to a contract schema during the move would weaken a trust boundary — diff
old vs new bytes)? (b) can the AGENTFORGE_CONTRACTS_DIR override be abused to load an attacker-controlled schema
(document it is intended tooling override, not a runtime attack surface)? (c) any path-traversal in the new
importlib.resources joinpath (a schema 'name' with ../ must not escape the package)? (d) no secret/PHI/network
added; no target/provider access. Report concrete issues with severity + fix. Do NOT print .env.local. ${SPEC}`,
    { label: 'security:packaging', phase: 'Review', schema: REVIEW_SCHEMA }),
])

return { test: testResult, impl: implResult, review, security }
