# T-F00 Independent Code Review

Status: DONE

Overall verdict: **CHANGES_REQUIRED** (Critical: 0, Important: 7, Minor: 2)

## Review basis

- Ticket: `tickets/T-F00.md`
- Frozen-test commit: `87b472ffe0f83f615f8a32a32b1687f951fc3cf7`
- Implementation commit: `3e1c3700740345a477f4033fd757f82590faf7f9`
- Exact reviewed implementation diff:
  `87b472ffe0f83f615f8a32a32b1687f951fc3cf7..3e1c3700740345a477f4033fd757f82590faf7f9`
  restricted to the five ticket file scopes.
- The exact diff changes only the five declared implementation files; it does not
  change the frozen tests.
- Reviewed the frozen tests, final test-design review, implementation report, and
  retained gate report. The orchestrator independently reports the full wrapper
  green with 1018 passed / 3 skipped and Ruff, secret, spec, and import gates green.
  This review did not rerun the write-producing wrapper because this role may write
  only this report.

## SPEC COMPLIANCE verdict

**CHANGES_REQUIRED**

| Criterion / DoD | Verdict | Evidence |
|---|---|---|
| AC-1 — mechanical AC/test mapping | CHANGES_REQUIRED | The current frozen cases pass, but `spec-lint.sh` can approve mappings supplied by functions pytest never collects and does not use the supplied diff base to identify new tests (I-2). |
| AC-2 — reject package-layer cycles | CHANGES_REQUIRED | The frozen root-package fixture passes, but common nested-package and package-initializer imports are omitted from the graph, allowing real cycles to pass (I-3). |
| AC-3 — executable baseline or owner-approved waiver | CHANGES_REQUIRED | Executable-policy validation is substantially present, but the committed waiver names only a generic role rather than recording a verifiable owner approval (I-7). Coverage semantic failures are also misreported (I-5). |
| AC-4 — continue and report after mapped failures | PARTIAL | The loop continues after an ordinary mapped command failure and preserves bounded command output. The platform gate map nevertheless omits required Tier-1 gates (I-1), and coverage validation failures can leave a zero-exit report row (I-5). |
| AC-5 — hash-bound green report | CHANGES_REQUIRED | Required labels and the two requested hashes are emitted, but `head` is not bound to the tested worktree bytes and base ancestry/head stability are not verified (I-4). |
| DoD — reviewed RED tests frozen | PASS | `.tdd-swarm/reports/T-F00-test-review.md:5-16`; the implementation diff contains no test file. |
| DoD — named wrapper green, hashes retained | PASS WITH CONCERN | `.tdd-swarm/reports/T-F00-gates.md:3-21` contains the successful retained run and hashes, but I-4/I-5 limit its evidentiary strength. |
| DoD — no Critical/Important code/security findings | FAIL | This code review has seven Important findings. |

## CODE QUALITY verdict

**CHANGES_REQUIRED**

Positive observations: shell expansions used for paths and arguments are generally
quoted; source ticket/policy/tool symlinks are rejected; commit arguments are
hex-constrained before `git rev-parse`; Markdown tables are parsed fail-closed on
malformed rows; mapped commands use `shlex.split` plus `subprocess.Popen` without an
implicit shell or `eval`; and captured command bytes are bounded.

### Important findings

#### I-1 — Required Tier-1 gates are omitted rather than mechanically mapped or explicitly skipped

`.tdd-swarm/gates.md:8-13` maps only format, lint, unit, and secret scan. It omits
type checking, new-test execution, TODO/debug-marker checks, documentation checks,
and reachability from the Tier-1 contract at
`.claude/skills/tdd-swarm/references/quality-gates.md:11-23`. The contract also says
an unrunnable gate must be listed as skipped with a reason
(`quality-gates.md:42-46`), while `.tdd-swarm/run-local-gates.sh:231-234` silently
discards every non-`AVAILABLE` row. The generic CI/release note at
`.tdd-swarm/gates.md:15-17` neither names these local gates nor supplies per-gate
reasons.

Impact: the wrapper can report green while required local correctness checks were
never represented or run. This defeats the ticket's purpose as the bootstrap gate
for all later code tickets.

Required change: enumerate every Tier-1 gate with an executable command or an
explicit non-green skipped/blocked status and reason; make the wrapper retain every
declared row and fail or disclose non-runnable local gates according to the locked
posture.

#### I-2 — Spec mapping can be satisfied by a non-test and ignores the diff-base contract

`.tdd-swarm/spec-lint.sh:16-23` validates the diff-base commit, but the Python
checker receives only the ticket path at line 25 and never consults a Git diff.
Then `spec-lint.sh:111-133` walks every nested function whose name merely starts
with `test` and accepts its docstring tag without checking pytest collection or a
skip marker. A nested function, a method on a non-`Test*` class, or a skipped test
can therefore satisfy every AC while executing zero assertions. Conversely, the
implementation scans all legacy tests in a scope instead of the AC's “new test”
set and recognizes only function docstrings, despite the tdd-swarm contract
allowing a tag in a name or comment
(`.claude/skills/tdd-swarm/SKILL.md:102-108`).

Impact: a lazy or accidental non-collected mapping can pass AC-1 and the “new tests
present and execute” gate.

Required change: use the diff base to identify added test nodes, validate tags in
the supported locations, bind mappings to pytest-collected node ids, and reject
skipped/uncollected mappings.

#### I-3 — The import graph misses common nested-package and `__init__.py` cycles

`.tdd-swarm/check-import-cycles.py:20-21` names an initializer
`agentforge.sub.__init__` rather than the importable package `agentforge.sub`.
`check-import-cycles.py:45-54` expands imported aliases only when the parent is
exactly the root `agentforge` package. Thus `from agentforge.sub import b` and a
nested `from . import b` yield only `agentforge.sub`; because that package is not
present in the module set under its real name, `_target_module` at lines 57-65
returns no target. Edges through package initializers and ordinary nested relative
imports disappear before cycle detection.

Impact: AC-2 can return “acyclic” for real package-layer cycles. The frozen fixture
at `tests/swarm/test_import_cycles.py:32-47` exercises only root-level
`from agentforge import layer_*` and does not cover this false-negative class.

Required change: canonicalize every `__init__.py` to its package module, resolve
relative imports using package context, and expand `from <package> import <module>`
aliases whenever the alias resolves to a repository module. Add nested-package and
initializer-cycle regression cases through the Test Agent.

#### I-4 — Recorded base/head do not identify the worktree that was actually tested

`.tdd-swarm/run-local-gates.sh:32-37` proves only that both names resolve to commits.
It does not require the base to be an ancestor of head, reject relevant tracked
worktree changes, or re-check HEAD after commands finish. The report later prints
the early `head_sha` at lines 443-466, while the gate map, ticket, wrapper,
spec-linter, and frozen tests are not hashed. A dirty or command-mutated test file
can therefore be executed while the report claims an unchanged committed HEAD.

Impact: the report is not reproducible evidence for the labeled commit, and a
weakened dirty frozen test can produce an apparently commit-bound green report.

Required change: verify base ancestry; bind the relevant tested tree to HEAD (or
record and verify a complete dirty-state digest); hash the ticket, gate map, tools,
and declared test scopes; and re-check HEAD/worktree invariants after all commands
before atomically publishing the report.

#### I-5 — Coverage semantic failures can produce an all-zero report

The coverage command's process exit is stored at
`.tdd-swarm/run-local-gates.sh:349-357`. Malformed coverage output or a measured
regression changes only `overall_status` at lines 360-394; the diagnostic goes to
the wrapper's stderr and is not appended to the coverage output file. Line 395
then records the original process exit, commonly zero. The report also has no
overall verdict field.

Impact: the wrapper correctly exits nonzero, but its retained report can show a
zero-exit coverage row and all other rows green, losing the reason AC-3 failed.

Required change: model command execution and coverage-policy validation as separate
statuses (or make the coverage row nonzero), retain validation diagnostics, and
record the wrapper's overall PASS/FAIL result.

#### I-6 — Report publication follows symlinks and can overwrite an arbitrary file

Inputs are checked against leaf symlinks at
`.tdd-swarm/run-local-gates.sh:21-30`, but the output path is not. Lines 443-466
create/use `.tdd-swarm/reports` and redirect directly to
`${ticket_id}-gates.md`. A pre-existing symlink at either the directory or report
path is followed and its target is truncated.

Impact: running a local verification tool in an untrusted checkout can overwrite a
file outside the report directory. Interrupted redirection can also leave a
partial report.

Required change: resolve and verify the report directory remains inside the
repository, reject symlink components and a symlink destination, then write a
same-directory temporary regular file and atomically replace the intended report.

#### I-7 — The temporary coverage waiver does not record a verifiable owner approval

`tickets/T-F00.md` AC-3 and Out of Scope require an owner-approved
`non-applicable` decision. `.tdd-swarm/coverage-policy.md:3-7` is complete and
expires on 2026-07-31, and the stated absence of installed coverage tooling is
consistent with the implementation report. However, line 5 says only
`approver: T-F00 task owner`; it does not identify an approving person or point to
an approval record. A committed assertion authored by the implementation flow is
not independent owner approval.

Impact: coverage is skipped without auditable evidence that the owner accepted the
temporary exception.

Required change: record the actual owner identity and approval evidence, or leave
the decision blocked/open until the owner approves. Retain the short expiry and
prominent report disclosure.

### Minor findings

#### M-1 — Exact-limit output is incorrectly labeled truncated

`.tdd-swarm/run-local-gates.sh:292-300` appends the truncation marker whenever the
stored length equals 16 KiB, even when the process emitted exactly 16 KiB and no
additional byte. Track whether bytes beyond the limit were observed before adding
the marker.

#### M-2 — Report cells do not neutralize raw HTML/control content

`.tdd-swarm/run-local-gates.sh:305-313` escapes backslashes, pipes, backticks, and
line endings, but preserves raw HTML and other control characters from untrusted
command output. That output can alter or conceal rendered evidence even though it
cannot break the pipe-delimited source row directly. Encode `<`, `>`, `&`, and
non-printing controls, or emit output in a safely delimited/encoded attachment.

## Conclusion

The frozen suite and current repository run demonstrate the intended narrow paths,
and the shell command runner avoids implicit-shell injection while bounding stored
output. The implementation is not ready to become the trust root for later swarm
tickets because it can silently omit required gates, approve non-executing test
mappings, miss common Python package cycles, and issue reports whose commit and
status claims are not fully bound to the tested state.
