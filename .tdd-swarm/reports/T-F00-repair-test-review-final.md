# T-F00 Repair Test-Design Final Re-review

Status: DONE

Verdict: **CHANGES_REQUIRED** (Critical: 0, Important: 5, Minor: 1)

## Review basis

- Ticket: `tickets/T-F00.md`
- Implementation under test: `3e1c3700740345a477f4033fd757f82590faf7f9`
- Frozen candidate: `93e62dc`
- Integrated test commits: `cc60235`, `32d7b69`, `0e46672`, `cd188de`,
  and `93e62dc`
- Prior reports: `T-F00-code-review.md`, `T-F00-security.md`, and
  `T-F00-repair-test-review.md`
- Exact diff reviewed: `3e1c370..93e62dc`, limited to the three declared test
  files

Focused verification:

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -p no:cacheprovider -vv \
  tests/swarm/test_spec_lint.py \
  tests/swarm/test_import_cycles.py \
  tests/swarm/test_gate_wrapper.py

59 collected; 44 failed; 15 passed; 0 errors
```

All RED results are assertion failures against the unchanged implementation;
there are no syntax, import, collection, or fixture-setup errors. Ruff and
`ruff format --check` both pass for all three files.

## Prior Important disposition

| Prior gap | Disposition |
|---|---|
| Contradictory/blocklist-passable command fixtures | PARTIAL — successful rows now use fixed vectors and changed argv is rejected, but ID-to-vector binding and adapter allowlisting remain unproved (I-1). |
| Actual pytest collection | PARTIAL — `collect_ignore`, module skip, and collection failure are strong, but a collected node dynamically marked skipped remains uncovered (I-2). |
| Unbounded noisy output | CLOSED — a continuously noisy process group must terminate before the test deadline and leave no descendant marker. |
| Independent known-format redaction | CLOSED — configured and non-environment AWS-format values are asserted separately. |
| Atomic/symlink filesystem behavior | PARTIAL — static symlinks and inode replacement are covered, but unlink/rewrite and validation/read races still pass (I-4). |
| Dummy evidence hashes | PARTIAL — exact digest values are now required, but only one declared test scope is exercised (I-3). |
| Self-attested external approval | CLOSED — detached signature, bad signature, allowlisted identity, policy hash, and commit binding are independently exercised. |
| Exact-limit and render-active output | CLOSED — exact/over-limit and HTML/ANSI/control cases were added. |

## Important findings

### I-1 — Fixed authority is not bound to the gate ID, and the coverage adapter is not allowlisted

`tests/swarm/test_gate_wrapper.py:588-666` rejects an arbitrary executable,
extra arguments on `secret-scan`, an unsanctioned `sh -c`, and the deprecated
`coverage-command` field. It never places a sanctioned vector under the wrong
gate ID. A global set of allowed command strings therefore passes even though
the required protected mapping is **gate ID → exact argv**; for example,
`lint | bash scripts/secret_scan.sh | AVAILABLE` remains admissible.

The coverage negative retains the valid `coverage-adapter: pytest-cov` and adds
an obsolete command field. A runner can reject only `coverage-command` while
treating any `coverage-adapter` value as an executable name. No test supplies an
unknown/malicious adapter and proves it was not run.

Required repairs:

1. Put a valid sanctioned command under a different valid gate ID and require
   rejection before execution.
2. Supply an unknown coverage adapter backed by a marker-writing executable and
   require rejection without the marker.
3. Keep the current mutated-argv cases; together these distinguish a pair-bound
   fixed map from a blocklist or global command set.

### I-2 — “Non-skipped” can still be implemented as source special-cases

The new collection cases at `tests/swarm/test_spec_lint.py:194-274` are valuable:
they force awareness of `collect_ignore`, a module-level skip, and a collection
failure. However, the only collected function-level skip is the syntactically
obvious `@pytest.mark.skip` case.

A lazy implementation can use real collection for missing nodes, special-case
that one decorator in the AST, and still approve a collected item dynamically
marked skipped by `pytest_collection_modifyitems`, `pytest.mark.skipif(True)`,
or an equivalent runtime mechanism. That does not satisfy the prior finding's
“pytest-collected and non-skipped” requirement.

Add a `conftest.py` hook that applies a skip marker to an otherwise ordinary
tagged collected node. Require the linter to name and reject that node. This
forces the decision to use pytest's actual item state rather than a decorator
blocklist.

### I-3 — Test-scope hashing exercises only the first-scope case

`tests/swarm/test_gate_wrapper.py:1061-1093` now asserts correct digest values,
which closes the dummy-label weakness for each named field. But the fixture
ticket at lines 36-55 declares exactly one test scope, and the expected aggregate
at lines 1086-1089 contains exactly that one path.

An implementation that reads and hashes only the first declared test scope
passes. The real T-F00 ticket declares three scopes, and the prior finding
requires every declared frozen scope to be bound.

Declare at least two fixture scopes with distinct bytes and assert the aggregate
over both. Prefer also reversing their declaration order while requiring the
documented canonical sorted-path digest, so neither first-only hashing nor
order-dependent concatenation passes.

### I-4 — The atomic-report test permits unlink then rewrite, and no TOCTOU case exists

`tests/swarm/test_gate_wrapper.py:941-958` proves that the final report uses a new
inode. That rejects direct truncation, but it does not prove atomic replacement:
`unlink(report); open(report, "w")` also produces a new inode and passes every
assertion while exposing a missing/partial report window.

The static ticket/package/report symlink cases at lines 905-999 likewise do not
exercise SEC-04's central validation-versus-use race. An implementation may
`lstat`, pause, and later reopen the same pathname normally; all current cases
pass even though a concurrent swap redirects the read or write.

Add deterministic synchronization/failpoint fixtures:

- pause immediately before final publication, terminate the wrapper, and prove a
  pre-existing complete report is still present byte-for-byte;
- pause after input validation, replace one validated path with a symlink, then
  resume and prove the wrapper rejects it without reading/writing the external
  target.

The synchronization interface should be test-only and generic, not an assertion
on a particular implementation function name.

### I-5 — Security fixtures execute an untracked allowlisted script

`_prepare_fixture` commits the initial fixture at
`tests/swarm/test_gate_wrapper.py:377-387`, but `_write_secret_scan` creates
`scripts/secret_scan.sh` later at lines 367-370. Timeout, output-limit,
redaction, encoding, and exact-limit tests then select
`bash scripts/secret_scan.sh` without committing or otherwise integrity-binding
that new executable.

A runner that correctly rejects an untracked mapped executable, or requires the
executed script bytes to be included in commit/evidence binding, will fail these
tests before reaching the intended timeout/redaction/output behavior. Conversely,
the tests currently normalize executing untracked worktree code under an
allowlisted vector, weakening the command-authority and commit-evidence findings.

Create a benign `scripts/secret_scan.sh` before `_commit_fixture`. For each
behavioral variant, update and commit the script (then refresh the signed
approval's commit binding), or use a committed fixed shim controlled through
non-code fixture input whose digest is explicitly recorded. Add a negative that
modifies the mapped executable after the commit and requires rejection or an
explicit digest binding; do not silently execute it.

## Minor finding

### M-1 — Shell wording remains broader than the actual contract

`SECRET_SCAN_COMMAND` intentionally sanctions `bash scripts/secret_scan.sh` at
line 27, while the test at lines 634-645 says shell interpreters cannot be
selected. Its behavior correctly rejects an unsanctioned `sh -c`, but the wording
is contradictory. Rename it to say “unsanctioned shell vector” so future
implementers do not infer that every fixed shell-backed gate is forbidden.

## Conclusion

The candidate substantially improves the repair suite and its RED is clean.
Import-cycle coverage, Tier-1 disclosure, process termination, output bounds,
redaction, exact digest values, base/HEAD checks, coverage-status reporting, and
signed approval behavior are now strong. Freeze is still blocked by five
Important test-design gaps that permit a global/blocklist command authority,
runtime-skipped mappings, first-scope-only hashing, non-atomic unlink/rewrite,
and execution of untracked mapped code.
