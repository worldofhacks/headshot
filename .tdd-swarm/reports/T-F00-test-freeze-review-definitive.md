# T-F00 Definitive Test Freeze Review

Status: DONE

Verdict: **CHANGES_REQUIRED** (Critical: 0, Important: 1, Minor: 0)

## Review basis

- Candidate HEAD: `f3e9302b0c44155ef69c741b0d9e6043bc4eb1a2`
- Test Agent equivalent: `1977d68` (candidate file bytes mechanically integrated as
  `f3e9302`)
- Implementation under test: `3e1c3700740345a477f4033fd757f82590faf7f9`
- Complete test diff: `3e1c370..f3e9302`
- Atomic-repair diff: `4469a2d..f3e9302`
- Reviewed the ticket, tdd-swarm and quality-gate contracts, and every prior T-F00
  test, implementation, code-review, security-review, gate, repair-review, and
  freeze-review report.

## Verification

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -p no:cacheprovider -vv --tb=no \
  tests/swarm/test_spec_lint.py \
  tests/swarm/test_import_cycles.py \
  tests/swarm/test_gate_wrapper.py

66 collected; 50 failed; 16 passed; 0 errors
```

Every RED is a pytest assertion failure against behavior missing from implementation
commit `3e1c370`; there are no syntax, import, collection, fixture-setup, or cleanup
errors.

```text
.venv/bin/ruff check <three test files>                 PASS
.venv/bin/ruff format --check <three test files>        PASS
git diff --check 3e1c370..f3e9302 -- <three test files> PASS
git diff --check e8b0954..f3e9302 -- gate-wrapper test PASS
```

The candidate changes only the three declared test files. The increment after
`4469a2d` adds one atomic-publication test and a backward-compatible optional
environment argument to its process helper; it does not remove or weaken the prior
tests.

## Prior finding disposition

| Area | Verdict |
|---|---|
| Gate ID to fixed-vector binding and coverage-adapter allowlisting | CLOSED |
| Actual pytest collection, including a runtime hook-applied skip | CLOSED |
| Canonical hashing of every declared test scope | CLOSED |
| Mapped-executable commit binding | CLOSED |
| Gate-map validation/use swap and static parent/leaf symlinks | CLOSED |
| Atomic report publication | **CHANGES_REQUIRED** |
| Prior import-cycle, Tier-1 inventory, timeout/process-group, output-budget, redaction, exact-limit, rendered-output, base/HEAD, exact-hash, coverage-status, and signed-approval cases | RETAINED |

## Important finding

### I-1 — The injected publisher proves its own `os.replace`, not the production publication path

At `tests/swarm/test_gate_wrapper.py:1150-1198`, the test writes an untracked
executable outside the fixture repository. That executable itself calls
`os.replace`. At lines 1202-1211, the wrapper is required to select that executable
through `TDD_SWARM_TEST_REPORT_PUBLISHER`. The event, hashes, inode, and before/after
metadata asserted at lines 1253-1284 are all measured and emitted by that same
injected executable.

Consequently, this lazy implementation still passes the complete candidate:

```text
if TDD_SWARM_TEST_REPORT_PUBLISHER is set:
    execute it with staged and destination paths
else:
    unlink(destination)
    create destination and rewrite the report
```

- The ordinary success test sees a new inode.
- The kill test stops before the unlink and preserves the old report.
- The new test delegates to the fixture's `os.replace`, producing exactly the
  expected metadata and final staged inode.
- The normal production branch still has a missing/partial-file window.

The `f3e9302` stat bindings make the fixture's account internally consistent, but
they do not bind that account to the wrapper's default publisher. The test also
requires production code to honor an arbitrary, uncommitted executable path from
environment. A `TEST` prefix plus caller-controlled failpoint variables is not an
authority boundary; this conflicts with the suite's fixed-command and
committed-executable security contracts. The staged-file checks are only
header/newline/verdict checks, so the override branch can also stage a minimal
report rather than the complete report contract.

#### Smallest exact repair

1. Remove the environment-selected publisher and its untracked executable from the
   test contract. The wrapper's ordinary invocation must exercise the exact same
   fixed publication path used outside tests.
2. At the existing precommit failpoint, retain the old-destination check and
   kill-before-commit test, and compare the staged bytes with the complete expected
   report contract (all identities, hashes, statuses, rows, and final newline).
3. The smallest acceptable repair is a fixed in-repository publisher module owned
   by T-F00, invoked unconditionally by the wrapper with no environment-selected
   executable. Directly unit-test that module with a filesystem-primitive spy:
   exactly one `os.replace(staged, destination)`, zero unlink/delete or
   truncate/create operations, and no alternate commit path. Keep a wrapper
   integration case under the ordinary environment proving that the same module
   receives the prepared same-directory file and that the destination retains its
   inode and exact bytes. A syscall/directory-event observer of the ordinary wrapper
   path is an equally strong alternative.
4. Any remaining test hook may provide synchronization or a read-only observation
   sink only. Add a negative proving an environment-supplied publisher executable is
   ignored or rejected without execution.

## Conclusion

All earlier Critical/Important test-design findings except atomic publication remain
closed, and RED quality is clean. Freeze is still blocked because the only evidence
for a one-step atomic commit comes from a substituted helper that performs the
operation itself, while the production publication path may remain non-atomic.
