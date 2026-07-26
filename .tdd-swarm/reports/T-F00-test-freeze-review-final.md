# T-F00 Final Test Freeze Review

Status: DONE

Verdict: **REVIEW_PASS** (Critical: 0, Important: 0, Minor: 0)

## Review basis

- Immutable candidate HEAD:
  `514f59b64d9068a380a18f903f618ffb31b7313c`
- Incremental repair: cherry-picked test commit `a2b5c8f`, integrated as
  `514f59b`
- Incremental diff: `1177329..514f59b`
- Approved publisher scope amendment:
  `164ac8e57392623deab58089488fab3be185ffb9`
- Implementation under test:
  `3e1c3700740345a477f4033fd757f82590faf7f9`
- Reviewed the amended ticket, complete three-file test candidate, incremental
  test diff, and all prior T-F00 test, implementation, code, security, repair,
  and freeze-review reports.

The incremental commit changes only
`tests/swarm/test_gate_wrapper.py`.

## Verification

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -p no:cacheprovider -vv --tb=no \
  tests/swarm/test_spec_lint.py \
  tests/swarm/test_import_cycles.py \
  tests/swarm/test_gate_wrapper.py

67 collected; 51 failed; 16 passed; 0 errors
```

Every RED is a pytest assertion failure against behavior missing from
implementation commit `3e1c370`. The two repaired publisher tests each fail at
the explicit missing `.tdd-swarm/publish-report.py` assertion. There are no
syntax, import, collection, fixture-setup, or cleanup errors.

```text
python -m py_compile <three test files>                     PASS
ruff check <three test files>                              PASS
ruff format --check <three test files>                     PASS
git diff --check 1177329..514f59b -- gate-wrapper test     PASS
git diff --check 3e1c370..514f59b -- complete test/ticket  PASS
```

## Prior finding disposition

### I-1 — Fixed publisher reachability: CLOSED

The source-string assertion has been removed. The wrapper test now:

- runs the ordinary wrapper with the real fixed module and proves the malicious
  environment-selected publisher is ignored;
- verifies the complete report contract, one regular non-symlink
  same-directory stage, prior-destination preservation at the precommit
  boundary, and final staged inode/bytes;
- replaces the literal in-repository publisher path with a committed randomized
  non-publishing trap and refreshes the commit-bound signed approval;
- requires the trap's unpredictable nonce and exact stage/destination argv,
  exactly one invocation, and its sentinel exit;
- requires the old destination's full filesystem state to remain unchanged,
  proving the wrapper neither falls back nor publishes after the trap fails.

The trap records reachability only; it does not implement publication. The
separate real-module test owns the atomic behavior claim. A compliant but unused
module plus a wrapper-local unlink/rename path can no longer pass.

### I-2 — Blocklist-passable publisher spy: CLOSED

The production module now runs in a fresh subprocess whose audit hook is
installed before module import. During import and the tightly bracketed
`publish_report` call, the harness:

- instruments `os.replace` before import, calls the real primitive, and requires
  exactly one call with the supplied stage and destination;
- requires exactly one corresponding audited `os.rename` event;
- denies every other `os.*` mutation/process event except read-only directory
  enumeration;
- denies write/create/truncate opens;
- denies subprocess, `ctypes`, CFFI, PTY, thread, multiprocessing, trace/profile,
  runtime compile/exec, and native/process escape surfaces;
- fails on an extra rename, remove/unlink, spawn/fork/exec, system call,
  destination write path, or environment-selected executable.

Direct `posix` aliases emit the same audited `os.*` events, so changing the API
spelling does not evade the contract. The final event log, source disappearance,
destination inode, metadata, and exact bytes bind the audit observation to the
real replacement.

## Complete-candidate disposition

The new repair does not remove or weaken the earlier closed cases. The complete
suite still covers gate-ID/vector authority, coverage-adapter authority, real
pytest collection and runtime skips, every declared test-scope hash,
mapped-executable commit binding, nested import cycles, Tier-1 inventory,
process-group timeout/output bounds, redaction/encoding, report symlinks and
validation/use races, base/HEAD stability, exact evidence hashes, semantic
coverage status, and signed waiver authorization.

The kill-before-publication case remains separate and intact.

## Conclusion

The candidate behaviorally binds the ordinary wrapper to the fixed
in-repository publisher, tests the real publisher rather than a substitute,
permits exactly one real atomic replacement, and closes alternate
filesystem/process paths without a source-text or selected-API blocklist.
No Critical, Important, or Minor test-design finding remains. The T-F00 tests
are approved to freeze at `514f59b`.
