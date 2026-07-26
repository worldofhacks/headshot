# T-F00 Post-review Test Freeze

Status: DONE

Verdict: **REVIEW_CHANGES_REQUIRED**

Severity counts: **Critical: 0 · Important: 10 · Minor: 0**

## Immutable review basis

- Branch: `ticket/T-F00-swarm-gates`
- Test candidate: `19e1a038e0798303a335ccf15f748a51dc212d57`
- Implementation under test: `e15f0a3056d78318c111edf3ce76e3f42d424ec3`
- Exact reviewed diff: `e15f0a3..19e1a03`
- That diff changes only:
  - `tests/swarm/test_spec_lint.py`
  - `tests/swarm/test_gate_wrapper.py`
- `tests/swarm/test_import_cycles.py` is unchanged and was used only to establish the
  complete T-F00 collection/pass count.

## Mechanical verification

```text
pytest --collect-only tests/swarm
87 collected:
  tests/swarm/test_gate_wrapper.py: 62
  tests/swarm/test_import_cycles.py: 5
  tests/swarm/test_spec_lint.py: 20

Legacy selection (all 20 post-review nodes deselected)
PASS — 67/67:
  gate-wrapper legacy nodes: 44
  import-cycle legacy nodes: 5
  spec-lint legacy nodes: 18

Post-review selection only
FAIL as intended — 20/20 assertion failures in 30.23s
Collection errors: 0
Setup/runtime errors: 0
Unexpected passes: 0

Complete suite
67 passed; 20 failed; 0 errors

python3 -m py_compile <two reviewed files>
PASS

ruff check <two reviewed files>
PASS

ruff format --check <two reviewed files>
PASS

git diff --check e15f0a3..19e1a03 -- <two reviewed files>
PASS
```

The RED partition is therefore numerically clean and the legacy 67 remain green.
That is necessary but not sufficient for freeze: several new contracts are
contradictory, weakenable, or cover only one of the trust-boundary paths named by
the final reviews.

## Important findings

### I-1 — The repository-green contract can pass without the required verifier ever succeeding

`tests/swarm/test_gate_wrapper.py:1913-1952` only checks that map status strings
equal `AVAILABLE`, that three coverage-policy strings have expected values, and
that the baseline names some commit. It neither executes the real mapped commands
nor invokes the ticket's exact required verifier. A repair can relabel every row
`AVAILABLE` and write a syntactically executable policy while adapters are absent
or commands still fail; this test then passes although code-review I-1 remains.

Required repair: exercise the ordinary fixed wrapper against a temporary committed
copy of the real repository map/policy, require zero exit, require every mapped row
to have actually executed, and validate the resulting candidate/base/head and
evidence hashes. A text-only inventory check may remain as a supplementary test.

### I-2 — The approval tests do not establish protected owner trust and synthesize an owner-looking approval

`tests/swarm/test_gate_wrapper.py:497-510` generates a key inside the test process
and commits a repository file that declares its fingerprint to be
`owner:headshot`. `tests/swarm/test_gate_wrapper.py:2094-2139` then treats a
signature from that generated key as an approved waiver. The record helper at
lines 134-170 still binds only policy digest, one commit SHA, and identity; it does
not bind ticket, diff base, and HEAD independently as SEC-F01 requires. Nor is
there a negative proving that the trust anchor cannot be replaced as caller/job
controlled repository state.

This is a synthetic fixture, not evidence of actual Headshot owner approval, but
its production-looking identity makes that distinction unsafe and the success
contract would bless an incomplete trust design.

Required repair: use an unmistakably test-only identity; supply the pinned test
public key/fingerprint from a harness-owned, non-job-controlled authority; bind and
assert ticket, base, HEAD, policy digest, verified identity, key fingerprint,
record digest, and signature digest; and add dirty/replaced/symlinked trust-anchor
negatives. Never turn the repository's real policy into an invented approved
waiver.

### I-3 — The failpoint contracts are mutually incompatible and preserve the production vulnerability

`tests/swarm/test_gate_wrapper.py:2142-2171` requires production failpoint
environment variables not to touch or delay paths outside the fixture repository.
But the unchanged tests at lines 1162-1193 and 1392-1605, plus the new handoff test
at lines 2204-2244, require the ordinary production wrapper to honor the same
caller-controlled path variables when those paths are inside the repository.
There is no independently protected test mode.

A lazy repair can allow path failpoints only for in-repository paths and pass all
tests while retaining SEC-F02's arbitrary touch/delay authority. A faithful repair
that removes production path failpoints fails the synchronization tests.

Required repair: make every production invocation ignore/reject all
`TDD_SWARM_TEST_FAILPOINT*` path inputs, regardless of path location. Replace test
synchronization with a harness-controlled inherited pipe/file descriptor or a
separate test-only boundary that cannot be enabled by normal environment input.

### I-4 — The silent-descendant fixture can reject a correct supervisor

At `tests/swarm/test_gate_wrapper.py:1962-1971`, the shell starts the Python child
in the background and exits without waiting for the child to write
`silent-child.pid`; the test then requires that file at lines 1983-1989. A correct
supervisor may detect leader exit and kill the process group before Python starts
and writes the file, failing the test despite leaving no descendant. This is a
scheduling race in the contract for code-review I-2 / SEC-F03.

Required repair: add a bounded child-ready handshake before the leader exits (or
use an inherited descriptor), then prove the already-running pipe-holding child is
gone, the row fails, and no PASS report is published.

### I-5 — Executable provenance is checked for one name and two labels, not the final trust boundary

`tests/swarm/test_gate_wrapper.py:2174-2201` poisons only `python3` and accepts the
mere presence of `python-interpreter-sha256` and
`execution-environment-sha256`; hard-coded dummy labels pass. It does not exercise
the `bash`, `git`, or `openssl` PATH substitutions, mutable/symlinked
`.venv/bin/*`, exact executable digests, or a sanitized environment required by
SEC-F04.

Likewise, `tests/swarm/test_spec_lint.py:225-271` probes the current
`__PYVENV_LAUNCHER__`/`lsof` discovery path but permits either success or failure
and does not bind the successful collector to an exact coordinator-approved
interpreter. Other ancestor/PATH discovery and mutable local interpreters can
remain, so SEC-F05 is only partially covered.

Required repair: poison every named resolution surface with independent markers;
exercise symlinked and post-validation-mutated toolchain entries; assert exact
canonical paths and digests against harness-known binaries/environment manifests;
and make spec-lint use one explicit protected interpreter while all caller and
ancestor discovery inputs are hostile.

### I-6 — SEC-F06 is mostly untested and the report-handoff test covers bytes, not object identity

The legacy gate-map swap covers one validation/use race, but no post-review test
swaps the ticket, policy/approval artifacts, spec-lint input, import source/checker,
publisher, or report-directory object identified by SEC-F06.

`tests/swarm/test_gate_wrapper.py:2204-2244` mutates bytes through the existing
stage pathname. It does not replace the stage inode, exchange the report
directory, swap an earlier ancestor after validation, or assert the expected
directory/stage device+inode, length, and digest at the publisher boundary. A
repair that merely re-reads the pathname just before publication passes while the
SEC-F06/SEC-F07 pathname races remain.

Required repair: after moving synchronization off production path failpoints, add
deterministic object-swap cases for each named input class and for report
directory/stage identity. Assert held no-follow directory/object identities,
expected length/digest, preservation of the prior destination, and no external
read/write.

### I-7 — Metadata encoding can be special-cased to the two exercised sources

`tests/swarm/test_gate_wrapper.py:2247-2271` covers three useful characters, but
only in coverage command output and a `BLOCKED` gate reason. SEC-F08 separately
names policy reason/approver, skipped metadata, identity fields, and every other
externally derived report/console field. Those paths remain untested; a repair can
special-case these exact fields/code points and pass.

Required repair: parameterize representative C0, C1, bidi, and isolate/format
controls across command output, policy reason/approver, blocked/skipped reasons,
and identity/table fields; assert the exact canonical encoding in console and
report, plus conservative rejection rules for identity fields.

### I-8 — Implementation binding is first-scope-only and misses the required dirty-state surface

The fixture added at `tests/swarm/test_gate_wrapper.py:41-53` declares exactly one
implementation scope. Consequently the clean/dirty cases at lines 2274-2304 are
passed by an implementation that reads and hashes only the first `file_scopes`
entry. The real ticket has six scopes. The test also covers only a pre-existing
dirty tracked file, not relevant untracked content or mutation between start and
finish, as required by SEC-F09.

Required repair: declare multiple distinct scopes in reversed declaration order,
assert the exact canonical aggregate over all of them, exercise relevant tracked
and untracked dirt, and synchronize a mid-run mutation before the final
revalidation.

### I-9 — The child-environment test is satisfiable by redaction while secrets still reach the gate

`tests/swarm/test_gate_wrapper.py:2307-2338` asserts only that two secret values do
not appear in console/report and that a policy label exists. A runner can pass the
entire parent environment to the child, redact these two outputs afterward, and
hard-code `child-environment-policy: minimal-allowlist`. That leaves SEC-F10's
primary confidentiality failure intact.

Required repair: require the committed child probe to observe `unset` for hostile
parent variables, enumerate the exact allowed child keys/values, include
unpatterned arbitrary variables and several named credential carriers, and retain
output redaction only as a separate defense-in-depth contract.

### I-10 — The stale/orphan tests authorize unsafe deletion rather than proving ownership

`tests/swarm/test_gate_wrapper.py:2341-2360` explicitly accepts deleting the prior
fixed report on a failed invocation. That conflicts with AC-5's no-destination-
delete rule and SEC-F12's requirement to preserve the prior complete destination
while preventing it from being represented as the current run.

At lines 2363-2388, an orphan is considered owned solely from a predictable
filename, attacker-creatable contents, and mode. Blindly deleting every matching
file passes, while a same-user file can be removed without provenance.

Required repair: retain the prior immutable report byte-for-byte, use a run-scoped
identity plus an atomically updated current-status/pointer contract that rejects
head/run mismatches, and clean only stages whose ownership is proven by retained
directory/object identity or a protected run registry. Add a malicious exact-
pattern lookalike that must survive.

## Final-review coverage disposition

| Final finding | Freeze disposition |
|---|---|
| Code I-1 — required verifier cannot pass | **PARTIAL — I-1** |
| Code I-2 / SEC-F03 — surviving descendant | **PARTIAL / racy — I-4** |
| Code I-3 — parametrized `::` node ID | COVERED |
| Code I-4 / SEC-F11 — missing/duplicate import digest | COVERED |
| Code M-1 — earlier publisher ancestor symlink | COVERED |
| Code M-2 — non-finite coverage baseline | COVERED |
| SEC-F01 — caller-selected approval trust | **PARTIAL — I-2** |
| SEC-F02 — production-active failpoints | **CONTRADICTORY — I-3** |
| SEC-F04 — executable provenance | **PARTIAL — I-5** |
| SEC-F05 — spec-lint interpreter discovery | **PARTIAL — I-5** |
| SEC-F06 — validation/use pathname races | **OPEN except gate-map case — I-6** |
| SEC-F07 — report directory/stage handoff | **PARTIAL — I-3, I-6** |
| SEC-F08 — untrusted metadata encoding | **PARTIAL — I-7** |
| SEC-F09 — HEAD/tested-tree binding | **PARTIAL — I-8** |
| SEC-F10 — inherited secrets | **PARTIAL — I-9** |
| SEC-F12 — stale report/orphan stage | **UNSAFE CONTRACT — I-10** |

## Conclusion

The candidate achieves the requested collection and RED partition exactly:
**87 collected, legacy 67 green, intended 20 red, zero errors**. The two files
also pass syntax, lint, format, and diff hygiene checks.

Freeze is nevertheless denied. The added tests do not yet provide a
production-faithful, non-weakenable closure of all final code/security findings,
and the failpoint tests cannot be satisfied by the required SEC-F02 repair without
retaining an insecure caller-selected path exception. No test, implementation,
ticket, or prior report was modified.
