# T-F00 Repair Test-Design Review

Status: DONE

Verdict: **CHANGES_REQUIRED** (Critical: 0, Important: 7, Minor: 3)

## Review basis

- Ticket: `tickets/T-F00.md`
- Implementation under repair: `3e1c3700740345a477f4033fd757f82590faf7f9`
- Spec/import repair-test commit: `cc60235`
- Gate-wrapper repair-test commit: `12eee42`
- Prior findings: `.tdd-swarm/reports/T-F00-code-review.md` and
  `.tdd-swarm/reports/T-F00-security.md`
- Contract sources: `.claude/skills/tdd-swarm/SKILL.md` and
  `.claude/skills/tdd-swarm/references/quality-gates.md`

This was a read-only design review of the exact test diffs. Test result claims were
not used as evidence of design adequacy.

## Coverage summary

| Finding area | Verdict | Reason |
|---|---|---|
| Fixed gate/coverage command authority | CHANGES_REQUIRED | Happy fixtures execute shell/policy commands while negatives reject selected shell/Python examples; a blocklist or fixture-specific allowlist passes. |
| Tier-1 inventory and disclosed skips | PASS | The repository map must enumerate the eleven Tier-1 rows, and a skipped row must remain visible and non-green. |
| Per-gate timeout/process-group termination | PASS | The delayed descendant marker detects failure to terminate the process group. |
| Output byte/resource bound | CHANGES_REQUIRED | The finite 256 KiB producer can be fully drained before the implementation reports an output-limit failure. |
| Output redaction | CHANGES_REQUIRED | The sole token is also an environment value, so known-format redaction is not independently exercised. |
| Report symlink safety | PASS (narrow) | Leaf report-directory and report-destination symlinks are covered. |
| Atomic report publication / broader filesystem binding | CHANGES_REQUIRED | No assertion distinguishes atomic replace from direct truncating redirection; validated input/package-root parent symlinks are also absent. |
| Base ancestry and final HEAD stability | PASS | Unrelated base and command-mutated HEAD cases are behaviorally exercised. |
| Dirty frozen-test rejection | PASS | A tracked test-scope mutation must be rejected and named. |
| Input/test hash binding | CHANGES_REQUIRED | New hash fields are checked only for label presence, not their values or sensitivity to byte changes. |
| Coverage semantic status and overall verdict | PASS | Malformed output must leave an explicit validation failure, diagnostic, and FAIL verdict in the report. |
| External waiver approval | CHANGES_REQUIRED | The fixture manufactures the purported independent approval itself, with no authenticity, and corrupts both bindings at once. |
| Diff-base new-test selection | PASS | Legacy and newly added untagged tests are distinguished using the same file across the base. |
| Actual collected, non-skipped spec mapping | CHANGES_REQUIRED | Only statically recognizable examples are covered; no pytest collection configuration/hook or collection failure is exercised. |
| Nested/relative/initializer import cycles | PASS | All three false-negative forms from the code review have direct cycle fixtures. |

## Important findings

### I-1 — Command-authority tests are contradictory and passable with a blocklist

`tests/swarm/test_gate_wrapper.py:21-24,53-63,323-367` makes the successful
wrapper fixtures depend on mutable `sh -c` command strings. The same file then
requires a different `sh -c` row to be rejected as an explicit shell command at
lines 388-399. Likewise, the executable-coverage happy path at lines 96-103 and
263-320 requires a policy-supplied `printf` executable, while lines 402-419 claim
coverage must use a fixed adapter.

These cases do not prove that gate IDs select fixed protected argument vectors.
An implementation can special-case the fixture strings, or merely reject
`python3 -c` and unrecognized `sh -c` strings, while continuing to execute other
policy/map-supplied programs. The tests also push a correct implementation toward
whitelisting test-only shell snippets.

Replace successful fixtures with sanctioned fixed gate/coverage adapter
identifiers. Add negatives that mutate the executable and arguments of an
otherwise valid gate, including a non-shell executable, and prove none run.

### I-2 — Spec-lint can pass without consulting actual pytest collection

`tests/swarm/test_spec_lint.py:166-242` covers only source forms a bespoke AST
checker can recognize: a direct `@pytest.mark.skip`, `__test__ = False`, a nested
function, and a method on a non-`Test*` class. Such a checker can pass every repair
case without binding tags to pytest-collected node IDs.

Missing deterministic cases include a tagged test excluded by `collect_ignore`
or a collection hook/configuration, a module-level/dynamic skip, and a tagged
file that fails collection. At least one collection-controlled fixture is needed
to distinguish real pytest collection from expanded syntax heuristics. A
comment-mapped test followed by an untagged sibling should also prove that a
file-global comment scan cannot launder another new test.

### I-3 — The noisy-output case does not prove an execution byte bound

`tests/swarm/test_gate_wrapper.py:508-521` emits a finite 256 KiB value. A lazy
implementation may read all output into memory, wait for the producer to exit,
then truncate the report and return failure. That passes every assertion while
leaving SEC-02's unbounded pipe draining/resource-consumption defect intact.

Use a continuously noisy producer or a producer that writes past the limit and
then schedules a delayed marker. Require prompt return, bounded evidence, and
absence of the marker/remaining process, proving the output budget terminates the
process group rather than merely truncating after collection.

### I-4 — Known secret-format redaction is not independently tested

`tests/swarm/test_gate_wrapper.py:524-545` places the AWS-looking value in
`FIXTURE_SECRET`. Redacting every non-empty environment value is sufficient to
pass, even if the implementation has no known-secret-pattern detection. SEC-03
explicitly requires both configured-value and known-format redaction.

Emit two distinct values: one innocuous configured secret and one recognized
credential format that is not present in the environment. Require both to be
absent from console and report output while retaining raw-output digest binding.

### I-5 — Atomic publication and the rest of SEC-04 are untested

`tests/swarm/test_gate_wrapper.py:548-581` checks only a symlink at the report
directory leaf and at the final report leaf. Direct `> report_file` publication
after those checks passes both tests; nothing requires same-directory temporary
file plus atomic replace or proves a prior complete report cannot become partial.

The security finding also names symlinked input parents and a symlinked
`src/agentforge` package root, neither of which has a repair case. Add a
deterministic atomic-replacement assertion (for example, a pre-existing report
whose inode/content can only change by complete replacement), plus package-root
and validated-input-parent symlink fixtures that prove no external read/write.

### I-6 — New evidence hashes may be dummy values

`tests/swarm/test_gate_wrapper.py:643-660` checks only that six labels occur in the
report. Constant zeroes, the wrong file's digest, or one digest copied into every
field passes. Thus the tests do not close the code review's requirement to bind
the ticket, gate map, tools, and declared test scopes to the tested bytes.

Compute and assert exact digests where serialization is already defined. For an
aggregate test-scope digest, document its canonicalization and assert the exact
value, or run paired fixtures proving that changing each individual input changes
only the corresponding binding and prevents stale evidence.

### I-7 — The “external approval” remains self-attested and each binding is not isolated

`tests/swarm/test_gate_wrapper.py:66-81` has the test process create the approval
record, choose `approver_id`, and populate the policy hash and commit. Any actor
who can edit the policy can generate the same JSON, so lines 686-722 do not prove
independent owner authorization or a protected/signed record. This recreates the
exact SEC-05 weakness in a second file.

The mismatch test also corrupts both `policy_sha256` and `commit_sha` at once and
accepts a diagnostic for either. An implementation that verifies only one field
passes.

Use a verifiable authority boundary, such as a fixture signed by an allowlisted
owner key or a test double for a protected approval provider. Reject an unsigned
record, a bad signature, and an unauthorized identity. Corrupt policy hash and
commit in separate cases so both bindings are mandatory.

## Minor findings

### M-1 — The timeout test has avoidable wall-clock brittleness

`tests/swarm/test_gate_wrapper.py:493-505` requires `elapsed < 1.5`, sleeps a fixed
0.9 seconds, and relies on a child scheduled at 0.8 seconds. Loaded CI can produce
false failures. Poll for the forbidden marker/process until a generous monotonic
deadline while retaining the much shorter configured gate timeout.

### M-2 — Exact-limit truncation behavior remains uncovered

The prior code-review Minor finding for exactly 16 KiB output is not repaired.
Add adjacent cases for exactly-at-limit and one-byte-over-limit output so only
the latter receives a truncation marker/failure.

### M-3 — Render-active/control output remains uncovered

The prior code-review Minor finding for raw HTML and non-printing control content
is not repaired. Add output containing `<`, `>`, `&`, an ANSI escape, and a
non-printing control and require inert, unambiguous report encoding.

## Conclusion

The import-cycle repairs, Tier-1 inventory, timeout/process-group case,
coverage-status reporting, ancestry/HEAD checks, and basic diff-base distinction
are strong. The suite is not ready to freeze because seven Important gaps still
permit lazy or insecure implementations, most notably self-authored approval,
blocklist command validation, static-only pytest mapping, dummy hashes, and
non-atomic report publication.
