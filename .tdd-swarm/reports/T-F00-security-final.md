# T-F00 Final Security Review

Status: DONE

Verdict: **CHANGES_REQUIRED**

Severity counts: **Critical: 0 · Important: 11 · Minor: 1**

## Review basis

- Immutable candidate: `e15f0a3056d78318c111edf3ce76e3f42d424ec3`
- Frozen-test base: `514f59b64d9068a380a18f903f618ffb31b7313c`
- Exact reviewed diff: `514f59b..e15f0a3`
- The diff changes only the six T-F00 implementation scopes. It does not change
  `tickets/T-F00.md` or the three frozen test files.
- Reviewed the repository rules, T-F00 ticket, tdd-swarm and quality-gate contracts,
  final freeze review, implementation repair map, prior code/security reports, all six
  implementation files, and the frozen tests.
- Already-completed independent evidence in
  `.tdd-swarm/reports/T-F00-code-review-final.md:27-56` records:
  - the focused and aggregate frozen T-F00 suites: **PASS — 67/67**;
  - shell syntax, Ruff lint/format, diff hygiene, and the current import-cycle check:
    **PASS**;
  - the exact frozen-test diff: **empty**.
- This review was static and did not rerun behavioral tests. No network, service,
  credential, provider, or live-target access was performed.

The repository wrapper is **not a green candidate gate**. The committed coverage policy
still says `PENDING_EXTERNAL_OWNER_APPROVAL`, no trusted approval was supplied for this
review, and `.tdd-swarm/gates.md` contains eight `BLOCKED` rows that necessarily make the
overall verdict fail. The retained `T-F00-gates.md` names old HEAD `3e1c370`; it is not
gate evidence for `e15f0a3`.

## Critical

None.

## Important

### SEC-F01 — Coverage approval trusts a caller-selected key and caller-selected allowlist

**Affected lines:** `.tdd-swarm/run-local-gates.sh:337-418,971-977`

The approval record, detached signature, public key, and authorized approver IDs all come
from invocation environment variables. A detached signature proves only that the record
matches the supplied key; it does not establish that the key belongs to an owner when the
same caller selects both the key and the allowlist. The report then records the policy's
free-text `approver`, not the signed `approver_id`, key identity, or approval-artifact
digests.

**Safety impact:** an untrusted job or wrapper caller can turn the coverage waiver back
into self-attestation and make unauditable owner-approval claims.

**Required remediation:** load the trusted public key/fingerprint and approver allowlist
from protected, non-job-controlled configuration (or a pinned CI identity), bind the
record to ticket, base, HEAD, and policy digest, and report the verified signed identity,
key fingerprint, record digest, and signature digest. Free text must remain descriptive
only.

### SEC-F02 — Production-active failpoints permit arbitrary filesystem touches and delay

**Affected lines:** `.tdd-swarm/run-local-gates.sh:596-610,792-793,1008-1010`

The normal production script honors `TDD_SWARM_TEST_FAILPOINT*` without a protected test
mode. Its ready-file value is passed directly to `Path.touch()`, and the wrapper can then
wait for up to 30 seconds on another caller-selected path.

**Safety impact:** an environment-controlling caller can create an empty file or alter
timestamps through the wrapper's authority, follow a symlink during `touch`, and cause a
repeatable local denial of service. The pre-publication hook also intentionally widens
the lifetime of mutable staged evidence.

**Required remediation:** remove path-based failpoints from the production entrypoint.
If synchronization is indispensable in tests, require an independently protected test
mode and use inherited pipe/file descriptors or a newly created private temporary
directory with no-follow, exclusive file creation. Never touch a caller-selected path.

### SEC-F03 — A quiet descendant can survive successful process supervision

**Affected lines:** `.tdd-swarm/run-local-gates.sh:526-593`

After a gate leader exits, a nonblocking read that raises `BlockingIOError` is converted
to `b""` at lines 575-582 and treated as EOF. A quiet descendant that still owns the pipe
therefore causes the loop to return the leader's success code without terminating or
reaping the remaining process group. Group termination runs only on timeout or output
overflow.

**Safety impact:** background gate descendants can outlive verification, consume
resources, mutate the worktree, or race report publication after their gate was recorded
as successful.

**Required remediation:** distinguish EAGAIN from a zero-byte EOF, keep supervising until
real pipe EOF within the deadline, and terminate/reap the remaining group before every
return, including nominal success. Run gates in an OS-level containment boundary when
session/process-group escape must be prevented.

### SEC-F04 — Fixed argv does not bind executable provenance

**Affected lines:** `.tdd-swarm/run-local-gates.sh:4,34-58,74-82,400-415,889-929,1015-1024`

The map correctly binds gate IDs to argument tuples, but several executables are resolved
through caller-controlled `PATH` (`python3`, `bash`, `git`, `openssl`), while `.venv/bin/*`
is mutable external toolchain state. In this worktree `.venv` is itself an external
symlink. Neither interpreter/tool bytes nor the execution environment are verified or
recorded.

**Safety impact:** command text can remain exactly sanctioned while a substituted
interpreter or mutable tool executes different code under the runner's credentials.

**Required remediation:** execute in a pinned, read-only toolchain/container; use
canonical absolute executable paths; reject symlinked executable components; sanitize
`PATH` and the inherited environment; verify approved executable/image digests; and
record toolchain identities in the report.

### SEC-F05 — Spec lint executes environment- and ancestor-discovered Python candidates

**Affected lines:** `.tdd-swarm/spec-lint.sh:212-288`

Interpreter discovery tries `__PYVENV_LAUNCHER__`, local mutable venv paths, ancestor
working directories, and executables parsed from ancestor command lines. Each candidate
whose basename starts with `python` is executed before it is selected.

**Safety impact:** a caller-controlled environment or process context becomes executable
authority during a supposedly fixed spec-lint gate.

**Required remediation:** remove interpreter discovery and ancestor inspection. Accept
only one coordinator-approved, canonical, integrity-bound interpreter from the protected
toolchain used by the wrapper.

### SEC-F06 — Validation and use remain separated by pathname races

**Affected lines:** `.tdd-swarm/run-local-gates.sh:85-169,337-418,633-637,941-945,1008-1024`;
`.tdd-swarm/spec-lint.sh:35-74,390-394`;
`.tdd-swarm/check-import-cycles.py:154-183`

Input checks generally perform `lstat`, then reopen the same pathname to read it.
Approval artifacts are snapshotted but later passed by pathname to OpenSSL. The wrapper
revalidates the publisher and then starts it by pathname. The spec linter and import
checker have equivalent check-then-read windows.

**Safety impact:** a concurrent same-user process can replace and restore a regular file
or directory between validation and use, redirecting reads or execution despite the
static symlink checks.

**Required remediation:** traverse with held directory descriptors; open each leaf once
with `O_NOFOLLOW`; derive bytes, digest, and identity from that descriptor; and consume
the retained bytes/descriptor rather than reopening a name. Verify approval snapshot
bytes in private no-follow files or descriptors, and load/execute the already verified
publisher artifact rather than resolving its pathname after gates run.

### SEC-F07 — The report directory and prepared bytes are not bound across the publisher handoff

**Affected lines:** `.tdd-swarm/run-local-gates.sh:639-702,1007-1029`;
`.tdd-swarm/publish-report.py:28-64`

The wrapper creates the stage relative to a held report-directory descriptor, closes that
descriptor, reconstructs lexical paths, and hands only those paths to a subprocess. The
publisher opens the parent pathname again; `Path.absolute()` is only a lexical comparison,
and `O_NOFOLLOW` on that open does not bind earlier parent components or prove that this is
the directory used for staging. The wrapper does not pass the expected directory/stage
identity, report length, or report digest. The publisher checks a stage inode, opens it
read-only, does not hash its content, and closes that descriptor before the name-based
`os.replace`.

**Safety impact:** a surviving same-user process or concurrent workspace mutation can make
the publisher operate on a different directory object, stage object, or bytes than the
wrapper prepared, while the result occupies the trusted destination.

**Required remediation:** preserve and pass a no-follow report-directory descriptor (plus
leaf names) across the fixed boundary, bind it to the wrapper's expected directory and
stage device/inode, and require the expected report length and digest. Use a
source-object-bound publication primitive, failing closed where the platform cannot
provide one, and verify that the destination is the retained object with the expected
bytes. Walk every ancestor from a trusted anchor without following symlinks, keep the
directory private, and ensure no gate descendants survive into publication.

### SEC-F08 — Untrusted metadata bypasses the evidence encoder

**Affected lines:** `.tdd-swarm/run-local-gates.sh:265-268,448-478,859-870,971-977,994-997`

Command output receives partial Markdown/control encoding, but policy reason/approver
values and `BLOCKED`/`SKIPPED` gate reasons are emitted directly to console and Markdown.
They can contain Markdown/HTML/terminal-active content. Even encoded command output still
permits Unicode bidi/format controls and C1 controls because only ASCII controls, DEL,
and ESC are encoded.

**Safety impact:** a malicious policy, map, or tool output can reorder, conceal, or forge
the rendered security evidence and terminal display without changing the raw-output
digest.

**Required remediation:** route every externally derived field through one
context-appropriate encoder, reject C0/C1, bidi, and other invisible format controls,
and use a strict structured report schema. Validate identity fields with conservative
character sets; never interpolate raw reasons into Markdown tables or terminal output.

### SEC-F09 — Reported HEAD does not bind the tested implementation tree

**Affected lines:** `.tdd-swarm/run-local-gates.sh:734-753,783-794,941-958,1010-1013`;
`.tdd-swarm/check-import-cycles.py:154-195`

The wrapper requires committed bytes only for frozen test scopes, its four core tools,
and mapped repository scripts. It does not parse/bind the ticket's implementation
`file_scopes`, reject dirty relevant source, or record a complete tested-tree manifest.
The import digest hashes only canonical edges, so source changes that preserve edges are
not represented. Rechecking `HEAD` does not detect dirty worktree mutations.

**Safety impact:** a report can name a clean commit while gates and import analysis ran
against materially different source bytes.

**Required remediation:** run against a detached read-only checkout of the candidate, or
fail on every dirty relevant tracked/untracked path at start and finish. Parse all ticket
scopes and record a deterministic path/content manifest (or exact tree plus explicit
dirty-state digest) that is bound to the report and approval.

### SEC-F10 — Secret protection depends on a narrow best-effort name/format list

**Affected lines:** `.tdd-swarm/run-local-gates.sh:421-445,526-535,481-503`

Gate subprocesses inherit the full wrapper environment. Exact-value redaction is enabled
only for environment keys containing a small set of words, and the known-format list is
limited. Common sensitive carriers such as database URLs/DSNs, authorization headers,
cookies, sessions, and newer provider formats are not reliably covered.

**Safety impact:** a failing tool can persist credentials in console output and the
long-lived Markdown report despite the apparent redaction boundary.

**Required remediation:** give gates a minimal allowlisted environment with secrets
removed, use the CI/provider's authoritative masking registry, expand structured
credential detection, and avoid persisting arbitrary command output by default. Treat
redaction as defense in depth, not the primary confidentiality boundary.

### SEC-F11 — Missing or ambiguous import evidence can still produce a PASS verdict

**Affected lines:** `.tdd-swarm/run-local-gates.sh:914-939,946-1004`

The import checker's nonzero exit marks the run failed, but a zero exit with no digest,
a malformed digest, or more than one digest merely sets `import-graph-sha256:
unavailable`. It does not change `overall_pass`. The final report can therefore contain
`overall-verdict: PASS` without the import-graph evidence required by AC-5. This same
source defect is independently recorded in
`.tdd-swarm/reports/T-F00-code-review-final.md:134-153`.

**Safety impact:** a green-looking report can omit or ambiguously source a required
integrity measurement, so downstream reviewers cannot prove which graph observation was
approved.

**Required remediation:** require exactly one full-line, strictly formatted 64-hex digest
from the same successful checker observation. Missing, malformed, or duplicate evidence
must add an explicit import-validation failure row/status and force
`overall-verdict: FAIL`; add frozen regressions for each case.

## Minor

### SEC-F12 — Failure can leave a stale “latest” report and orphaned stage

**Affected lines:** `.tdd-swarm/run-local-gates.sh:639-702,1008-1038`

Fatal preflight failures leave any prior fixed-name report in place. A kill or publisher
failure after staging leaves the unpredictable stage behind. The current worktree
demonstrates the stale-report case: its retained report identifies old HEAD `3e1c370`,
not the reviewed candidate.

**Safety impact:** consumers that read the fixed report path without coupling it to the
current process exit and exact candidate SHA can accept stale evidence; repeated failures
also accumulate artifacts.

**Required remediation:** make consumers reject any report whose head/run identity does
not match the invocation, use run-scoped immutable reports plus an atomically updated
status pointer, and safely clean owned orphan stages through held directory descriptors.
Preserve the prior complete destination on publication failure, but never present it as
the current run.

## Positive controls retained

- Gate-map text cannot directly supply arbitrary argv; available rows are bound to a
  gate ID and exact tuple.
- The ordinary subprocess calls do not enable `shell=True` or `eval`.
- Bounded capture distinguishes exactly 16 KiB from one byte over on the covered path.
- Static report-directory/destination symlinks are rejected, and the fixed publisher
  performs one directory-relative `os.replace`.
- The frozen suite meaningfully covers many prior command, timeout, output, signature,
  hash, symlink, base/HEAD, and atomicity regressions.

These controls do not close the eleven Important trust-boundary findings above. Therefore
`REVIEW_PASS` is not issued.
