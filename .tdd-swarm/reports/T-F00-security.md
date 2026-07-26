# T-F00 Security Review

Status: CHANGES_REQUIRED

Reviewed commit range: `87b472f..3e1c370`  
Reviewed scope: `.tdd-swarm/spec-lint.sh`, `.tdd-swarm/run-local-gates.sh`,
`.tdd-swarm/check-import-cycles.py`, `.tdd-swarm/coverage-policy.md`, and
`.tdd-swarm/gates.md`.

## Executive summary

No Critical finding was identified. Five Important findings remain: mutable policy content
can execute commands, child processes are unbounded, raw output is persisted, filesystem
validation is raceable, and coverage approval is self-attested. The implementation has no
`eval`, does not import scanned Python modules, and adds no dependencies or direct
network/live-provider behavior.

The frozen test files were not changed: the commit changes only the five declared files.

## Critical

None.

## Important

### SEC-01 — Mutable gate and coverage content is treated as executable code

**Locations:** `.tdd-swarm/run-local-gates.sh:203-253,259-303,351-352,401-403`; `.tdd-swarm/gates.md:3-13`

The gate map and executable coverage policy accept arbitrary command strings, parse them
with `shlex.split`, and invoke the resulting executable. This prevents shell-metacharacter
injection, but not code execution from configuration: a mutable row can name any executable
or explicitly use `sh -c`, which the policy documentation permits. An untrusted change to
either input can therefore execute commands with the gate runner's credentials.

**Fix:** Do not make Markdown/policy command text executable authority. Keep an allowlisted,
protected mapping from gate IDs to fixed argument vectors in the runner or a protected
manifest, and let Markdown only select known IDs. Use a fixed coverage adapter with
constrained options; reject shell interpreters and arbitrary executable paths.

### SEC-02 — Child commands can run indefinitely and consume unbounded runner resources

**Locations:** `.tdd-swarm/run-local-gates.sh:282-301`

Output is capped only after it is read, while the child has no timeout, byte budget, or
CPU/memory limit. A hung or noisy command can occupy the runner indefinitely;
`start_new_session=True` does not terminate its process group. The `16 KiB` report cap does
not bound execution or total bytes drained from the pipe.

**Fix:** Apply a per-gate deadline, then terminate the entire process group (`SIGTERM`,
followed by `SIGKILL`). Stop reading after a bounded amount and kill the process, or use a
bounded spool. Add CI/container CPU and memory limits and record timeout/truncation as a
failing gate.

### SEC-03 — Raw gate output can disclose secrets into logs and the persistent report

**Locations:** `.tdd-swarm/run-local-gates.sh:335-346,358-359,409-410,422-423,433-434,463-466`

Every command's combined stdout/stderr is printed and written into
`.tdd-swarm/reports/<ticket>-gates.md`. Failures can include environment values, request
headers, credentials, or fixture payloads; a length cap does not make those values safe.
This creates a durable, potentially review-visible secret sink.

**Fix:** Treat captured output as sensitive. Redact configured environment values and known
secret formats before console/report emission; keep raw diagnostics only in a private,
short-lived artifact, and write sanitized/truncated output plus a digest to Markdown.
Exclude reports from commits unless explicitly approved.

### SEC-04 — Validation does not bind later reads/writes to validated filesystem objects

**Locations:** `.tdd-swarm/spec-lint.sh:12-15,33-45,95-106`; `.tdd-swarm/run-local-gates.sh:21-30,45-55,81-84,210,316-322,441-466`; `.tdd-swarm/check-import-cycles.py:69-85`

The scripts validate path type/containment and later reopen the original path names. A
concurrent replacement can swap a ticket, test file, policy, gate map, source file, or
report target for a symlink. The report directory/file are never checked before redirection,
so a hostile workspace can redirect the report outside the repository. The import checker
also accepts a symlinked `src/agentforge` directory because it checks only discovered Python
files, not `package_root`.

**Fix:** Retain canonical paths beneath a canonical repo root, reject symlinked parents
(including package and reports directories), and use no-follow descriptor-based reads/writes.
Create the report through a private non-symlinked directory, temporary file, and atomic
rename; do not redirect to an unchecked path.

### SEC-05 — Coverage waiver approval is self-attested

**Locations:** `.tdd-swarm/run-local-gates.sh:108-126`; `.tdd-swarm/coverage-policy.md:3-7`

`approver` is accepted solely because it is non-empty. Anyone changing the policy can claim
`non-applicable` with plausible approver/date/expiry fields and suppress coverage without
independent owner authorization. That does not enforce an owner-approved waiver in an
adversarial workflow.

**Fix:** Require a protected CI approval record keyed by policy hash and commit SHA, or a
signed approval from an allowlisted owner identity. Never accept a waiver introduced or
modified in the same unapproved change solely because its free-text metadata is complete.

## Minor

None.

## Positive controls verified

- `subprocess.Popen` receives an argument vector and does not set `shell=True`; there is no
  `eval`/`exec` in the reviewed tooling.
- The import-cycle checker uses `ast.parse` and never imports target modules.
- Current mapped commands are repository-local. The diff adds no dependencies, network
  clients, live-target calls, provider calls, or test-file modifications.
- Commit/base IDs are syntax-validated and resolved to commits; the executable coverage
  baseline is compared to the supplied base SHA. This does not mitigate SEC-05.
