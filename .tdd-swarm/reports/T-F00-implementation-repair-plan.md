# T-F00 implementation repair map

Status: READY_FOR_IMPLEMENTATION_AFTER_FREEZE

Review basis:

- Ticket/allowed scope at `164ac8e` (including the new fixed
  `.tdd-swarm/publish-report.py` boundary).
- Existing implementation commit `3e1c370`.
- Complete candidate through the final fixed-publisher test repair
  `12aad6e2ee64f379fa585239146cceec456c03e1`, all T-F00 implementation,
  code, security, repair, and freeze-review reports, and the Tier-1
  quality-gate contract.
- The final atomic contract retains the ordinary wrapper path and fixes the
  publisher interface as
  `publish_report(staged: Path, destination: Path) -> None`.

Do not edit the three frozen test files. The only implementation writes are the
six `file_scopes` in `tickets/T-F00.md`.

## File ownership

| File | Exact responsibility |
|---|---|
| `.tdd-swarm/spec-lint.sh` | Parse ticket/AC/scopes, identify tests added since the supplied base, bind mappings to actual current pytest collection, and reject skipped/uncollected/collection-error mappings. |
| `.tdd-swarm/check-import-cycles.py` | Build the canonical repository module graph without importing it, normalize package initializers and relative/alias imports, detect cycles, and emit its stable graph hash. |
| `.tdd-swarm/run-local-gates.sh` | Validate/snapshot inputs, enforce protected gate and coverage adapters, supervise processes, sanitize evidence, verify approvals/tree identities, render the complete report, stage it safely, and invoke the fixed publisher. |
| `.tdd-swarm/publish-report.py` | Expose `publish_report(staged, destination)` and perform the sole atomic report commit. No rendering, executable selection, destination write, delete, or fallback path. |
| `.tdd-swarm/coverage-policy.md` | Select only `non-applicable` or a fixed coverage-adapter ID and carry the required policy metadata. It is not executable authority. |
| `.tdd-swarm/gates.md` | Inventory every Tier-1 gate. It may select only a protected gate ID/exact display vector; it never grants argv authority. |

## Repair contracts

### 1. Collection-bound spec lint

Use the supplied diff base, not just `rev-parse` it.

1. Read the ticket and every exact declared test scope through validated,
   non-symlinked repository paths; retain bytes/identity and fail if they change
   during collection.
2. Parse current source into test candidates with qualified name and line.
   Associate a tag only with that node:
   `spec(T-F00:AC-1)` in its docstring, an immediately attached source comment,
   or the normalized name form `test_spec_T_F00_AC_1`.
3. Read each scope at the base commit with argument-vector Git calls and compare
   node identities. Every current node absent at the base is a new test; every
   new test requires one valid ticket/AC tag. A legacy untagged node is allowed.
4. Run real pytest collection for the exact scopes with a `trylast` collection
   observer. Capture node IDs, source locations, collection failures, and final
   skip markers after repository hooks run.
5. Only collected, non-skipped nodes can satisfy an AC. Reject and name:
   direct skips, hook-added skips, module-level skips, `collect_ignore`,
   `__test__ = False`, nested functions, methods outside `Test*` classes, and
   files that fail collection.
6. Independently reject wrong-ticket and nonexistent-AC tags, reject an
   untagged new sibling even beside a comment-tagged node, require every AC to
   have at least one valid mapping, and preserve the complete-mapping success
   case.

This replaces the current AST-only scan at `spec-lint.sh:95-136`.

### 2. Canonical import graph

- Canonicalize `.../__init__.py` to its importable package name
  (`agentforge.subsystem`, never `agentforge.subsystem.__init__`).
- Resolve a relative import from the source package context: the package itself
  for an initializer, otherwise the source module's parent.
- For every `from <package> import <alias>`, prefer the concrete
  `<package>.<alias>` module when it exists; otherwise retain the imported
  package module. Apply this at every nesting depth, not only root
  `agentforge`.
- Store only canonical repository-module edges, sort `(source, target)` pairs,
  serialize exactly as `source -> target\n`, and hash those bytes.
- Reject a symlinked package root, source parent, or source file before parsing.
  Parse with `ast`; never import application modules.

This covers root, nested absolute-alias, nested relative, initializer cycles,
and the current acyclic repository graph.

### 3. Fixed gate IDs and coverage adapter

Keep protected dictionaries in code:

- `gate ID -> immutable argv tuple`, including the fixture vectors for
  `format`, `lint`, `typecheck`, and `secret-scan`.
- `coverage adapter ID -> immutable argv tuple`; the only candidate adapter in
  the frozen tests is `pytest-cov`.

Parse `gates.md` as data, then require the exact pair of gate ID and canonical
display vector. A sanctioned vector under another valid ID is invalid. Reject
unknown executables, changed/extra argv, and unsanctioned shell vectors before
starting anything. Do not use `shlex` on map-controlled content. Likewise,
`coverage-policy.md` may contain `coverage-adapter`, never
`coverage-command`; an unknown adapter is rejected without execution.

Snapshot the gate map once, parse/execute that snapshot, and revalidate the
original identity/hash after the `after-input-validation-before-use`
failpoint. A swapped symlink must neither be read nor executed. Before executing
a protected repository script such as `scripts/secret_scan.sh`, require its
tracked bytes to match the starting commit. Tool installations under `.venv`
are external toolchain inputs and should not be mistaken for tracked source.

Retain every declared row. `SKIPPED`/`BLOCKED` requires a nonempty `reason=...`,
is written to the report, and makes the verdict fail. `gates.md` must enumerate
all eleven Tier-1 IDs: format, lint, typecheck, unit, new-tests, coverage,
no-todos, no-debug-logging, docs, reachability, and spec-lint.

### 4. Coverage and signed waiver

Fail closed on an absent/malformed policy.

- `executable` requires only `coverage-adapter`,
  `baseline-base-sha`, and `baseline-percent`; resolve the SHA and require it to
  equal the supplied diff base. Run the fixed adapter, require exactly one
  bounded `coverage=<0..100>` result, and reject regression.
- `non-applicable` requires nonempty reason/approver/date/expiry, a nonfuture
  date, and an unexpired expiry. Free text is descriptive only.
- Require an external JSON approval record, detached Ed25519 signature,
  externally supplied public key, and allowlisted `approver_id`. Verify with a
  fixed `openssl pkeyutl -verify -rawin ...` argv. Require exact schema version,
  policy SHA-256, and starting commit SHA. Reject missing record/signature, bad
  signature, unauthorized identity, stale policy hash, and stale commit
  independently.
- A semantic coverage failure gets its own failed status and retained
  diagnostic even if the adapter process exited zero; the report must say
  `coverage-validation-status: FAIL` and `overall-verdict: FAIL`.

Never create/sign the real owner approval from the implementation flow.

### 5. Bounded command supervision and safe evidence

For every fixed argv, use one new process session and a nonblocking/select-based
read loop:

- enforce a validated positive per-gate deadline;
- retain at most 16,384 raw bytes and read at most one sentinel byte beyond it;
- on timeout or byte 16,385, send `SIGTERM` to the process group, allow a short
  bounded grace, then `SIGKILL` and reap it; do not drain an unbounded producer;
- exactly 16,384 bytes is success with no truncation marker; one byte over is a
  failed output-limit result;
- continue through every remaining mapped row after an ordinary failure.

Hash raw bytes before transformation. Redact both configured secret values and
known credential formats (including AWS access-key form) from console and
report output. Then encode Markdown-active and control bytes canonically:
`<`, `>`, `&`, backtick/pipe/backslash, ANSI ESC as `&#x1B;`, other controls as
`&#xNN;`, and line breaks as `<br>`. Retain a visible
`output-sha256: <raw digest>` binding without changing the simple table-row
contract.

### 6. Base, HEAD, clean tree, and exact hashes

- Resolve base and starting HEAD to full commits and require
  `git merge-base --is-ancestor base head`.
- Before gates, reject dirty declared frozen test scopes and dirty protected
  repository executables, naming the path. The signed policy may remain an
  external, hash-bound input as exercised by the fixtures.
- Snapshot ticket, gate map, wrapper, spec-linter, import checker, publisher,
  policy, and every declared test scope. Before publication, require HEAD to
  equal the starting HEAD and recheck protected worktree/input identities. A
  gate that commits must produce no report.
- Emit exact SHA-256 values for each input. The aggregate test-scope hash is
  over scopes sorted by UTF-8 path, each encoded as:
  4-byte big-endian path length + path bytes + 8-byte big-endian content length
  + raw content bytes. Include every scope, regardless of declaration order.
- Derive the import-graph hash from the same successful canonical graph
  observation used for the gate, not from an unrelated mutable rerun.
- Reports always include ticket/base/head, policy and graph hashes, commands,
  process/semantic statuses, sanitized output and raw-output digests, plus
  `overall-verdict: PASS|FAIL`.

### 7. Fixed atomic publisher

The wrapper must first render the entire final report bytes. Safely open/create
the real `.tdd-swarm/reports` directory without following symlink components.
Create one unpredictable stage name in that directory using
`O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW` with restrictive permissions, write
all bytes, `fsync` the stage, close it, and only then expose
`before-report-publish`. Killing there must leave the prior destination exact.

Invoke the literal fixed argv
`python3 .tdd-swarm/publish-report.py <stage> <destination>` unconditionally.
Never inspect or execute `TDD_SWARM_TEST_REPORT_PUBLISHER` (or any other
publisher selector).

`publish_report(staged, destination)` must:

1. require distinct leaf names in the same verified, non-symlinked directory;
2. hold an `O_DIRECTORY | O_NOFOLLOW` parent descriptor;
3. verify the stage is the expected regular non-symlink object, and any existing
   destination is a regular non-symlink without opening it for write;
4. open the stage read-only with `O_NOFOLLOW`, verify descriptor identity, and
   `fsync` it;
5. call real `os.replace` exactly once, preferably with stage/destination
   basenames plus `src_dir_fd`/`dst_dir_fd` bound to that held directory;
6. `fsync` the held directory and return.

There is no `unlink`, `remove`, `rename`, destination truncate/create/write,
second replace, subprocess/`os.system` delegation, or fallback branch. The
destination must become the prepared stage's inode and exact bytes. Publication
failure propagates; it never degrades to direct output redirection.

## Likely implementation order

1. Add the isolated fixed publisher and make its focused unit/integration
   atomic tests green.
2. Repair import canonicalization (small, independent surface).
3. Replace spec lint with base-aware pytest collection.
4. Refactor wrapper input snapshots, protected ID/argv maps, and signed policy
   validation.
5. Add bounded process supervision, redaction/encoding, row/verdict semantics,
   clean-tree/HEAD checks, and exact hashes.
6. Render/stage once and route every report publication through the fixed
   publisher.
7. Reconcile `gates.md` Tier-1 inventory and `coverage-policy.md` only with
   truthful runnable/approved state.

## Verification commands

```text
bash -n .tdd-swarm/spec-lint.sh .tdd-swarm/run-local-gates.sh
.venv/bin/ruff check .tdd-swarm/check-import-cycles.py .tdd-swarm/publish-report.py
.venv/bin/ruff format --check .tdd-swarm/check-import-cycles.py .tdd-swarm/publish-report.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -p no:cacheprovider -vv --tb=short tests/swarm/test_import_cycles.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -p no:cacheprovider -vv --tb=short tests/swarm/test_spec_lint.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -p no:cacheprovider -vv --tb=short tests/swarm/test_gate_wrapper.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -p no:cacheprovider -q tests/swarm
git diff --check
git diff --name-only <FROZEN_TEST_SHA>..HEAD
.tdd-swarm/run-local-gates.sh tickets/T-F00.md <FROZEN_DIFF_BASE>
```

The final diff-name check must show only the six ticket implementation files;
the report itself remains uncommitted review evidence.

## Pre-GREEN blockers to keep explicit

- The current real policy is free-text self-attestation; the repaired wrapper
  cannot accept it without a genuine externally signed owner approval, or an
  executable coverage adapter and baseline.
- This environment currently has no `.venv/bin/mypy`, coverage executable, or
  pytest-cov installation. `gates.md` must not label missing tooling green.
  Honest `SKIPPED`/`BLOCKED` rows satisfy inventory disclosure but intentionally
  keep the wrapper non-green until the coordinator supplies an approved,
  reproducible toolchain or expands scope.
- `.tdd-swarm/prompts/T-F00-implement.md` predates the publisher scope. The
  implementation dispatch must explicitly use the updated ticket scope; do not
  omit `publish-report.py` because of that stale prompt.
