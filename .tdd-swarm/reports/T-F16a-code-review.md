# T-F16a Code and Security Review

Status: `DONE`

Reviewed GREEN commit: `993bb19b9c0cacd69e3dde6e3d4ec27bb210b820`

SPEC verdict: **CHANGES_REQUIRED**

CODE/SECURITY verdict: **CHANGES_REQUIRED**

The committed implementation is not review-passed. Two independently reproduced Important
fail-closed gaps remain. This report is anchored to the commit above; uncommitted product repairs
that appeared later in the shared worktree were excluded from the verdict and were not edited or
staged by this reviewer.

## Findings

### Important — schema-v2 definitions can omit the policy and regain target-level auth

`AttackSurfaceDefinition` and `AuthorizationScope` accept `surface_policy=None` without considering
their target/surface major version (`src/agentforge/target/spec.py:1056-1059,1156-1159`).
`AuthorizationScope.for_definitions` then deliberately copies target-level auth for that shape
(`src/agentforge/target/spec.py:1204-1208`), and registry registration/resolution repeats the same
fallback (`src/agentforge/target/registry.py:111-115,222-229`).

An in-memory reproduction built a `2.0.0` chat surface from the canonical fixture, removed
`surface_policy` plus its hash, registered and readied it, built a scope, and successfully resolved
it with target-level `session` auth:

```text
v2_missing_policy_resolved True session
```

The environment catalog rejects this shape, but the domain and registry boundary that AC-5
explicitly requires to reject target-level fallback does not. Legacy fallback is therefore keyed
only by field absence, not by the AC-6 legacy version boundary. Any trusted store/provisioning path
that supplies definitions directly can create v2 authority without the canonical policy/hash.

Required change: require a policy and canonical policy hash for every schema-v2 target/surface
definition and scope at construction, registration, and resolution. Keep target-auth fallback only
for the explicitly compatible pre-v2 single-profile chat/synthetic contract.

### Important — self-consistent document-policy understatements are accepted

The policy validator proves only that top-level totals equal the operations it was given
(`src/agentforge/target/spec.py:764-782`). For document policies it requires merely some upload
operation and a subset of document classes (`src/agentforge/target/spec.py:807-814`;
`src/agentforge/target/catalog.py:191-197`); it never requires the complete lab/intake workflow or
the locked per-operation logical maxima.

Two independently rehashed policies were accepted:

```text
truncated_document_policy_accepted ['upload'] 1
self_consistent_understated_lab_accepted 33 65
```

The first removed every lab poll/read operation and reduced the physical reservation from `67` to
`1`. The second reduced the status-poll maximum from `30` to `29`, recomputed internally consistent
top-level totals, and was accepted at logical `33` / physical `65`. Both violate AC-1/AC-4 and the
locked `34` logical / `67` physical lab contract
(`docs/planning/final-target-adapters.md:61-75`). Arithmetic consistency is insufficient when the
declared operation set or operation maximum is itself incomplete.

Required change: validate the complete canonical document workflow shape and its per-operation
logical maxima before hashing or catalog admission: lab must bind upload `1`, status poll `30`, and
report/preview/readback `1` each; intake must bind upload plus duplicate-check `1` each. Then derive
and require the exact `34/67` and `2/2` totals.

## Frozen-test and scope integrity

- GREEN is directly based on final test-review commit
  `e392cacac40cfd9f6a1bcda28e7857fe76e5d974`.
- `tests/test_final_target_surface_policy.py` remains byte-identical to frozen commit
  `295e9ccd0b8e1d2c13ad1ccfd8074e762461860f`.
- Recomputed test SHA-256:
  `fdf129e50018a13d7e69e74d9eb9f08821daba1312dc5bf84d7492583890145e`.
- Recomputed/current Git blob:
  `af6df0ff25e4e53aa0b6aca691d6494ff1d1e501`.
- `git diff 295e9cc..993bb19 -- tests` is empty.
- Commit `993bb19` changes only the five implementation-owned source/migration paths and the
  implementation report.

## Independent verification

- Focused frozen, target compatibility, and contract suites: `233 passed`.
- A full backend invocation returned `1228 passed, 3 skipped`, but concurrent uncommitted repair
  edits appeared in the shared worktree during that run, so it is recorded only as regression
  context; the pre-repair focused run above is the authoritative exact-candidate evidence.
- Scoped Ruff check: pass.
- Scoped Ruff format check: pass; four Python files already formatted.
- `git diff --check e392cac..993bb19`: pass.
- Repository lightweight secret scan: `secret scan clean (851 files)`.
- No dependency, lockfile, network client, credential/fixture read, adapter construction, target
  call, or deployment change exists in the committed implementation diff.

The prompt-mandated `.tdd-swarm/run-local-gates.sh` remains absent at this branch and therefore
cannot satisfy the ticket's wrapper gate; direct mapped tests/static checks above were run instead.
Regardless of that infrastructure concern, the two Important findings independently require
implementation repair and re-review before T-F16a can pass.
