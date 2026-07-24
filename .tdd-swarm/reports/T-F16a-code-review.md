# T-F16a Code and Security Re-review

Status: `DONE_WITH_CONCERNS`

Reviewed repair commit: `1899c6ae16cf26b6dec0c6e1d012b06358172633`

SPEC verdict: **PASS**

CODE/SECURITY verdict: **PASS**

The two Important findings from review commit
`0dc935e2bda0b6c93bb97d7e1d54e66ef3584ddf` are closed. No Critical, Important, or
Minor correctness finding remains in the repaired implementation.

## Prior finding closure

### Schema-v2 definitions can no longer omit policy through a v1 surface version

Policy enforcement now keys on the target version, not the independently supplied surface version:

- `AttackSurfaceDefinition` rejects a missing policy for a schema-v2 target
  (`src/agentforge/target/spec.py:127-130,1081-1086`).
- `AuthorizationScope` and `AuthorizationScope.for_definitions` reject the same downgrade before
  scope construction (`src/agentforge/target/spec.py:1183-1191,1234-1242`).
- Registry registration rejects a missing policy using `surface.target_version`, and resolution
  checks both the supplied scope and trusted registered surface
  (`src/agentforge/target/registry.py:68-69,104-114,206-232`).
- Target-level auth fallback remains reachable only for the pre-v2 compatibility shape.

An independent reproduction took the canonical `2.0.0` chat surface, changed only its surface
version to `1.0.0`, removed `surface_policy` and its hash, and parsed it through the public
serialization boundary. It failed with `DefinitionError`:

```text
V2_TARGET_V1_SURFACE_POLICYLESS REJECTED DefinitionError
```

A second probe constructed the equivalent valid pre-v2 object, forged only its target version to
`2.0.0` after construction, and passed it to `TargetRegistry.register_surface`. The independent
registry guard rejected it:

```text
FORGED_V2_TARGET_V1_SURFACE_REJECTED_AT_REGISTRY
```

The prior route to target-level `session` auth and the target credential reference is therefore
closed at the domain and registry boundaries.

### Document workflows now bind complete operations and exact per-operation maxima

`SurfacePolicy` declares two complete operation contracts and compares both the operation set and
each `(maximum_logical_operations, retry_count)` tuple
(`src/agentforge/target/spec.py:688-700,824-843`). Catalog admission separately permits only those
two complete document sets (`src/agentforge/target/catalog.py:53-60,197-204`).

Independent canonical parsing produced:

```text
LAB_CONTRACT {
  'upload': (1, 0),
  'status_poll': (30, 1),
  'report': (1, 1),
  'preview': (1, 1),
  'readback': (1, 1)
} 34 67

INTAKE_CONTRACT {
  'upload': (1, 0),
  'duplicate_check': (1, 0)
} 2 2
```

Independently rehashed hostile policies were rejected with `DefinitionError`:

```text
LAB_UPLOAD_ONLY REJECTED
LAB_SELF_CONSISTENT_33_65 REJECTED
INTAKE_UPLOAD_ONLY_1_1 REJECTED
INTAKE_RETRY_DRIFT_2_3 REJECTED
```

Arithmetic consistency can no longer hide an incomplete operation set or understated
per-operation maximum.

## Frozen-test integrity

- Frozen test commit:
  `295e9ccd0b8e1d2c13ad1ccfd8074e762461860f`.
- Recomputed/current SHA-256:
  `fdf129e50018a13d7e69e74d9eb9f08821daba1312dc5bf84d7492583890145e`.
- Recomputed/current Git blob:
  `af6df0ff25e4e53aa0b6aca691d6494ff1d1e501`.
- `git diff 295e9cc..1899c6a -- tests` is empty.
- The repair commit changes only `spec.py`, `catalog.py`, `registry.py`, and the implementation
  report. It does not change tests, transport adapters, fixtures, credential sources, deployment,
  or dependencies.

## Independent verification

Focused frozen contract:

```text
PYTHONPATH=src python -m pytest -o addopts='' \
  tests/test_final_target_surface_policy.py -q
```

Result: `103 passed`.

Target, registry, adapter-registry, and contract regressions:

```text
PYTHONPATH=src python -m pytest -o addopts='' \
  tests/target/test_relative_path_parameters.py \
  tests/target/test_target_spec.py \
  tests/target/test_target_registry.py \
  tests/target/test_adapter_registry.py \
  tests/contract -q
```

Result: `160 passed`.

- Scoped Ruff check: pass.
- Scoped Ruff format check: pass; all four implementation Python files already formatted.
- `git diff --check e392cac..1899c6a`: pass.
- Credential guard: pass.
- Secret scan: `secret scan clean (852 files)`.
- Full-history gitleaks scan: no leaks found.
- No network, credential read, fixture-byte read, adapter construction, target call, deployment, or
  external service action was performed during this review.

## Infrastructure concern

The prompt-mandated `.tdd-swarm/run-local-gates.sh` remains absent at this dependency base because
T-F00 is not integrated. The wrapper therefore cannot be represented as passing. This is the
previously recorded infrastructure concern; every available mapped correctness/static gate above
passes, and it does not reopen either implementation finding.

Final verdict: T-F16a's repaired implementation is **PASS** for specification compliance, code
quality, and the reviewed security boundaries. It may proceed to its separate security-review and
integration gates subject to the T-F00 wrapper prerequisite.
