# T-F16a Test Agent report

Status: `DONE`

## Provenance

- Worktree: `/Users/quietguy/Documents/Dev/Gauntlet/wt-T-F16a`
- Branch: `ticket/T-F16a-surface-policy-contract`
- Reviewed planning base: `4e5c33f15c86a8970085c1e63e9b53b2e3e8f523`
- Product-code baseline: `1ac3ee02be7855b638dd1fa43bb0612a3db5f025`
- Baseline relationship: `4e5c33f` is the direct child of `1ac3ee0`; its diff contains planning,
  ticket, prompt, and report artifacts only. It changes no product or test code.

## Test-owned artifacts

- `tests/test_final_target_surface_policy.py`
- `.tdd-swarm/reports/T-F16a-test.md`

No product code, configuration, catalog artifact, plan, ticket, migration note, runtime fixture, or
credential source was changed.

## Serialized contract submitted for re-review

The tests define the v2 boundary through existing public serialization functions, avoiding a
collection-time import of symbols that do not exist yet:

- each declared v2 surface serializes `surface_policy` and `surface_policy_sha256`;
- the policy binds schema/version, adapter profile, per-surface auth/no-auth facts, redirect and
  transport limits, typed operation templates, retry counts, logical/physical maxima, and complete
  fixture descriptors;
- every operation template binds method, relative path, request/response content types, credential
  placement, exact credential field name, retry count, and maximum logical operations;
- the authorization scope carries the exact policy and policy SHA-256, and its outer scope hash is
  independently recomputed from canonical JSON;
- v2 multi-surface catalog entries have no target-wide request-shaping profile fallback;
- legacy one-surface/one-profile chat remains loadable, while mixed target-wide
  `payload_profiles` is denied.
- the declared scope is the fixed eight-surface set: Week 1 chat/UI/evidence and Week 2
  chat/UI/evidence/lab/intake;
- `2.0.0` enables chat/UI/evidence while lab/intake remain disabled, and document-capable `2.1.0`
  is a distinct version with separately hashed authorization scopes.

The canonical placement table is:

| Surface/operation | Placement | Exact field |
|---|---|---|
| chat | JSON | `session_id` |
| UI shell | query | `sid` |
| evidence search | none | none |
| document upload | multipart | `session_id` |
| document status/report/preview/readback | query | `session_id` |

## RED map

| Criterion | Frozen RED coverage |
|---|---|
| AC-1 | Catalog -> registry -> scope coverage for all eight final surfaces; Week 1 `/app`; `2.0.0` disabled documents and separately hashed `2.1.0` activation; complete policy shape/hash; missing, duplicate, forged-hash, and target-wide ambiguity refusals |
| AC-2 | Exact credential-key table; UI `session_id` attack; document-upload `None`/`sid` attacks; placement alternates; isolated evidence auth-triad mutations plus combined authenticated downgrade before credential resolution |
| AC-3 | Exact six-field fixture descriptor; omission of every field on both document surfaces; absolute/file/relative/traversal/HTTP/query locators; intra- and cross-surface duplicate refs; upload without descriptor |
| AC-4 | Lab `34` logical / `67` physical and intake `2` / `2`; self-consistent upload/poll/read retry-ceiling attacks; boolean, negative, nonfinite, unbounded, understated, and overstated operation/top-level maxima; valid generic retry `2` control with exact arithmetic |
| AC-5 | Exact policy/hash in canonical scope; independently rehashed method/path/profile/retry/fixture/credential drift; separate adapter, credential, and fixture boundary probes remain untouched; independent auth and path fallback refusals |
| AC-6 | Synthetic and legacy single-profile compatibility; otherwise-identical exact `54b3a4d` target-wide `payload_profiles` ambiguity rejection; executable v1 approval invalidation; exact `1.0.0 -> 2.0.0 -> 2.1.0` migration and rollback contract |

## RED evidence

Final focused command:

```text
/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine/.venv/bin/python \
  -m pytest tests/test_final_target_surface_policy.py -q --tb=no
```

Result after test-review repairs: exit `1`; `101` collected, `101` failed, `0` passed, `0`
collection/setup errors.

The failures are intentional and feature-specific:

1. the baseline catalog rejects the new per-surface entry shape because it still requires one
   target-wide `transport_policy`;
2. baseline `AttackSurfaceDefinition`/serialization rejects `surface_policy` because the canonical
   v2 policy and hash do not exist;
3. baseline accepts mixed target-wide `payload_profiles`;
4. the old v1 approval cannot yet be compared with a canonical v2 policy-bearing scope;
5. the required v2 migration note does not exist.

The helpers convert absent-v2 `TypeError`/catalog refusal into explicit pytest assertion failures,
so collection and fixture setup remain healthy. No test opens a socket, reads a fixture, resolves a
credential, constructs an adapter, or calls a target.

The original test-design attempts stayed within the cap:

1. initial contract: `36/36` intentional RED;
2. formatted contract confirmation: `36/36` intentional RED;
3. final adversarial expansion: `50/50` intentional RED.

The independent Test Reviewer then requested six bounded coverage repairs. The repaired contract
was collected once as a whole (`101/101` intentional RED), followed by a three-test AC-6
failure-causality sample. That sample confirmed the expected causes: current acceptance of the
partial target-wide profile set, absent v2 policy support, and the absent migration note.

## Baseline and static checks

Existing scoped baseline:

```text
/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine/.venv/bin/python \
  -m pytest tests/target/test_relative_path_parameters.py tests/target/test_target_spec.py -q
```

Result: exit `0`; `79` passed.

Formatting/lint:

```text
/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine/.venv/bin/ruff \
  check tests/test_final_target_surface_policy.py
/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine/.venv/bin/ruff \
  format --check tests/test_final_target_surface_policy.py
```

Result: both exit `0`.

Secret checks:

```text
bash scripts/secret_scan.sh
gitleaks git --pre-commit --staged --redact --verbose --no-banner
```

Result: both exit `0`; repository lightweight scan reports `secret scan clean (849 files)`, and
gitleaks reports no leaks in the staged test/report diff. Test data contains only opaque
`secretref://` handles and the two approved non-secret fixture descriptors.

## Post-implementation verifier

`.tdd-swarm/run-local-gates.sh` is intentionally unavailable at this planning base. The locked gate
map records it as blocked pending dependency T-F00. After T-F00 and the implementation land, run:

```text
.tdd-swarm/run-local-gates.sh tickets/T-F16a.md 1ac3ee02be7855b638dd1fa43bb0612a3db5f025
```

This blocked post-GREEN wrapper does not weaken the proven focused RED result above.
