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

## Frozen serialized contract

The tests define the v2 boundary through existing public serialization functions, avoiding a
collection-time import of symbols that do not exist yet:

- each enabled v2 surface serializes `surface_policy` and `surface_policy_sha256`;
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
| AC-1 | Complete per-surface policy shape; one policy per enabled surface; independent canonical policy SHA-256; missing, duplicate, forged-hash, and target-wide ambiguity refusals |
| AC-2 | Exact credential-key table; UI `session_id` attack; omitted fields; query/JSON/header/cookie/body alternates; document placement; evidence `auth_mode=none`, `explicit_no_auth=true`, and no credential ref |
| AC-3 | Exact six-field fixture descriptor; both approved opaque descriptors; missing/extra fields; path/file/HTTP/query locators; duplicate refs; bad digest/length/type; upload without descriptor |
| AC-4 | Lab `34` logical / `67` physical and intake `2` / `2`; upload retry zero; poll/read retry one; negative, boolean, string-unbounded, infinity, NaN, excess retry, and understated maxima refusals |
| AC-5 | Exact policy/hash in canonical scope; hostile rehashed policy cannot resolve; evidence cannot inherit target auth; policy drift fails before adapter/credential/fixture construction; no auth/path fallback |
| AC-6 | Legacy single-profile compatibility; partial target-wide `payload_profiles` rejection; v2 scope downgrade rejection; migration-note hash break, old-approval invalidation, staged activation, and rollback assertions |

## RED evidence

Final focused command:

```text
/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine/.venv/bin/python \
  -m pytest tests/test_final_target_surface_policy.py -q --tb=no
```

Result: exit `1`; `50` collected, `50` failed, `0` passed, `0` errors.

The failures are intentional and feature-specific:

1. the baseline catalog rejects the new per-surface entry shape because it still requires one
   target-wide `transport_policy`;
2. baseline `AttackSurfaceDefinition`/serialization rejects `surface_policy` because the canonical
   v2 policy and hash do not exist;
3. baseline accepts mixed target-wide `payload_profiles`;
4. the required v2 migration note does not exist.

The helpers convert absent-v2 `TypeError`/catalog refusal into explicit pytest assertion failures,
so collection and fixture setup remain healthy. No test opens a socket, reads a fixture, resolves a
credential, constructs an adapter, or calls a target.

Test-design attempts stayed within the cap:

1. initial contract: `36/36` intentional RED;
2. formatted contract confirmation: `36/36` intentional RED;
3. final adversarial expansion: `50/50` intentional RED.

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

Result: both exit `0`; repository lightweight scan reports `secret scan clean (848 files)`, and
gitleaks reports no leaks in the staged test/report diff. Test data contains only opaque
`secretref://` handles and the two approved non-secret fixture descriptors.

## Post-implementation verifier

`.tdd-swarm/run-local-gates.sh` is intentionally unavailable at this planning base. The locked gate
map records it as blocked pending dependency T-F00. After T-F00 and the implementation land, run:

```text
.tdd-swarm/run-local-gates.sh tickets/T-F16a.md 1ac3ee02be7855b638dd1fa43bb0612a3db5f025
```

This blocked post-GREEN wrapper does not weaken the proven focused RED result above.
