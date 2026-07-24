# WP-15 — Wire an authorized feedback-driven mutation loop

**Branch:** `rtg/wp15-authorized-mutation`

**Model:** capable

**Depends on:** WP-10, WP-11, WP-13E, WP-14, and the final-submission hosted
configuration/transport authority if it lands

**Implements toward (live validation pending):** RT-04

Do not recreate provider configuration, secret resolution, price accounting, or transport.
If the reviewed hosted transport dependency is absent, complete only the provider-neutral
implementation seam and report all provider-backed/live behavior blocked.

**Implementation writes only**

- `src/agentforge/agents/red_team/candidate_pipeline.py`
- `src/agentforge/agents/red_team/bundle_review.py`
- `src/agentforge/agents/red_team/generation.py`
- `src/agentforge/agents/red_team/providers.py`
- `src/agentforge/agents/red_team/mutation.py`
- `src/agentforge/agents/red_team/handoff.py`
- `src/agentforge/campaign/corpus.py`
- `src/agentforge/campaign/authorization.py`
- `src/agentforge/runner.py`
- `src/agentforge/storage/models.py`
- `migrations/versions/<MIGRATION_REV>_candidate_bundles.py`
- `src/agentforge/contracts/v1/generation_authorization.json`
- `src/agentforge/contracts/v1/candidate_bundle_review.json`

**Test writes only**

- `tests/red_team/test_candidate_pipeline.py`
- `tests/red_team/test_generation_authorization.py`
- `tests/red_team/test_mutation_authorization_boundary.py`
- `tests/test_runner_mutation_handoff.py`

## Required result

Implement two separately authorized stages:

1. **Generation:** `target_scope:none`; binds provider/model/configuration, seed corpus,
   prompt/policy hashes, call/token/USD/time/depth/candidate caps, and expiry.
2. **Target campaign:** after independent review, binds exact target/surface, the new
   reviewed corpus hash, synthetic assertion, caps, nonce, and expiry.

Generation receives synthetic seed content plus trusted WP-10 gaps/WP-11 criteria—never
raw target responses, credentials, tool arguments, or clinical data. Parse strict output;
Unicode-normalize; bound turns/bytes/depth; reject secrets, PHI indicators, and unapproved
destinations; schema validate; exact/near deduplicate; score novelty; and content-address
every lineage edge. URL/link/OAST/SSRF/output-sink candidates are allowed only as typed
data when their exact destination/callback class is compatible with a reviewed WP-12
surface policy; generation itself must never resolve or contact them.

Consume WP-13E proposed manifests and persist an immutable proposed bundle. Bind every
candidate to exact surface compatibility, expected-safe-behavior hash, taxonomy/version,
required-oracle-policy hash, deterministic near-dedup algorithm/version, minimization and
parent lineage, provider/model/config identity, and atomic call/token/USD accounting. A
distinct authorized Headshot member reviews the exact bundle hash. Approval creates a new
reviewed corpus/hash and reviewer decision but no target authority. Mutation never occurs
inside an already authorized campaign.

Use the reviewed provider transport through injection; no second SDK/client. Tests prove
generation makes zero target calls, target campaign makes zero generation calls, old/new
scope/corpus mismatch denial, post-review tamper denial, idempotency conflict, hostile
feedback containment, lineage, budget/refusal/malformed-output behavior, and no silent
seed-replay fallback.

These are non-evidentiary prechecks. Mutation is operational only when WP-21C performs a
genuine separately authorized provider generation, obtains the existing independent human
bundle review, then executes the new hash under a fresh target authorization against the
deployed target.

**Focused verifier**

```bash
python -m pytest tests/red_team tests/test_runner_mutation_handoff.py tests/test_migrations.py tests/test_readiness_m1d.py -q
```

**Security focus:** approval confused deputy, generated-secret leakage, target authority
inheritance, mutable bundle, corpus substitution, hostile transcript feedback, provider
drift, and cost-cap race.

**Handoff:** WP-20A/WP-20B integrate candidate review and execution; WP-21A/WP-21C require
separate generation and target authorization artifacts.
