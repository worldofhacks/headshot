---
id: T-F05c
title: Implement campaign-grant and reviewed-smoke preflight
status: backlog
wave: 8
depends_on: [T-F04h, T-F05a]
branch: ticket/T-F05c-live-campaign-preflight
file_scopes:
  - src/agentforge/campaign/live_preflight.py
  - scripts/preflight_live_campaign.py
test_scopes: [tests/test_live_campaign_preflight.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, exact target authorization, synthetic-only fixtures, budget, rate, abort
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34, USR-04, USR-07, LEAD-09
  - .tdd-swarm/reports/openrouter-scope-review-final.md C1
---

## Context
[locked-decision] Wave 8 deterministic code owns one public zero-call campaign preflight that reads the immutable `campaign.json` grant itself and adds T-F04e smoke/review provenance to the existing campaign authorization, binding, caps, target preflight, and Policy Gateway checks. Expected manifest/review hashes are read from the grant, never supplied as caller-selected expected values. The ticket creates no grant, resolves no credential, and performs no provider/target action.

## Acceptance Criteria
- **AC-1**: Given `python scripts/preflight_live_campaign.py --authorization docs/evidence/authorizations/campaign.json --target-observation <TARGET_OBSERVATION> --deployment-manifest <CURRENT_DEPLOYMENT_MANIFEST> --corpus-manifest <CORPUS_MANIFEST> --synthetic-fixture-manifest <SYNTHETIC_FIXTURE_MANIFEST> --configuration-projection <HOSTED_CONFIGURATION_PROJECTION> --smoke-manifest <SMOKE_MANIFEST> --evidence-review <EVIDENCE_REVIEW> --security-review <SECURITY_REVIEW> --smart-lease-metadata <SMART_LEASE_METADATA> --launcher-ref <LAUNCHER_REF> --check-only`, when invoked, then it parses `campaign.json` as a grant and exits 0 only after every criterion below passes; absent/malformed/request-only/expired grant exits 4.
- **AC-2**: The grant and observed artifacts must exactly agree on normalized staging target ID, adapter surface, scheme/host/port, exact host allowlist and allowlist hash, corpus ID/hash, synthetic fixture IDs/hashes with `synthetic_only:true`, release SHA, current deployment manifest/hash/deployed release, target version, and T-F04g current four-role configuration-set/projection/provider/policy/catalog/data-policy hashes.
- **AC-3**: The grant itself binds the canonical T-F04e smoke-manifest SHA-256 and unequal Evidence/Security review-record SHA-256 values. Preflight invokes T-F04h review verification with those grant-derived expectations and proves two distinct non-executor APPROVED reviewers plus exact manifest/release/configuration/fixture/requested-returned/upstream/prompt/rubric/criteria/policy/catalog/data-policy/verifier provenance; no expected hash is accepted from a CLI substitution.
- **AC-4**: The grant and current Policy Gateway state exactly agree on aggregate and per-role physical call/retry/input/output/reasoning-token/USD/rate/concurrency/timeout/wall-clock/abort caps, expiry, launcher identity, distinct approver identity and permissions, authorization operation hash/nonce, SMART credential-reference hash, session lease generation/not-before/expiry/target binding, and current lease metadata. Launcher equals approver, stale generation, expired/overlong lease, cap expansion, or credential-reference mismatch exits 4.
- **AC-5**: The public verifier composes—not replaces—the existing campaign authorization/binding/caps/target-preflight/Policy-Gateway checks. Every mismatch exits 4 before database mutation, credential resolution, adapter/SDK construction, provider call, target call, or spend; success prints only `CAMPAIGN_PREFLIGHT_OK <CAMPAIGN_AUTHORIZATION_SHA256>`.

## Test Plan
- Unit (deterministic): mutate every grant binding independently, including target/host/surface/allowlist, corpus/synthetic hashes, release/deployment, role configuration/policies, smoke/review hashes, caps, principals, expiry, and SMART lease generation.
- Integration (deterministic): invoke the exact public CLI with immutable local fixtures; patch store writes, resolver, provider, target adapter, socket, and spend hooks to fail; prove T-F04h review expectations originate from `campaign.json`.
- Eval: none.
- E2E: no network; existing Policy Gateway checks plus additive smoke-review gate.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05c.md <DIFF_BASE>` exits 0.
- [ ] Exact public preflight consumes the grant and returns zero-call exit 4 on every mismatch.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No authorization creation/approval, secret/session value resolution, smoke or campaign execution, provider/target call, evidence mutation, deploy, or publication.
