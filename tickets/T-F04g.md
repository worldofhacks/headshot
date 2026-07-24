---
id: T-F04g
title: Implement read-only hosted authority preflight and projection
status: backlog
wave: 2
depends_on: [T-F04c]
branch: ticket/T-F04g-hosted-authority-preflight
file_scopes:
  - src/agentforge/agents/activation.py
  - src/agentforge/api/birdseye.py
  - scripts/preflight_openrouter_roles.py
test_scopes: [tests/test_hosted_role_preflight.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf four-agent activation, drift, and observability
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-13, PRD-25, PRD-26, OPT-08
  - .tdd-swarm/reports/openrouter-scope-review.md I1
---

## Context
[locked-decision] Wave 2 consumes only the immutable set created by T-F04c and owns read-only authorization comparison, activation/drift disposition, and secret-free projection. It never stages/mutates records, parses canonical settings, resolves credentials, or constructs transport.

## Acceptance Criteria
- **AC-1**: Given `python scripts/preflight_openrouter_roles.py --authorization <AUTHORIZATION> --configuration-set-sha256 <CONFIGURATION_SET_SHA256> --fixture <FIXTURE> --check-only`, when invoked, then it loads the persisted set and compares exact release/configuration/model/reference/upstream/schema/prompt/rubric/criteria/policy/catalog/data-policy/price/`max_price`/fixture/cap/expiry/approver/`target_scope:none` bindings; mismatch exits 4.
- **AC-2**: Given a successful T-F04c public stage invocation, when the same set hash is passed to check-only preflight, then all four records load through the public read interface and the approved immutable set—not reconstructed environment state—is returned to downstream composition.
- **AC-3**: Given any bound-field, authorization, catalog-price, fixture, policy, model, endpoint, or schema drift, when activation is evaluated, then all affected hosted assignments remain `staged_pending_authorization`/invalidated until exact reviewed evidence passes; deterministic defaults are not relabeled hosted.
- **AC-4**: Given a Birdseye/API read projection, when records/executions are returned, then only role/version/configuration-set/hash/reference/activation evidence is exposed; raw credentials, full environment values, and secret resolver handles are absent.
- **AC-5**: Given check-only execution, when store/resolver/transport/target hooks are instrumented, then reads occur but insert/update/delete, secret resolution, SDK construction, provider call, target-adapter construction, and target call counts are all zero.

## Test Plan
- Unit (deterministic): exact authorization comparison, every drift dimension, activation state, secret-free projection.
- Integration (deterministic): stage through T-F04c public CLI fixture, then load the identical set through public check-only preflight; mutation/resolver/transport/target hooks fail if called.
- Eval: none.
- E2E: read-only CLI/projection with injected store and zero external network.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F04g.md <DIFF_BASE>` exits 0.
- [ ] Preflight is mechanically read-only and configuration-set identity survives stage→preflight unchanged.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No settings/domain/persistence/migration, transport/accounting, role behavior, smoke contracts/composition, provider spend, or live target.
