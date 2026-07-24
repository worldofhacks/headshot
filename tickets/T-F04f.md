---
id: T-F04f
title: Implement OpenRouter transport identity accounting and abort
status: backlog
wave: 3
depends_on: [T-F04c, T-F04g]
branch: ticket/T-F04f-openrouter-transport
file_scopes:
  - src/agentforge/providers/__init__.py
  - src/agentforge/providers/openrouter.py
  - src/agentforge/providers/credentials.py
  - src/agentforge/providers/accounting.py
test_scopes: [tests/test_openrouter_transport.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf four-agent model use, cost, rate, and abort controls
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-13, PRD-16, PRD-25, PRD-26, PRD-33, OPT-08
  - .tdd-swarm/reports/openrouter-scope-review.md I2
---

## Context
[locked-decision] Wave 3 consumes only T-F04g-approved persisted records and owns the shared OpenRouter call boundary. Every physical attempt reserves worst-case tokens/USD atomically before dispatch using authorization-bound token maxima, catalog price vector, and `max_price`, then reconciles exact usage. It never reparses settings/authorization.

## Acceptance Criteria
- **AC-1**: Given a persisted, authorization-matched role configuration, when a role client is constructed, then it resolves only that record's sealed reference through an injected resolver into a redacting `Secret` at the final call boundary; raw/ambient/shared `OPENROUTER_API_KEY`, cross-role resolution, serialization, logging, and exception disclosure are rejected.
- **AC-2**: Given an authorized request, when the transport builds it, then it uses bound base URL/model/schema/routing/data policy, strict JSON Schema, `provider.require_parameters=true`, no fallback, pinned Judge endpoint, authorization-bound catalog price hash and `max_price`; capability or current-price snapshot mismatch fails before reservation/dispatch.
- **AC-3**: Given a provider response, when it is parsed, then the typed result records exact requested/returned model, actual upstream provider/endpoint, trace/request ID, input/output/reasoning tokens, measured USD, schema status, and configuration/policy hashes; missing accounting, malformed output, fallback, or expected-versus-actual identity drift/collision is terminal.
- **AC-4**: Given one physical attempt, when dispatch is proposed, then under one atomic role/global lock accounting reserves worst-case max input+output+reasoning tokens and USD computed from the bound price vector/`max_price`; if reservation would exceed any token/USD/call/retry/concurrency cap, dispatch count remains zero. The last exactly affordable reservation passes.
- **AC-5**: Given a response, when accounting reconciles, then exact returned input/output/reasoning tokens and measured cost replace the reservation and unused capacity is released; a retry acquires a new physical reservation, missing usage/cost retains the full estimate as partial evidence, and price drift or reasoning growth beyond the authorized reservation is terminal/abort with no later call.
- **AC-6**: Given concurrent roles sharing one ledger, when reservations race, then serialization prevents aggregate oversubscription; client reconstruction cannot reset reservations/abort, and timeout/refusal/402/repeated-429/schema/identity failure preserves reserved/reconciled evidence without fallback.

## Test Plan
- Unit (deterministic): role-only secret resolution, strict request/identity, max_price, worst-case formula, last-affordable/refused call, reconciliation, missing usage, price drift, reasoning growth, retry reservation, typed errors.
- Integration (deterministic): concurrent four-role reservations share one atomic ledger; prove no oversubscription/reset and zero transport when reservation fails.
- Eval: none.
- E2E: none; provider SDK/socket construction is patched to fail.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F04f.md <DIFF_BASE>` exits 0 and report hashes are retained.
- [ ] Transport accepts only persisted T-F04c records and cannot parse independent environment/artifact values.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No settings/persistence/migration, role-specific adapter, smoke command/fixture, paid call, live target, or authorization artifact creation.
