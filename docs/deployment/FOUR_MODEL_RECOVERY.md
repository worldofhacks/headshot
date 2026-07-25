# Four-model recovery runbook — launch blocked

This runbook describes the target four-model envelope without changing Railway topology,
networking, domains, databases, services, Clerk, or the public API version. It is not evidence that
the envelope is available or composed.

**Current stop condition:** the production Runner composes hosted Orchestrator, Judge, and
Documentation calls, but Red Team remains deterministic corpus selection. The traced q generator is
a tested component only; its governed generation → quarantine → human review → fresh authorization
workflow is not production-composed. Do not launch or describe a four-model recovery until that gap
is closed and a human gives final model-envelope confirmation.

## Fixed role set

These are requested identities, not availability claims:

| Role | Requested model |
| --- | --- |
| Orchestrator | `anthropic/claude-opus-4.8` |
| Red Team | `qwen/qwen3.5-397b-a17b` |
| Judge | `google/gemini-2.5-pro` |
| Documentation | `openai/gpt-5.4` |

After q is governed and composed, all four roles must be staged atomically. Per-role activation,
model fallback, provider fallback, and browser-managed credential configuration remain unsupported.
The distinct human confirmation must verify that every exact model/upstream pair resolves on the
selected OpenRouter route; the repository must not infer availability from a model name or silently
substitute another model.

## Read-only preflight

Stop before every provider or target call unless the production-composition blocker above is closed
and all of these checks pass:

- the exact target and attack-surface versions are ready and allowlisted;
- the private Runner heartbeat is no more than 30 seconds old;
- the human-confirmed staged configuration hash resolves to four distinct role credential
  references and exact model/upstream routes;
- two distinct Headshot organization users requested and approved the exact scope;
- the authorization covers campaign start plus the full run timeout;
- the authorization binds the configuration set, generation policy, corpus, target and surface,
  SMART session generation, 56-call maximum, **measured $10 maximum**, one retry, concurrency one, and
  provider timeout; *(corrected 2026-07-25 from "$5" — the enforced ceiling is
  `HOSTED_MAX_MEASURED_USD = Decimal("10")` at `src/agentforge/agents/hosted.py:28`, with per-role
  ceilings of $1.50 / $1.00 / $4.00 / $1.00 at `:39-45` summing to $7.50 inside it. The 56-call,
  one-retry and concurrency-one figures match `hosted.py:27,29,30` exactly.)*
- the SMART lease covers campaign start plus the full run timeout;
- all fixtures are synthetic.

The configuration preflight is deliberately secret-free and performs zero provider and target
calls. A missing q-generation composition, stale Runner heartbeat, incomplete credential
readiness, unresolved model envelope, or lease failure is terminal for that launch attempt.

## Final SMART session rotation

This section is inapplicable while the q-composition stop condition remains open. Once closed, do
not reuse or overwrite a previously authorized generation. Immediately before the final authorized
campaign:

1. Obtain a genuinely fresh session from the authorized operator workflow.
2. Provision only the raw identifier value inside the protected provisioning boundary. Never
   include a cookie-name wrapper.
3. Create a new immutable, generation-specific secret reference and compute its digest inside that
   same boundary.
4. Update only the existing Runner credential binding, lease metadata, and versioned catalog
   reference for the new generation.
5. Record an issuer-verified expiry only when the issuer supplied it. Otherwise use
   `operator_conservative_lease`.
6. Restart only the existing private Runner and verify that no previous generation overlaps.
7. Launch within five minutes, set authorization expiry within twenty minutes, and keep the
   campaign timeout at fifteen minutes or less.

Resolve the session once into one campaign HTTP client. Session expiry terminates the campaign;
there is no refresh, substitution, or retry. Never place the identifier or its digest in the Web
service, browser storage, API payloads, database records, logs, artifacts, source, shell history,
or evidence.

## Runtime and evidence acceptance

The required future governed path is:

`Orchestrator → q generation → quarantine/review → fresh authorization → deterministic selection → Policy Gateway/target → Judge → Documentation`

The generation and dispatch phases are separate authorization domains; q output cannot flow
directly to the target. The Policy Gateway remains the only target-dispatch authority. A
deterministic oracle or canary finding takes precedence over the hosted Judge, and Documentation
emits unpublished drafts behind the human approval gate.

A live run is operationally accepted only when evidence includes real provider request IDs,
returned model and upstream provider identities, token usage and measured cost, configuration and
policy hashes, execution lineage, and real target HTTP records. The q generation must have its own
canonical logical/physical lineage and a fresh authorized corpus must bind its reviewed output.
Mocks, cassettes, deterministic Red Team selection, and component tests do not count as q-live
evidence.

## Abort conditions

Abort without a provider or target call when the q workflow is not composed, final human model
confirmation is absent, or any preflight gate fails. Abort an active campaign on session expiry,
returned-model/provider mismatch, invalid structured output, budget or physical-call exhaustion,
authorization expiry, or explicit operator abort. Never relaunch a terminal campaign from a
consumed approval.
