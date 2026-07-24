# Four-Model Recovery Runbook

This runbook recovers the hosted four-role campaign path without changing Railway topology,
networking, domains, databases, services, Clerk, or the public API version. The only permitted
launch-time operational change is a generation-specific SMART credential rotation in the existing
private Runner.

## Fixed role set

| Role | Requested model |
| --- | --- |
| Orchestrator | `anthropic/claude-opus-4.8` |
| Red Team | `qwen/qwen3.5-397b-a17b` |
| Judge | `google/gemini-2.5-pro` |
| Documentation | `openai/gpt-5.4` |

All four roles must be staged atomically. Per-role activation, model fallback, provider fallback,
and browser-managed credential configuration are unsupported.

## Read-only preflight

Stop before every provider or target call unless all of these checks pass:

- the exact target and attack-surface versions are ready and allowlisted;
- the private Runner heartbeat is no more than 30 seconds old;
- the staged configuration hash resolves to four distinct role credential references;
- two distinct Headshot organization users requested and approved the exact scope;
- the authorization covers campaign start plus the full run timeout;
- the authorization binds the configuration set, generation policy, corpus, target and surface,
  SMART session generation, 56-call maximum, measured $5 maximum, one retry, concurrency one, and
  provider timeout;
- the SMART lease covers campaign start plus the full run timeout;
- all fixtures are synthetic.

The configuration preflight is deliberately secret-free and performs zero provider and target
calls. A missing hosted composition, stale Runner heartbeat, incomplete credential readiness, or
lease failure is terminal for that launch attempt.

## Final SMART session rotation

Do not reuse or overwrite a previously authorized generation. Immediately before the final
authorized campaign:

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

The hosted path is:

`Orchestrator -> Red Team -> Policy Gateway/target -> Judge -> Documentation`

The Policy Gateway remains the only target-dispatch authority. A deterministic oracle or canary
finding takes precedence over the hosted Judge, and Documentation emits unpublished drafts behind
the human approval gate.

A live run is operationally accepted only when evidence includes real provider request IDs,
returned model and upstream provider identities, token usage and measured cost, configuration and
policy hashes, execution lineage, and real target HTTP records. Mocks and cassettes do not count.

## Abort conditions

Abort without a provider or target call when any preflight gate fails. Abort an active campaign on
session expiry, returned-model/provider mismatch, invalid structured output, budget or physical-call
exhaustion, authorization expiry, or explicit operator abort. Never relaunch a terminal campaign
from a consumed approval.
