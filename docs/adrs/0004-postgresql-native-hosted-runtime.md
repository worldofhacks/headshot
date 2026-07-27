# ADR-0004 — PostgreSQL-native orchestration and exact hosted-role routing

- **Status:** Accepted and implemented
- **Date:** 2026-07-26
- **Supersedes:** runtime/orchestration/model-placement portions of ADR-0001
- **Applies to:** Web, Runner, Scheduler, hosted roles, queue, evidence, and observability

## Context

The original defense selected LangGraph and a local/hosted-OSS Red Team before the platform's durable
authority and Railway operating model were implemented. The delivered system requires exact
authorization binding, physical provider-call accounting, resumability semantics, database-backed
leases, release-parity checks, and independent evidence that survive process restarts.

The current release also routes four distinct roles through OpenRouter and must fail closed if a
returned model or upstream provider differs from the staged identity.

## Decision

1. PostgreSQL is the authoritative control plane, durable queue, audit store, evidence store, and
   projection source.
2. A custom Python Runner claims jobs through PostgreSQL leases/`SKIP LOCKED` and records explicit
   campaign, attempt, logical-agent, physical-provider, target, result, and verdict lineage.
3. LangGraph is not a runtime dependency. Agent separation is enforced by distinct contracts,
   prompts, models/upstreams, executions, context, and authority—not by a graph-framework class.
4. Web, Runner, and Scheduler use one immutable Docker artifact. Web alone has public ingress and owns
   Alembic pre-deploy migration; private workers require the exact packaged database head.
5. OpenRouter is the routing boundary for:

   | Role | Model | Required upstream |
   |---|---|---|
   | Orchestrator | `anthropic/claude-opus-4.8` | `anthropic` |
   | Red Team | `qwen/qwen3.5-397b-a17b` | current staging: `chutes` |
   | Judge | `google/gemini-2.5-pro` | `google-vertex` |
   | Documentation | `openai/gpt-5.4` | `openai` |

6. Fallback/substitution is disabled. Availability is proved at preflight/runtime for the exact staged
   configuration, never inferred from a model list or replaced with a “nearest” model.
7. The live Red Team is an exact-corpus structured selector. Novel generation is quarantined until
   review, frozen provenance, a new workload digest, and fresh authorization.
8. PostgreSQL is observability truth. Langfuse is a sanitized fail-soft projection that counts as
   delivered only after authenticated exact query-back.

## Consequences

- The platform controls leases, idempotency, caps, lineage, and recovery directly.
- Process-framework checkpoints cannot be confused with durable target-side-effect truth.
- Every physical provider attempt, including a failed/retired attempt, can be charged and audited.
- Web/Runner/Scheduler release skew is a hard campaign blocker.
- The custom Runner owns difficult retry/resume correctness and therefore needs the explicit work in
  [`../../PLAN.md`](../../PLAN.md).
- OpenRouter remains a shared routing dependency even though the upstream models are cross-provider.

## Validation

The decision is true when:

- `pyproject.toml` has no LangGraph runtime dependency;
- migrations have one packaged head and workers reject another head;
- logical and physical provider lineage is durable before/reconciled after each call;
- returned model/upstream mismatches fail closed;
- identical policy/file hashes are observed across all deployed application services; and
- Langfuse loss cannot alter authorization, evidence, verdict, or queue truth.

Current deployed evidence and known gaps are in [`../CURRENT_STATE.md`](../CURRENT_STATE.md).
