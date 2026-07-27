# Hosted four-role recovery

**Reconciled:** 2026-07-26

**Detailed state:** [`../CURRENT_STATE.md`](../CURRENT_STATE.md)

**Remediation plan:** [`../../PLAN.md`](../../PLAN.md)

This is an incident-recovery note, not an authorization to deploy, change Railway variables, rotate a
target credential, or launch a campaign. The older pre-`0025` recovery instructions have been retired;
they described a 56-call/15-minute envelope and an uncomposed hosted Red Team that no longer match the
platform.

## Current role binding

| Role | Model | Required upstream |
|---|---|---|
| Orchestrator | `anthropic/claude-opus-4.8` | `anthropic` |
| Red Team | `qwen/qwen3.5-397b-a17b` | staging currently resolves `chutes` |
| Judge | `google/gemini-2.5-pro` | `google-vertex` |
| Documentation | `openai/gpt-5.4` | `openai` |

The live Red Team is a hosted structured selector over the exact approved corpus. Novel generation is a
separate quarantine/review/authorization workflow; generated text cannot flow directly to the target.
The Documentation role runs only for a confirmed finding.

The default code generation-policy digest is
`b83acb23122de9b4911032738bce136f214a34328357b457935ad821b44b0b18`. The active staged configuration is
stored in PostgreSQL, not environment variables, and its digest and limits are recorded in
`docs/CURRENT_STATE.md`.

## Recovery sequence

1. Choose one reviewed commit. Confirm `origin/main` and `gitlab/main` resolve to that same commit and
   run the required checks; a green check never substitutes for reviewing the release delta.
2. Build one immutable image and use it for Web, Runner, and Scheduler.
3. Make Runner inert, deploy Web, and allow Web's pre-deploy Alembic step to reach the packaged sole
   head.
4. Deploy Runner and Scheduler from the identical artifact.
5. Verify database head, service health/readiness, Runner/Scheduler heartbeats, unauthorized denial,
   and exact generation-policy parity across all three services.
6. Perform the signed-in Clerk acceptance flow with real staging users.
7. Validate the exact live target/surface catalog, synthetic-only fixtures, credential-generation
   reference, credential lease, campaign authorization, physical-call limits, target-turn limits,
   spend limits, and abort conditions.
8. Create a fresh request and obtain approval from a different Headshot user after the deployment.
   Authorizations minted against another policy/configuration digest are intentionally invalid.
9. Launch once, then monitor PostgreSQL as the source of truth. Langfuse is a fail-soft projection and
   must be reconciled, not trusted as the campaign ledger.

## Current blockers to a reliable full suite

The `456d6e5` staging release fixed execution-lineage conflicts and completed eleven full role/target/
Judge cycles. It then aborted the whole campaign when one Judge call returned HTTP `200` with
schema-invalid output. The current hosted configuration authorizes zero logical retries, the transport
only retries selected transport/HTTP failures, a structured-output failure is not retried, and an
attempt error fails the campaign. There is no resume path.

Do not call this configuration full-suite reliable until the accepted `PLAN.md` work lands:

- bounded Judge structured-output repair/retry with fully durable physical-attempt lineage;
- case-local terminal outcomes for eligible provider failures;
- resumable execution without repeating completed target turns;
- complete Langfuse projection/reconciliation, including partial and failed campaigns; and
- exact-model Judge calibration with an enforced category-level policy.

## Abort conditions

Abort before traffic on any release skew, stale heartbeat, migration mismatch, unknown policy/config
digest, invalid or expired authorization, insufficient credential lease, unresolved route, cap mismatch,
or non-synthetic fixture. Abort active work on a target/session/auth mismatch, target-version drift,
budget/call exhaustion, or evidence-integrity failure.

An observed target HTTP `422` is application evidence, not a transport success for product semantics.
An `INDETERMINATE` Judge result is not proof that the target defended the attack.
