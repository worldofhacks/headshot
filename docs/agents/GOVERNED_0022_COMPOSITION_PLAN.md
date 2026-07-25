# Governed 0022 — real four-role composition (design, code-grounded)

**Goal (v1 hard blocker):** a real attack flows end to end over the **existing reviewed/authorized
corpus** — Orchestrator selects a reviewed case → Red Team dispatches *that exact reviewed case*
through the Policy Gateway to the target → Recorder persists the **real** response → Judge evaluates
that **real** response (not synthetic) → Documentation drafts from the real verdict. No unreviewed
generation (Horizon 2). Approach: **reuse `HostedFourRoleRuntime.run_attempt`** with a real gateway
dispatch — m's chosen Option 1.

Confirmed with m: 0018 = `0018_provider_call_lineage` (rev 0018←0017) is canonical; build 0022 on
0021. `codex/integration-four-role-composition-b176` is an **ancestor** of this branch (PR #43,
already incorporated) — no lane to deconflict. Runtime-hardening/terminalization =
`fix/provider-evidence-terminalization` (ahead; HEAD "the traced Red Team path dangled, and a billed
call could read as never made") — the governed lifecycle **must** adopt its terminalization contract.

## The gap (measured, not assumed)

`agent_acceptance.py::run_agent_acceptance` is a **smoke chain**: all four roles make real OpenRouter
calls (real cost/tokens/traces) BUT Red Team output is `generated_output_disposition:
"quarantined_not_dispatched"` / `target_call_limit: 0`; the Judge scores a hardcoded synthetic
`EvidenceEnvelopeBuilder` transcript (`ACCEPTANCE-CANARY-ONLY`); the verdict is hardcoded
`EXPLOIT_CONFIRMED`. No gateway, no target, no real response (`agent_acceptance.py:1-6,302-655`).

The real seam already exists: `HostedFourRoleRuntime.run_attempt` (`hosted_runtime.py:631-783`) takes
a `policy_gateway_dispatch` callable + `authorized_case`, dispatches the Red Team output through it →
`evidence` → `deterministic_judge(evidence)` → hosted Judge over `target_evidence` → Documentation.
It is **already the real composition** — it just needs a real dispatch + real evidence + reviewed seed.

## Build: `run_governed_acceptance` (new, alongside `run_agent_acceptance`)

Reuse `run_attempt`; supply four real dependencies:

1. **`authorized_case` = a reviewed corpus case.** `campaign/corpus.py::load_mvp_corpus` →
   `verified_case_payload(case)`; `seed_replay.py::seed_to_attempt(case)` is the exact reviewed
   attack_attempt projection. `authorized_case = {"case_id": case.case_id, ...verified payload...}`.

2. **Governed `policy_gateway_dispatch`** — enforce the corpus-hash invariant, then dispatch through
   the real gateway (reusing the coordinator pattern `coordinator.py:520-619`):
   ```python
   expected = seed_to_attempt(reviewed_case)            # the reviewed bytes
   def governed_dispatch(red_team_output):
       if dict(red_team_output) != expected:            # authorization invariant (seed-replay)
           raise HostedCompositionError(code="red-team-proposal-out-of-scope")
       result = gateway.execute(expected, policy, target_id=binding.target_id,
                                campaign_run_id=run_id, attempt_id=attempt_id, ...,
                                red_team_execution_id=red_team_execution_id)  # REAL target
       with engine.begin() as conn: recorder.record(result.fields, conn)     # persist real response
       transcript = reread_response_transcript(engine, run_id, attempt_id)   # real bytes
       return {"transcript": transcript, "content_hash": result.content_hash, ...}  # REAL evidence
   ```
   The `PolicyGateway` is built like `coordinator._run_gateway` (allowlist = bound target only,
   bound adapter, scoped credential, recorder, caps). Gateway is the SOLE cap-enforcing target exit;
   Red Team never holds a credential. Dispatched bytes == reviewed corpus, else hard abort — so the
   authorization invariant holds and no unreviewed content ever reaches the target.

3. **Real `deterministic_judge`** — the platform oracle/canary over the REAL transcript (not a
   hardcoded verdict). Build the `EvidenceEnvelope` from the real transcript + oracle_results +
   canary_hits, exactly as the coordinator does (`EvidenceEnvelopeBuilder`), and reconcile via the
   oracle. The hosted Judge then evaluates that real `target_evidence` (`run_attempt` line 714-738).

4. **Terminalization-safe lifecycle** — the `_AcceptanceLifecycle` start/finish + evidence
   preservation, adopting `fix/provider-evidence-terminalization`'s contract: terminalization can
   never be refused (an execution never dangles); cost is a separable observation (a billed call is
   never recorded as never-made); the Red Team traced path finishes on every exit. Wrap the whole run
   so `create_agent_acceptance_run` → (four executions) → `complete_agent_acceptance_run` /
   `abort_agent_acceptance_run` on any failure.

Return `AgentAcceptanceResult` + the real evidence `content_hash` (re-read + `recorder.verify`).

## Migration 0022 — governed, target-BOUND four-role authority (down_revision 0021)

0020/0021 authorize the **target-free** acceptance (`target_call_limit = 0`, quarantined Red Team,
`network_scope = openrouter_langfuse_only`). Governed 0022 adds a **v3 / governed** authority that:
- permits `target_call_limit >= 1` bound to **one** authorized target + adapter kind + scoped
  credential marker, and binds the reviewed `corpus_id` + `corpus_sha256` (the seed-replay contract);
- keeps the four-role lineage + immutability + Judge failed-calibration/oracle-reconciliation guards
  from 0021's `m1d_validate_agent_acceptance_execution`, extended so the Red Team execution may carry
  a `dispatched_attempt` linkage to the recorded `attempt_result`;
- requires **two-person authority** (`launcher_user_id != approver_user_id`) — this is a live-target
  campaign, not a target-free harness;
- downgrade refuses while immutable governed rows exist (mirrors 0021's guard).

Migration test (like `test_agent_acceptance_migration.py`): upgrade/downgrade idempotence; the
governed limits constraint accepts a valid v3 payload and rejects target_call_limit=0 for governed;
the execution guard still enforces the four-role parent chain + Judge oracle.

## Tests vs. evidence (kept separate, per m)

- **End-to-end test (this PR, green in CI):** `test_governed_four_role_acceptance.py` invokes
  `run_governed_acceptance` against a **controlled** target (injected bound adapter returning a canned
  real-shaped response; injected deterministic transport returning the reviewed case for Red Team and
  fixed outputs for the other roles) on `migrated_db`. Asserts: the Judge's `target_evidence` equals
  the **real (controlled) target response**, NOT the synthetic canary; four executions recorded with
  real lineage + the four-role parent chain; verdict derived from the real evidence; the run
  completes with no dangling execution. **Proves the wiring — is not the evidence.**
- **Real four-role evidence (separate, post-deploy):** an authorized live-target campaign (real SID
  via the sealed secretref binding + two-person auth) run in the private Runner using the `.env.local`
  OpenRouter/Langfuse credentials → actual Langfuse traces + measured cost. Command staged in the PR;
  never conflated with the test.

## Sequencing

1. Migration 0022 + migration test (schema foundation) — this increment.
2. `run_governed_acceptance` + the governed dispatch + terminalization-safe lifecycle.
3. The green e2e test (controlled target).
4. Rebase onto / coordinate the `fix/provider-evidence-terminalization` contract; PR to m.
5. Post-deploy: the authorized live-target evidence campaign → the real acceptance artifact.
