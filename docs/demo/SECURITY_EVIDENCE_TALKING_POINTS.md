# Final security-evidence talking points

Read-aloud companion to the final demo. Every statement must be checked against the exact release and
campaign shown on screen. Paths are relative to the repository root.

## Do not present this as live evidence yet

The moving candidate has one Alembic head at `0018`, but the currently audited GitHub/GitLab `main` and
Railway release remain `23490ea` with database revision `0013`. That older release proves only its own
health/topology and protected-route denial; it cannot prove the candidate's four-agent runtime, physical
provider lineage, or Langfuse reconciliation. Use the wording below only after the exact final commit is
green in authoritative GitHub CI, mirrored to GitLab, deployed to staging, migrated through `0018`, and
used for the authorized frozen 100-case campaign.

## 1. Identity permits a request; exact policy authorizes traffic

“A human reaches Headshot through Clerk, exact Headshot Organization membership, and backend-verified
custom permissions. An Operator may request and launch; a different Approver may authorize. Client role
labels have no authority, and the launcher cannot approve their own request.

“That identity layer is separate from campaign authority. The operation hash also binds the exact target,
surface and version, literal allowlist, target credential reference, synthetic-data assertion and
attestation, frozen corpus hash, hosted configuration and Judge identity, budget, logical and physical
request caps, rate, timeout and expiry, retry policy, nonce, and abort controls. The private Runner
revalidates the persisted grant before dispatch.”

Source: [`USERS.md`](../../USERS.md) and
[`docs/evidence/ato/AUTHORIZATION_MODEL.md`](../evidence/ato/AUTHORIZATION_MODEL.md).

Do not claim that live Headshot membership, custom permissions, MFA, or the two-real-user flow passed
until the final authenticated staging acceptance records it.

## 2. Four roles, one ordered and bounded lineage

“The authorized runtime records **Orchestrator → Red Team → Judge → Documentation** as parent-linked,
durable executions:

| Role | Requested model | Exact upstream route | Authority boundary |
|---|---|---|---|
| Orchestrator | `anthropic/claude-opus-4.8` | `amazon-bedrock/eu-west-1` | Plans and selects work; cannot dispatch directly |
| Red Team | `qwen/qwen3.5-397b-a17b` | `atlas-cloud/fp8` | Untrusted generation; no target credential, verdict, or publication authority |
| Judge | `google/gemini-2.5-pro` | `google-vertex/global` | Independent assessment; deterministic signals retain precedence |
| Documentation | `openai/gpt-5.4` | `azure/eu` | Drafts only from validated findings; cannot publish |

“For every selected frozen seed, the hosted Red Team performs one real traced generation. Its generated
text is not part of the approved corpus, so Headshot stores only a content hash and
`quarantined_not_dispatched` disposition, discards the unreviewed text, and sends the byte-exact authorized
seed to the target. Provider, trace, or budget failure stops the path before target dispatch. Adaptive
variants require review, a new corpus hash, and fresh authorization.”

Source: [`src/agentforge/runner.py`](../../src/agentforge/runner.py) and
[`docs/integration/migrations/provider-call-lineage-v1.md`](../integration/migrations/provider-call-lineage-v1.md).

Documentation is conditional: if there is no validated finding eligible for a draft, say that it did not
run. Never manufacture a fourth event.

## 3. The model Judge is advisory; deterministic oracles decide

“The security owner's model-Judge calibration passed its documented thresholds for the identities
captured in that run, but its `human_approved` and `runtime_enabled` flags are false. Those captured
provider identities also differ from this candidate's exact `google-vertex/global` Judge and
`atlas-cloud/fp8` Red Team routes. Therefore the model assessment remains fail-closed/advisory.
Deterministic oracle/canary evidence is decisive and cannot be downgraded by the model. A calibration
mismatch does not block the campaign; it blocks model-only safety claims.”

Source:
[`docs/evidence/ato/SECURITY_AND_EVAL_EVIDENCE.md`](../evidence/ato/SECURITY_AND_EVAL_EVIDENCE.md).

The security owner controls the corpus, calibration evidence, bottleneck analysis, and reports 004–006.
Do not reinterpret those conclusions. Open the owner-maintained
[`docs/vulnerabilities/README.md`](../vulnerabilities/README.md) and state its recorded provenance and
dispositions exactly.

## 4. PostgreSQL first, Langfuse query-back second

“PostgreSQL is the system of record. Headshot persists each role execution and each physical provider
invocation/event before projecting observations. Langfuse receives an AGENT per role and a child
`provider.openrouter.attempt` GENERATION per physical hosted invocation. The physical generation owns
tokens and cost; the logical hosted-runtime observation is metadata-only, preventing double counting.

“The trace records campaign/run/attempt parentage, agent order, configured and returned provider/model,
latency, input/output tokens, physical sequence, retries, errors, provider request/event identity, and
actual cost where supplied. Raw prompts, responses, credentials, SIDs, and Langfuse keys do not belong in
the trace.

“An SDK flush is not delivery proof. `scripts/verify_langfuse_campaign.py` pages Langfuse Cloud back and
reconciles every expected observation with the durable Headshot rows before marking export verified.
Missing token or billing data stays unavailable; provider-estimated values stay labeled estimated.”

Source: [`src/agentforge/telemetry/outbound.py`](../../src/agentforge/telemetry/outbound.py),
[`scripts/verify_langfuse_campaign.py`](../../scripts/verify_langfuse_campaign.py), and
[`docs/security/LANGFUSE_AGENT_OBSERVABILITY_REVIEW_2026-07-24.md`](../security/LANGFUSE_AGENT_OBSERVABILITY_REVIEW_2026-07-24.md).

Read query-back counts and totals only from the final redacted artifact. The currently audited `0013`
deployment has no acceptable `0018` reconciliation totals.

## 5. Frozen corpus and synthetic evidence stay distinct

“The final campaign must use the security owner's exact frozen 100-case corpus and bind its SHA-256 and
Judge identity into the authorization. No generated/default corpus may replace it. Every case is
synthetic and tagged as boundary, invariant, or regression with OWASP Web and LLM mappings. Scanner-only,
simulated, `NOT_EXECUTED`, `INDETERMINATE`, and `ERROR` records never become confirmed exploits or live
coverage.”

The current integration candidate does **not** yet contain that frozen 100-case evidence. Until the owner
commit is reviewed and integrated, retain the visible blocker. The existing nine authored seeds and
historical adapter runs are not substitutes.

Source: [`docs/evidence/OWASP_COVERAGE_MATRIX.md`](../evidence/OWASP_COVERAGE_MATRIX.md) and
[`docs/evidence/ato/SECURITY_AND_EVAL_EVIDENCE.md`](../evidence/ato/SECURITY_AND_EVAL_EVIDENCE.md).

## 6. Security tools are bounded evidence, never verdict authority

“The repository pins Semgrep `1.170.0`, pip-audit `2.10.1`, npm audit, Gitleaks `8.30.1`, Promptfoo
`0.121.19`, and OWASP ZAP `2.17.0` by image digest. The retained historical artifacts record clean
platform-source dependency/secret scans, one offline Promptfoo case, and expected passive ZAP header
alerts against an isolated fake target. Garak, PyRIT, and Giskard evidence is bounded and offline.
None of that authorizes a live target scan or issues a Judge verdict.

“The final release claim depends on the `security-tools` and `secret-scan` jobs passing in GitHub Actions
for the exact release commit. GitHub CI is authoritative; GitLab is a same-commit mirror, and a GitLab
403/no-runner is not a release failure. Live-origin ZAP remains blocked without its own exact
authorization.”

Source:
[`docs/evidence/ato/SECURITY_TOOL_EVIDENCE.md`](../evidence/ato/SECURITY_TOOL_EVIDENCE.md) and
[`docs/security_tools/ACTIVE_SCAN_AND_TOOL_EVIDENCE.md`](../security_tools/ACTIVE_SCAN_AND_TOOL_EVIDENCE.md).

## Close only after the evidence exists

“This exact staging release completed a bounded, synthetic-only, separately authorized frozen 100-case
campaign. Its four role executions and physical provider calls reconcile between PostgreSQL and Langfuse,
deterministic evidence retains Judge precedence, unreviewed Red Team output never reaches the target, and
findings remain human-gated.”

If any clause is not supported by the final release/campaign IDs and redacted query-back artifact, state
the blocker instead of reading the close.
