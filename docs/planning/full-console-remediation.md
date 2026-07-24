# Full console and runtime remediation

Status: evidence-backed remediation plan
Requirements authority: `Week_3_AgentForge.pdf`
Targets: `clinical-copilot-week1`, `clinical-copilot-week2`

## Release truth

The current console is not yet safe to describe as fully live or fully wired:

- Production Web and Runner identify themselves as `staging`.
- The queued campaign path replays one corpus and does not execute the complete applicable tool plan.
- The deployed workload is fourteen cases, not the required reviewed 100-case baseline.
- The two recorded seventeen-probe campaigns use deterministic judging with the hosted Judge unwired,
  so every verdict is `INDETERMINATE`.
- Production contains no final-target security-tool run records.
- Agent cards show configured assignments, not provider-confirmed model lineage.
- Hosted system-prompt bytes are neither stored nor sent as an OpenRouter `system` message.
- Tools evidence is aggregated by organization and repeated across target/surface rows.
- Final-target scan templates may select the first alphabetic surface even when it is disabled.

These are release blockers, not presentation defects.

## Navigation decisions

| Route | Decision | Required change |
|---|---|---|
| `/live` | Keep | Make campaign selection stable, show exact ScanPlan, preflight, target, surface, models, tools, caps, and physical-request progress. |
| `/findings` | Keep and expand | Add the complete vulnerability report, reproduction, clinical impact, expected/observed behavior, remediation, fix validation, and evidence/trace links. |
| `/approvals` | Keep | Invoke server preflight before launch, preserve two-person control, show bounded `reason_code`, and confirm launches. |
| `/coverage` | Keep and rename | Rename to **Coverage & Regression** and merge the useful resilience timeline and regression ledger here. Coverage is an explicit PDF requirement. |
| `/resilience` | Remove from navigation | Preserve a temporary redirect to `/coverage`; do not delete regression data or Birdseye resilience posture. |
| `/agents` | Keep and rebuild | Show prompt version/content, requested model, returned model, upstream provider, request ID, configuration hash, tokens, cost, latency, and immutable execution lineage. |
| `/tooling` | Keep and rebuild | Present the authorization-bound ScanPlan and per-tool states: planned, running, complete, skipped, not applicable, blocked, failed. |
| `/traces` | Keep | Stop filtering agent executions; expose physical requests, agent calls, handoffs, and evidence lineage together. |
| `/costs` | Keep | Reconcile target requests and hosted-provider calls; display observed tokens and cost without token-times-N estimates. |
| `/targets` | Keep | Select enabled surfaces only, remove aliases/duplicates, show lifecycle and adapter readiness, and expose exact 100/121 caps. |
| `/config` | Keep | Separate static catalog capability from current runtime heartbeat and deployment evidence. |

## Tool execution model

“Use every tool” means every **applicable and authorized** tool is represented in an immutable ScanPlan.
It does not mean blindly pointing every executable at every surface.

| Tool | Correct scope in a scan | Required execution/evidence |
|---|---|---|
| Garak | LLM candidate generation and mutation | Run offline generation at the deployed SHA, review candidates, bind accepted case hashes into the campaign corpus, then count their live attempts. |
| PyRIT | Multi-turn/converter candidate generation | Run offline generation, retain converter/strategy provenance, review, then dispatch accepted cases through the Policy Gateway. |
| Giskard | LLM scenario generation/evaluation | Implement the missing native broker/profile, review generated cases, and record accepted/rejected counts. |
| Promptfoo | Reproducible eval generation/regression | Run the pinned configuration, review candidates, bind hashes, and persist run evidence. |
| ZAP | Passive web companion scan only | Separate two-person authorization; exact origin; no session credential; five-minute cap; depth 5; maximum 10 children. |
| Semgrep | Headshot repository assurance | Run against the exact release SHA and ingest the signed artifact; never present it as a black-box target scan. |
| pip-audit/npm-audit/Gitleaks | Release assurance | Run in both CI systems and expose exact-SHA artifact state in Tooling. |
| Headshot workbench | Cross-tool planning and normalized findings | Persist ScanPlan, tool permits, broker runs, candidates, live dispatch lineage, and normalization results. |

The launch path must:

1. Resolve exactly one target, version, enabled surface, patient/session generation, and corpus.
2. Build a target/surface-specific ScanPlan with applicability and reason codes.
3. Run repository and offline-generation tools before live dispatch.
4. Require independent review of generated candidates.
5. Bind the resulting immutable 100-case manifest into a two-person authorization.
6. Dispatch live cases through the Policy Gateway only.
7. Run separately authorized passive web tooling where applicable.
8. Reconcile plan, process, permit, physical-send, Judge, report, and evidence counts.

## Agent configuration and provenance

The locked runtime assignments are:

- Orchestrator: `anthropic/claude-opus-4.8`
- Red Team: `qwen/qwen3.5-397b-a17b`
- Judge: `google/gemini-2.5-pro`
- Reporter/Documentation: `openai/gpt-5.4`

Each role requires an immutable prompt record:

- role and prompt version;
- exact UTF-8 prompt bytes or a content-addressed prompt object;
- `prompt_sha256`;
- input/output schema hashes;
- policy, rubric, and calibration hashes as applicable;
- configuration-set hash and activation state.

The OpenRouter request must send the verified prompt bytes as the `system` message. Each execution must
persist both requested and provider-confirmed identity:

- requested provider/model;
- returned model;
- upstream provider;
- provider request ID;
- prompt/configuration hashes;
- input/output hashes;
- observed input/output/reasoning tokens;
- measured provider cost and currency;
- start/finish/latency;
- parent execution, campaign, attempt, trace, and evidence references.

The Agents page must display those persisted fields. A configured assignment without a matching
provider-confirmed execution must be labeled **configured, not observed**.

## Page and read-model corrections

### Birdseye

- Never mark a role healthy without a current heartbeat or execution.
- Derive every handoff edge from a persisted parent/child execution, not the existence of any attempt.
- Separate configured, ready, running, degraded, blocked, and never observed.
- Show target, surface, ScanPlan, case/physical-request counts, tools, agents, budget, abort state, and evidence freshness.

### Live

- Select campaigns by durable ID rather than retaining a stale object.
- Show preflight result before launch.
- Show exact target/surface and complete tool plan.
- Confirm abort and display backend reason codes.
- Coalesce SSE updates instead of refreshing four full projections for every event.

### Findings

- Add vulnerability-report and validation-disposition read models.
- Link every finding to attempt, evidence envelope, trace, tool lineage, model lineage, and report.
- Keep publication/remediation human-gated.

### Coverage & Regression

- Count distinct cases, not attempts, for execution coverage.
- Retain OWASP Web/LLM mapping, boundary/invariant/regression classes, version comparison, and regression state.
- Merge resilience history and remove the standalone navigation item.

### Tooling

- Scope counts by organization, target, target version, surface, campaign, and tool.
- Never copy organization-global evidence onto every target.
- Distinguish catalog capability from executed evidence.
- Show enabled/disabled surface state and applicability reason.
- Add immutable run/artifact links and freshness timestamps.

### Traces and Costs

- Include agent/provider calls rather than filtering them out.
- Reconcile target physical requests, provider calls, tokens, measured cost, and authorization caps.
- Add bounded pagination and filters.

### Shared interaction quality

- Preserve backend `reason_code` and request correlation IDs.
- Add retry controls for failed reads.
- Confirm destructive or spend-causing commands.
- Make table-row navigation keyboard accessible.
- Normalize invalid routes.
- Add cursor pagination and stable filters to high-volume views.

## Delivery waves

### Wave A — Runtime truth and safe launch

- Correct production environment identity without crossing databases or secrets.
- Select enabled surfaces only.
- Fix target lifecycle and exact 100 logical / 121 physical / zero-retry caps.
- Add preflight to the launch UI and preserve reason codes.
- Correct false Birdseye health.

### Wave B — Final-target adapters

Execute T-F16a through T-F16f from `docs/planning/final-target-adapters.md`.

### Wave C — Hosted four-role runtime

- Compose the hosted runtime in private Runner.
- Add verified system-prompt storage and transmission.
- Persist requested/returned provider lineage and measured accounting.
- Expose truthful Runner readiness to Web.

### Wave D — Authorization-bound tool orchestration

- Add ScanPlan and per-tool applicability.
- Implement generation/dispatch brokers and missing Giskard profile.
- Persist target/surface-scoped tool-run and artifact records.
- Add the passive-ZAP authorization workflow.

### Wave E — Console information architecture

- Merge Resilience into Coverage.
- Rebuild Agents and Tooling around immutable execution evidence.
- Expose full vulnerability reports.
- Correct Traces, Costs, Targets, and Config truthfulness.
- Add confirmations, retry, pagination, accessibility, and targeted SSE updates.

### Wave F — Final evidence

For each final chat target, run sequentially:

- one target worker;
- no more than three total workers;
- 100 logical cases;
- exactly 121 authorized physical requests when the manifest requires it;
- zero target retries;
- same-origin rate at or below 0.5 requests/second;
- two-hour timeout;
- all four locked hosted role assignments;
- complete applicable tool plan;
- immutable performance, cost, bottleneck, coverage, verdict, and reproducibility report.

Week 2 document verification is separate and limited to the two authorized PDFs, at most two uploads,
one at a time. It cannot run from Railway until the owner supplies or authorizes a Runner-private fixture
binding without violating the prohibition on uploading the extracted bundle.

## Current blockers requiring owner/external state

- The production browser session must be signed in before the visual/interaction audit can complete.
- A distinct authorized Headshot approver must approve each live campaign; launcher self-approval is forbidden.
- The two authorized PDF bytes need an explicitly permitted Runner-private delivery mechanism.
- Production promotion requires a current-SHA deployment grant and rollback binding.
- Both GitHub and GitLab CI must be green on the exact release commit.

Until these conditions hold, the console must say **blocked** rather than imply that a full scan or
fully hosted four-role execution has occurred.
