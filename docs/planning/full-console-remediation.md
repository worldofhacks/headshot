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
| `/audit` API | Keep inside Configuration | Preserve permission-gated append-only audit history without adding another navigation destination. |

## Tool execution model

“Use every tool” means every **applicable and authorized** tool is represented in an immutable
ScanPlan. It does not mean blindly pointing every executable at every surface.

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

Each tool independently records installed, configured, generated, executed, and
evidenced/adjudicated state. No state implies the next.

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

The OpenRouter request must send the verified prompt bytes as the `system` message. Each execution
must persist both requested and provider-confirmed identity:

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
- Derive every handoff edge from a persisted parent/child execution, not any attempt's existence.
- Separate configured, ready, running, degraded, blocked, and never observed.
- Show target, surface, ScanPlan, case/physical-request counts, tools, agents, budget, abort state, and
  evidence freshness.

### Live

- Select campaigns by durable ID rather than retaining a stale object.
- Show preflight result before launch.
- Show exact target/surface and complete tool plan.
- Confirm abort and display backend reason codes.
- Coalesce resource-specific SSE updates and retain a bounded authoritative polling fallback.

### Findings

- Add vulnerability-report and validation-disposition read models.
- Link every finding to attempt, evidence envelope, trace, tool lineage, model lineage, and report.
- Keep publication/remediation human-gated.

### Coverage & Regression

- Count distinct cases, not attempts, for execution coverage.
- Retain OWASP Web/LLM mapping, boundary/invariant/regression classes, version comparison, and
  regression state.
- Merge resilience history and remove the standalone navigation item.

### Tooling

- Scope counts by organization, target, target version, surface, campaign, ScanPlan, and tool.
- Never copy organization-global evidence onto every target.
- Distinguish installed, configured, generated, executed, and evidenced/adjudicated.
- Show enabled/disabled surface state and applicability reason.
- Add immutable run/artifact links and freshness timestamps.

### Traces and Costs

- Include agent/provider calls rather than filtering them out.
- T-F18j first preserves known/partial/not-observed accounting across backend campaign and Birdseye
  projections before hosted deployment.
- T-F18p later reconciles target physical requests, provider calls, tokens, measured cost, and
  authorization caps in Costs with bounded database pagination and filters.

### Configuration and Audit

- Separate package installation, static catalog/configuration, activation, live heartbeat, and
  execution evidence.
- Never convert constructor booleans into operational evidence.
- Keep append-only Audit inside Configuration with backend permission enforcement and stable paging.

### Shared interaction quality

- Preserve backend `reason_code` and request correlation IDs.
- Add retry controls for failed reads.
- Confirm every destructive or spend-causing command through an exhaustive command registry.
- Make table-row navigation keyboard accessible.
- Normalize invalid routes.
- Add cursor pagination and stable filters to high-volume views.

## Delivery waves

### Wave A — Final-target surfaces

Execute T-F16a through T-F16f from `docs/planning/final-target-adapters.md`.

### Wave B — Hosted four-role runtime

Execute T-F17a through T-F17d, then the backend-only T-F18j bridge, then T-F17e/f from
`docs/planning/agent-runtime-provenance.md`. T-F18j is the accounting/Birdseye bridge that prevents
unknown hosted usage from becoming zero before the deployment and Agents projection land.

### Wave C — Authorization-bound tool orchestration

Execute T-F19a through T-F19e from `docs/planning/console-pages-remediation.md`.

### Wave D — Console information architecture

Execute T-F18a through T-F18p from `docs/planning/console-pages-remediation.md`.

### Wave E — Final evidence

Execute T-F18n for authenticated exact-SHA production console evidence, then T-F19f for the
separately approved final runs. T-F19f executes each final chat target sequentially:

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
one at a time. It cannot run from Railway until the owner supplies or authorizes a Runner-private
fixture binding without violating the prohibition on uploading the extracted bundle.

## Current blockers requiring owner/external state

- The production browser session must be signed in before visual/interaction audit.
- A distinct authorized Headshot approver must approve each live campaign.
- The authorized PDF bytes need an explicitly permitted Runner-private delivery mechanism.
- Production promotion requires a current-SHA deployment grant and rollback binding.
- Both GitHub and GitLab CI must be green on the exact release commit.

Until these conditions hold, the console must say **blocked** rather than imply a full scan or fully
hosted four-role execution has occurred.
