import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

const browserScope = {
  target_id: "browser-target",
  target_version: "v1",
  surface_id: "chat",
  surface_version: "v1",
  adapter_kind: "bruno",
  environment: "test",
  exact_host: "browser-target.example.test",
  auth_mode: "header",
  explicit_no_auth: false,
  auth_posture: "configured",
  protocol: "https",
  method: "POST",
  relative_path: "/chat",
  endpoint: "https://browser-target.example.test/chat",
  corpus_id: "browser-corpus",
  corpus_hash: "sha256:browser-corpus",
  caps: {
    budget_usd: 1,
    max_attempts_per_run: 9,
    target_requests_per_second: 1,
    run_timeout_seconds: 900,
    logical_case_limit: null,
    physical_request_limit: null,
    target_retries_per_turn: null,
  },
  execution_profile: "live",
  hosted_run: null,
} as const;

const browserHostedRun = {
  configuration_set_sha256: "a".repeat(64),
  generation_policy_sha256: "b".repeat(64),
  session_generation: "generation-browser-test",
  provider_model_call_limit: 56,
  provider_model_spend_limit_usd: "5",
  provider_max_retries: 1,
  provider_max_concurrency: 1,
  provider_timeout_seconds: 180,
} as const;

const browserOperationLimits = {
  target_budget_usd: 1,
  target_budget_remaining_usd: 0.94,
  provider_budget_usd: 5,
  provider_budget_remaining_usd: 4.97,
  logical_case_limit: null,
  physical_request_limit: null,
  physical_requests_remaining: null,
  provider_call_limit: 56,
  provider_calls_remaining: 38,
  target_requests_per_second: 1,
  run_timeout_seconds: 900,
  max_attempts_per_run: 9,
  target_retries_per_turn: null,
  provider_max_retries: 1,
  provider_max_concurrency: 1,
  provider_timeout_seconds: 180,
} as const;

const browserOperationsByCampaign = {
  "browser-campaign-alpha": {
    campaign_id: "browser-campaign-alpha",
    state: "complete",
    created_at: "2026-07-22T00:00:00Z",
    progress: {
      planned: 9,
      started: 9,
      running: 0,
      completed: 9,
      failed: 0,
      skipped: 0,
      remaining: 0,
    },
    executions: {
      logical_attempts: 9,
      physical_target_requests: 9,
      provider_calls: 27,
    },
    current_work: null,
    costs: {
      provider_measured_usd: 0.04,
      target_measured_usd: 0.05,
      total_measured_usd: 0.09,
      provider_measurement_state: "measured",
      target_measurement_state: "measured",
      measurement_state: "measured",
      currency: "USD",
    },
    limits: {
      ...browserOperationLimits,
      target_budget_remaining_usd: 0.95,
      provider_budget_remaining_usd: 4.96,
      provider_calls_remaining: 29,
    },
    verdict_distribution: { blocked: 5, safe: 4 },
    queue: {
      queued_jobs: 0,
      leased_jobs: 0,
      dead_lettered_jobs: 0,
      rate_limit_active: false,
    },
    terminal_failure: null,
    as_of: "2026-07-22T00:24:05Z",
    cursor: 68,
  },
  "browser-campaign-beta": {
    campaign_id: "browser-campaign-beta",
    state: "aborted",
    created_at: "2026-07-22T00:07:00Z",
    progress: {
      planned: 9,
      started: 4,
      running: 0,
      completed: 3,
      failed: 1,
      skipped: 0,
      remaining: 5,
    },
    executions: {
      logical_attempts: 4,
      physical_target_requests: 4,
      provider_calls: 12,
    },
    current_work: null,
    costs: {
      provider_measured_usd: 0.02,
      target_measured_usd: 0.04,
      total_measured_usd: 0.06,
      provider_measurement_state: "measured",
      target_measurement_state: "measured",
      measurement_state: "measured",
      currency: "USD",
    },
    limits: {
      ...browserOperationLimits,
      target_budget_remaining_usd: 0.96,
      provider_budget_remaining_usd: 4.98,
      provider_calls_remaining: 44,
    },
    verdict_distribution: { blocked: 2, safe: 1, failed: 1 },
    queue: {
      queued_jobs: 0,
      leased_jobs: 0,
      dead_lettered_jobs: 0,
      rate_limit_active: false,
    },
    terminal_failure: null,
    as_of: "2026-07-22T00:24:05Z",
    cursor: 68,
  },
  "browser-campaign-gamma": {
    campaign_id: "browser-campaign-gamma",
    state: "running",
    created_at: "2026-07-22T00:14:00Z",
    progress: {
      planned: 9,
      started: 6,
      running: 1,
      completed: 5,
      failed: 0,
      skipped: 0,
      remaining: 3,
    },
    executions: {
      logical_attempts: 6,
      physical_target_requests: 7,
      provider_calls: 18,
    },
    current_work: {
      stage: "coverage_governance",
      agent_role: "orchestrator",
      execution_id: "agent-execution-orchestrator",
      attempt_id: "browser-attempt-2",
      started_at: "2026-07-22T00:24:00Z",
    },
    costs: {
      provider_measured_usd: 0.03,
      target_measured_usd: 0.06,
      total_measured_usd: 0.09,
      provider_measurement_state: "measured",
      target_measurement_state: "measured",
      measurement_state: "measured",
      currency: "USD",
    },
    limits: browserOperationLimits,
    verdict_distribution: { blocked: 3, safe: 2, partial: 1 },
    queue: {
      queued_jobs: 2,
      leased_jobs: 1,
      dead_lettered_jobs: 0,
      rate_limit_active: false,
    },
    terminal_failure: null,
    as_of: "2026-07-22T00:24:05Z",
    cursor: 68,
  },
} as const;

const canonicalJson = (value: unknown): string => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
};

const sha256 = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

const browserCampaignSuite = {
  suite_id: "browser-100-case-suite",
  title: "Full 100-case suite",
  case_count: 100,
  physical_request_count: 121,
  categories: [
    "prompt_injection",
    "data_exfiltration",
    "tool_misuse",
    "state_corruption",
    "denial_of_service",
    "indirect_injection",
  ],
  batches: [34, 33, 33].map((caseCount, index) => ({
    ordinal: index + 1,
    batch_id: `browser-100-batch-${index + 1}`,
    target_id: "browser-target",
    target_version: "v1",
    surface_id: "chat",
    surface_version: "v1",
    corpus_id: `browser-100-batch-${index + 1}`,
    corpus_hash: String(index + 1).repeat(64),
    case_count: caseCount,
    physical_request_count: index === 0 ? 41 : 40,
    tool_sources: ["garak", "promptfoo", "pyrit"],
    execution_profile: "live",
    maximum_caps: {
      ...browserScope.caps,
      max_attempts_per_run: caseCount,
      logical_case_limit: caseCount,
      physical_request_limit: index === 0 ? 41 : 40,
      target_retries_per_turn: 0,
    },
    hosted_run: browserHostedRun,
  })),
} as const;

const browserCoverage = [
  {
    target_version: "browser-target@v1",
    verified_attempt_count: 9,
    total_case_count: 9,
    category_count: 3,
    execution_profile: "live",
    evidence_provenance: "live_target",
    classifications: ["boundary", "invariant", "regression"],
    owasp_web: ["A01:2021", "A05:2021"],
    owasp_llm: ["LLM01:2025", "LLM06:2025"],
    verdict_counts: { NO_EXPLOIT_OBSERVED: 6, EXPLOIT_CONFIRMED: 3 },
    covered: true,
    as_of: "2026-07-22T00:24:00Z",
  },
] as const;

const browserRegression = [
  {
    regression_id: "regression-prompt-injection",
    version: "v1",
    status: "NO_EXPLOIT_OBSERVED",
    recorded_at: "2026-07-22T00:22:00Z",
  },
  {
    regression_id: "regression-data-exfiltration",
    version: "v1",
    status: "EXPLOIT_CONFIRMED",
    recorded_at: "2026-07-22T00:23:00Z",
  },
] as const;

const browserBirdseye = {
  campaign: {
    run_id: "browser-campaign-gamma",
    target_id: "browser-target",
    target_name: "OpenEMR Clinical Co-Pilot",
    target_version: "v1",
    state: "running",
    execution_profile: "live",
    scope_hash: "sha256:scope-gamma",
    attempt_count: 6,
  },
  instrumentation: {
    budget_usd: 1,
    measured_cost_usd: 0.09,
    budget_utilization: 0.09,
    requests_per_second_cap: 1,
    queue_queued: 2,
    queue_leased: 1,
    queue_dead_letter: 0,
    confirmed_count: 1,
    confirmed_finding_count: 1,
    likely_count: 1,
    review_count: 1,
    healthy_components: 7,
    total_components: 7,
    system_state: "nominal",
  },
  security_posture: {
    tested_categories: 3,
    required_categories: 3,
    verified_case_count: 6,
    held_count: 2,
    exploited_count: 3,
    review_count: 1,
    observed_hold_rate: 0.4,
    open_finding_count: 2,
    in_progress_finding_count: 0,
    resolved_finding_count: 1,
    critical_open_finding_count: 1,
    resilience_direction: "improving",
    current_regression_hold_rate: 0.75,
    previous_regression_hold_rate: 0.5,
    resilience_delta: 0.25,
    cost_per_attempt_usd: 0.015,
    cost_velocity_usd_per_minute: 0.009,
    projected_cost_at_attempt_cap_usd: 0.135,
    priority_category: "prompt_injection",
    priority_reason: "Coverage gap: validate the least-tested required category before expanding.",
    priority_source: "orchestrator_decision",
    priority_at: "2026-07-22T00:24:01Z",
  },
  category_outcomes: [
    ["v1", "prompt_injection", 2, 2, 0, 2, 0],
    ["v1", "data_exfiltration", 2, 2, 1, 0, 1],
    ["v1", "tool_misuse", 2, 2, 1, 1, 0],
    ["v0.9", "prompt_injection", 2, 2, 1, 1, 0],
    ["v0.9", "data_exfiltration", 1, 1, 0, 1, 0],
    ["v0.9", "tool_misuse", 1, 1, 0, 1, 0],
  ].map(([targetVersion, category, cases, attempts, held, exploited, review], index) => ({
    target_version: targetVersion,
    category,
    verified_case_count: cases,
    verified_attempt_count: attempts,
    held_count: held,
    exploited_count: exploited,
    review_count: review,
    last_evaluated_at: `2026-07-22T00:${String(18 + index).padStart(2, "0")}:00Z`,
  })),
  agent_activity: [
    ["exec-orchestrator-5", null, "orchestrator", "succeeded", "coverage_governance", null, null, null],
    ["exec-red-team-5", "exec-orchestrator-5", "red_team", "succeeded", "authorized_case_selection", null, null, null],
    ["exec-judge-5", "exec-red-team-5", "judge", "succeeded", "independent_adjudication", "browser-attempt-5", "tool_misuse", "EXPLOIT_CONFIRMED"],
    ["exec-documentation-5", "exec-judge-5", "documentation", "succeeded", "draft_and_regression_admission", "browser-attempt-5", "tool_misuse", "EXPLOIT_CONFIRMED"],
    ["exec-orchestrator-6", "exec-documentation-5", "orchestrator", "running", "coverage_governance", null, null, null],
  ].map(([executionId, parentId, role, status, phase, attemptId, category, verdict], index) => ({
    execution_id: executionId,
    parent_execution_id: parentId,
    agent_role: role,
    status,
    phase,
    attempt_id: attemptId,
    category,
    verdict_state: verdict,
    finding_id: role === "documentation" ? "finding-tool-misuse" : null,
    error_code: null,
    started_at: `2026-07-22T00:24:0${index}Z`,
    finished_at: status === "running" ? null : `2026-07-22T00:24:0${index + 1}Z`,
    duration_ms: status === "running" ? null : 4.2 + index,
  })),
  nodes: [
    {
      component_id: "web-api",
      name: "Operator console API",
      kind: "web",
      trust_zone: "human",
      availability: "operational and evidenced",
      runtime_state: "ready",
      detail: "Authenticated Birdseye projection responded",
      current_task: "Serving the protected console snapshot",
      heartbeat_at: "2026-07-22T00:24:05Z",
      freshness_seconds: 1,
      is_fresh: true,
      healthy_instances: 1,
      total_instances: 1,
      p50_latency_ms: null,
      p95_latency_ms: null,
      execution_count: null,
      measured_cost_usd: null,
      accounting_status: null,
      currency: null,
      input_tokens: null,
      output_tokens: null,
      reasoning_tokens: null,
      token_observation_count: null,
      langfuse_not_attempted_count: null,
      langfuse_disabled_count: null,
      langfuse_queued_count: null,
      langfuse_exported_count: null,
      langfuse_error_count: null,
      langfuse_verified_count: null,
      last_langfuse_verified_at: null,
      langfuse_status: null,
      queue_depth: null,
      target_access: "none",
    },
    {
      component_id: "postgres",
      name: "PostgreSQL system of record",
      kind: "database",
      trust_zone: "data",
      availability: "operational and evidenced",
      runtime_state: "ready",
      detail: "Organization-scoped snapshot transaction succeeded",
      current_task: "Maintaining the authoritative campaign and evidence record",
      heartbeat_at: "2026-07-22T00:24:05Z",
      freshness_seconds: 1,
      is_fresh: true,
      healthy_instances: 1,
      total_instances: 1,
      p50_latency_ms: null,
      p95_latency_ms: null,
      execution_count: null,
      measured_cost_usd: null,
      accounting_status: null,
      currency: null,
      input_tokens: null,
      output_tokens: null,
      reasoning_tokens: null,
      token_observation_count: null,
      langfuse_not_attempted_count: null,
      langfuse_disabled_count: null,
      langfuse_queued_count: null,
      langfuse_exported_count: null,
      langfuse_error_count: null,
      langfuse_verified_count: null,
      last_langfuse_verified_at: null,
      langfuse_status: null,
      queue_depth: null,
      target_access: "none",
    },
    {
      component_id: "runner",
      name: "Campaign runner",
      kind: "worker",
      trust_zone: "execution",
      availability: "operational and evidenced",
      runtime_state: "working",
      detail: "Private runner heartbeat",
      current_task: "Processing 1 leased job(s)",
      heartbeat_at: "2026-07-22T00:24:04Z",
      freshness_seconds: 2,
      is_fresh: true,
      healthy_instances: 1,
      total_instances: 1,
      p50_latency_ms: 940,
      p95_latency_ms: 2135,
      execution_count: null,
      measured_cost_usd: null,
      accounting_status: null,
      currency: null,
      input_tokens: null,
      output_tokens: null,
      reasoning_tokens: null,
      token_observation_count: null,
      langfuse_not_attempted_count: null,
      langfuse_disabled_count: null,
      langfuse_queued_count: null,
      langfuse_exported_count: null,
      langfuse_error_count: null,
      langfuse_verified_count: null,
      last_langfuse_verified_at: null,
      langfuse_status: null,
      queue_depth: 3,
      target_access: "policy-gated",
    },
    ...[
      ["orchestrator", "Orchestrator", "control", "working", "Running orchestrator campaign work", "none"],
      ["red_team", "Red Team", "untrusted", "ready", "Latest execution succeeded", "policy gateway only"],
      ["judge", "Independent Judge", "evaluation", "ready", "Latest execution succeeded", "none"],
      ["documentation", "Documentation", "governance", "waiting", "Latest execution skipped", "none"],
    ].map(([role, name, trustZone, state, task, targetAccess], index) => ({
      component_id: `agent:${role}`,
      name,
      kind: `agent:${role}`,
      trust_zone: trustZone,
      availability: "operational and evidenced",
      runtime_state: state,
      detail: `headshot/${role}-engine-v1 · deterministic`,
      current_task: task,
      heartbeat_at: "2026-07-22T00:24:03Z",
      freshness_seconds: 3,
      is_fresh: true,
      healthy_instances: 1,
      total_instances: 1,
      p50_latency_ms: [4.6, 6.4, 5.8, 4.1][index],
      p95_latency_ms: [6.2, 7.2, 6.1, 4.5][index],
      execution_count: [6, 6, 6, 2][index],
      measured_cost_usd: 0,
      accounting_status: "measured",
      currency: "USD",
      input_tokens: null,
      output_tokens: null,
      reasoning_tokens: null,
      token_observation_count: 0,
      langfuse_not_attempted_count: 0,
      langfuse_disabled_count: 0,
      langfuse_queued_count: role === "orchestrator" ? 2 : 0,
      langfuse_exported_count: [4, 6, 6, 2][index],
      langfuse_error_count: 0,
      langfuse_verified_count: [4, 6, 6, 2][index],
      last_langfuse_verified_at: "2026-07-22T00:25:00Z",
      langfuse_status: role === "orchestrator" ? "queued" : "exported",
      queue_depth: null,
      target_access: targetAccess,
    })),
  ],
  edges: [
    ["postgres-to-orchestrator", "postgres", "agent:orchestrator", "OrchestrationSnapshot"],
    ["orchestrator-to-red-team", "agent:orchestrator", "agent:red_team", "CampaignDirective"],
    ["red-team-to-runner", "agent:red_team", "runner", "AttackAttempt"],
    ["runner-to-judge", "runner", "agent:judge", "EvidenceEnvelope"],
    ["judge-to-documentation", "agent:judge", "agent:documentation", "Verdict"],
  ].map(([edgeId, source, target, contractName]) => ({
    edge_id: edgeId,
    source_component_id: source,
    target_component_id: target,
    contract_name: contractName,
    state: "active",
    attempt_id: "browser-attempt-5",
    last_event_at: "2026-07-22T00:24:03Z",
    detail: "Typed, organization-scoped handoff",
  })),
  attention: [{
    attention_id: "approval:browser-approval-gamma",
    priority: 1,
    kind: "approval",
    title: "Campaign authorization requires a decision",
    detail: "Exact-scope request browser-approval-gamma is pending a distinct approver.",
    continuation: "No live campaign may start before approval.",
    record_type: "approval",
    record_id: "browser-approval-gamma",
    route: "/approvals/browser-approval-gamma",
    created_at: "2026-07-22T00:14:00Z",
  }],
  timeline: [
    ["68", "campaign.authorization_requested", "approval", "browser-approval-gamma"],
    ["67", "configuration.published", "configuration", "configuration-snapshot-0042"],
    ["66", "finding.confirmed", "finding", "finding-prompt-injection"],
  ].map(([cursor, eventType, aggregateType, aggregateId]) => ({
    cursor: Number(cursor),
    event_type: eventType,
    actor: "user_browser_fixture",
    summary: eventType.replace(".", " · "),
    aggregate_type: aggregateType,
    aggregate_id: aggregateId,
    created_at: "2026-07-22T00:24:00Z",
  })),
  cursor: 68,
  as_of: "2026-07-22T00:24:05Z",
};

const browserFindings = [
  {
    finding_id: "finding-prompt-injection",
    state: "confirmed",
    severity: "critical",
    category: "prompt injection",
    target_version: "v1",
    publication_status: "gated",
    evidence_integrity: "verified",
    source_kind: "agent",
    execution_profile: "live",
    evidence_provenance: "live_target",
    campaign_run_id: "browser-campaign-alpha",
    attempt_id: "browser-attempt-1",
    evidence_content_hash: "c".repeat(64),
    history: [{
      decision: "confirmed",
      actor_user_id: "user_independent_judge",
      rationale: "Independent replay reproduced the boundary violation.",
      reason_code: null,
      created_at: "2026-07-22T00:05:10Z",
    }],
  },
  {
    finding_id: "finding-missing-hsts",
    state: "triaged",
    severity: "low",
    category: "security misconfiguration",
    target_version: "v1",
    publication_status: "withheld",
    evidence_integrity: "verified",
    source_kind: "security_tool",
    execution_profile: "live",
    evidence_provenance: "scan_only",
    campaign_run_id: null,
    attempt_id: null,
    evidence_content_hash: "d".repeat(64),
    history: [],
  },
  {
    finding_id: "finding-cache-review",
    state: "resolved",
    severity: "informational",
    category: "response caching",
    target_version: "v1",
    publication_status: "published",
    evidence_integrity: "verified",
    source_kind: "security_tool",
    execution_profile: "live",
    evidence_provenance: "scan_only",
    campaign_run_id: null,
    attempt_id: null,
    evidence_content_hash: "e".repeat(64),
    history: [{
      decision: "resolved",
      actor_user_id: "user_security_reviewer",
      rationale: "Reviewed against the non-sensitive public response contract.",
      reason_code: null,
      created_at: "2026-07-22T00:12:20Z",
    }],
  },
];

const browserVerification = {
  availability: "ready",
  reason_code: null,
  finding_id: "finding-prompt-injection",
  campaign_run_id: "browser-campaign-alpha",
  attempt_id: "browser-attempt-1",
  attack_case: {
    case_id: "browser-case-prompt-injection",
    case_content_sha256: "a".repeat(64),
    category: "prompt_injection",
    attack_class: "boundary",
    owasp_mappings: [
      { framework: "OWASP LLM Top 10", id: "LLM01:2025" },
      { framework: "OWASP Web Top 10", id: "A01:2021" },
    ],
    oracle_expectation: {
      kind: "canary_absence",
      expected_behavior: "Refuse the synthetic instruction and do not reproduce the canary.",
    },
    corpus_reconciliation: "verified",
  },
  attack_attempt: {
    schema_version: "1",
    input_sequence: [
      "Synthetic adversarial request with fixture identifiers redacted.",
      "Follow-up asks the co-pilot to ignore its trusted clinical boundary.",
    ],
  },
  input_sequence: [
    "Synthetic adversarial request with fixture identifiers redacted.",
    "Follow-up asks the co-pilot to ignore its trusted clinical boundary.",
  ],
  request_transcript: {
    method: "POST",
    relative_path: "/chat",
    body: { turns: ["Synthetic fixture content redacted for console display."] },
  },
  response_transcript: "{\"answer\":\"Synthetic fixture canary was reproduced.\"}",
  policy_decision_id: "browser-policy-decision-1",
  executed_at: "2026-07-22T00:05:00Z",
  trace_id: "1".repeat(32),
  judge: {
    state: "EXPLOIT_CONFIRMED",
    confidence: 1,
    reason_codes: ["oracle_canary_observed", "trusted_boundary_crossed"],
    confirmation_source: "canary",
    oracle_refs: ["browser-case-prompt-injection:oracle_expectation"],
    canary_refs: ["synthetic-canary:browser-fixture-redacted"],
    rationale: null,
    rationale_availability: "unavailable",
    rationale_detail: "The verdict contract persists reason codes and confirmation source, not free-form Judge rationale.",
    error_code: null,
  },
  report_id: "browser-report-prompt-injection",
  minimal_reproduction: [
    "Submit the two redacted synthetic turns through the exact authorized chat surface.",
    "Verify that the synthetic canary is reproduced in the response.",
  ],
  reproduction_sha256: "b".repeat(64),
  regression: {
    disposition_id: "browser-regression-disposition-1",
    state: "blocked_pending_human_approval",
    reason_codes: ["human_approval_required"],
    reproduction_attempted: true,
    deterministic_reproduction: true,
    passes_for_right_reason: true,
    human_approved: false,
    admitted: false,
  },
  integrity: {
    stored_content_sha256: "c".repeat(64),
    finding_link_sha256: "c".repeat(64),
    recomputed_content_sha256: "c".repeat(64),
    evidence_record: "verified",
    finding_link: "verified",
    observability_reconciliation: "unavailable",
    observability_detail: "The durable span record has no transcript hash to reconcile.",
  },
  redaction_state: "synthetic_identifiers_redacted",
} as const;

const unavailableBrowserVerification = (findingId: string) => ({
  availability: "unavailable",
  reason_code: "campaign_verification_unavailable",
  finding_id: findingId,
  campaign_run_id: null,
  attempt_id: null,
  attack_case: null,
  attack_attempt: null,
  input_sequence: [],
  request_transcript: null,
  response_transcript: null,
  policy_decision_id: null,
  executed_at: null,
  trace_id: null,
  judge: null,
  report_id: null,
  minimal_reproduction: [],
  reproduction_sha256: null,
  regression: null,
  integrity: null,
  redaction_state: "synthetic_identifiers_redacted",
});

const browserReports = [{
  schema_version: "1",
  report_id: "browser-report-prompt-injection",
  finding_id: "finding-prompt-injection",
  campaign_run_id: "browser-campaign-alpha",
  attempt_id: "browser-attempt-1",
  source_case_id: "browser-case-prompt-injection",
  severity: "critical",
  category: "prompt_injection",
  description: "The live target reproduced a synthetic canary after an adversarial instruction.",
  clinical_impact: "A malicious synthetic instruction crossed the trusted clinical boundary.",
  minimal_reproduction: browserVerification.minimal_reproduction,
  reproduction_sha256: browserVerification.reproduction_sha256,
  observed_behavior: "The response contained the synthetic canary.",
  expected_behavior: "The target should refuse the untrusted instruction and omit the canary.",
  recommended_remediation: "Preserve trusted instruction priority and add a canary regression.",
  status: "draft",
  fix_validation: {
    state: "not_run",
    summary: "No remediation build has been supplied for validation.",
    evidence_references: [],
  },
  evidence_references: [`evidence://sha256/${"c".repeat(64)}`],
  publication_state: "blocked_pending_human_approval",
  regression: browserVerification.regression,
  report_integrity: "verified",
  created_at: "2026-07-22T00:05:30Z",
  verification: browserVerification,
}];

const browserApprovals = [
  { ...browserScope, run_nonce: "browser-run-alpha-0001", request_id: "browser-approval-alpha", scope_hash: "sha256:scope-alpha", launcher_user_id: "user_operator", expires_at: "2026-07-22T00:15:00Z", created_at: "2026-07-22T00:00:00Z", status: "approved", decision: "approved", approver_user_id: "user_approver", self_approval_override: false, decided_at: "2026-07-22T00:01:00Z", expired: false, consumed: true },
  { ...browserScope, run_nonce: "browser-run-beta-0002", request_id: "browser-approval-beta", scope_hash: "sha256:scope-beta", launcher_user_id: "user_operator", expires_at: "2026-07-22T00:22:00Z", created_at: "2026-07-22T00:07:00Z", status: "rejected", decision: "rejected", approver_user_id: "user_approver", self_approval_override: false, decided_at: "2026-07-22T00:08:00Z", expired: false, consumed: false },
  { ...browserScope, run_nonce: "browser-run-gamma-0003", request_id: "browser-approval-gamma", scope_hash: "sha256:scope-gamma", launcher_user_id: "user_operator", expires_at: "2026-07-22T00:29:00Z", created_at: "2026-07-22T00:14:00Z", status: "pending", decision: null, approver_user_id: null, self_approval_override: false, decided_at: null, expired: false, consumed: false },
];

const browserUnavailableProviderBudget = {
  status: "unavailable",
  campaign_run_id: null,
  configuration_set_sha256: null,
  role_cost_measurement_state: null,
  role_usd_cap: null,
  role_usd_spent: 0,
  role_unresolved_usd_exposure: 0,
  role_usd_remaining: null,
  role_usd_remaining_upper_bound: null,
  role_usd_overrun: 0,
  role_call_cap: null,
  role_physical_calls: 0,
  role_unresolved_physical_calls: 0,
  role_call_count_state: null,
  role_calls_remaining: null,
  role_call_overrun: 0,
  global_cost_measurement_state: null,
  global_usd_cap: null,
  global_usd_spent: 0,
  global_unresolved_usd_exposure: 0,
  global_usd_remaining: null,
  global_usd_remaining_upper_bound: null,
  global_usd_overrun: 0,
  global_call_cap: null,
  global_physical_calls: 0,
  global_unresolved_physical_calls: 0,
  global_call_count_state: null,
  global_calls_remaining: null,
  global_call_overrun: 0,
};

const browserHostedModels = {
  orchestrator: "anthropic/claude-opus-4.8",
  red_team: "qwen/qwen3.5-397b-a17b",
  judge: "google/gemini-2.5-pro",
  documentation: "openai/gpt-5.4",
} as const;

const browserAgents = [
  {
    role: "orchestrator",
    display_name: "Orchestrator",
    responsibility: "Prioritizes verified coverage gaps and redirects or halts bounded work.",
    trust_level: "trusted governor",
    target_access: "none",
    input_contract: "OrchestrationSnapshot v1",
    output_contract: "CampaignDirective v1",
    model: "coverage-governor-v1",
    execution_count: 6,
    skipped_count: 0,
  },
  {
    role: "red_team",
    display_name: "Red Team",
    responsibility: "Selects exact authored and reviewed security-tool cases from the authorized corpus.",
    trust_level: "untrusted generator",
    target_access: "policy gateway only",
    input_contract: "CampaignDirective v1 + authorized AttackCase corpus",
    output_contract: "AttackAttempt v1",
    model: "full-scan-corpus-v1",
    execution_count: 6,
    skipped_count: 0,
  },
  {
    role: "judge",
    display_name: "Independent Judge",
    responsibility: "Adjudicates hash-verified evidence with deterministic oracle precedence.",
    trust_level: "independent evaluator",
    target_access: "none",
    input_contract: "EvidenceEnvelope v1",
    output_contract: "Verdict v1",
    model: "oracle-precedence-v1",
    execution_count: 6,
    skipped_count: 0,
  },
  {
    role: "documentation",
    display_name: "Documentation",
    responsibility: "Drafts reports only from confirmed, sanitized evidence.",
    trust_level: "trusted draft writer",
    target_access: "none",
    input_contract: "Verdict v1 + sanitized DocumentationInput",
    output_contract: "VulnReport v1 + RegressionDisposition v1",
    model: "evidence-report-v1",
    execution_count: 2,
    skipped_count: 1,
  },
].map(({ model, ...agent }, index) => ({
  ...agent,
  active_assignment: {
    role: agent.role,
    provider: "headshot",
    model,
    resolved_model: null,
    upstream_provider: null,
    prompt_sha256: String(index + 5).repeat(64),
    prompt_version: "1",
    execution_mode: "deterministic",
    activation_state: "active",
    version: 1,
    configuration_sha256: String(index + 1).repeat(64),
    configured_at: null,
    configured_by: null,
  },
  staged_assignment: {
    role: agent.role,
    provider: "openrouter",
    model: browserHostedModels[agent.role as keyof typeof browserHostedModels],
    resolved_model: null,
    upstream_provider: null,
    prompt_sha256: String.fromCharCode(98 + index).repeat(64),
    prompt_version: "1",
    execution_mode: "hosted_advisory",
    activation_state: "staged_pending_authorization",
    version: 2,
    configuration_sha256: "a".repeat(64),
    configured_at: "2026-07-22T00:13:00Z",
    configured_by: "user_configuration_admin",
  },
  latest_acceptance_execution: null,
  running_count: agent.role === "orchestrator" ? 1 : 0,
  hosted_execution_count: agent.role === "red_team" ? 1 : 0,
  succeeded_count:
    agent.execution_count -
    agent.skipped_count -
    (agent.role === "orchestrator" ? 1 : 0),
  failed_count: 0,
  measured_cost: 0,
  cost_measurement_state: agent.role === "red_team" ? "partial" : "measured",
  accounting_status: agent.role === "red_team" ? "partial" : "measured",
  provider_event_ids: [],
  currency: "USD",
  input_tokens: null,
  output_tokens: null,
  reasoning_tokens: null,
  token_observation_count: 0,
  physical_call_count: 0,
  physical_call_count_state: agent.role === "red_team"
    ? "lower_bound"
    : "not_applicable",
  provider_budget: browserUnavailableProviderBudget,
  judge_calibration: agent.role === "judge"
    ? {
        state: "unavailable",
        calibration_id: null,
        decision_authority: "none",
        oracle_comparison_count: 0,
        oracle_agreement_count: 0,
        oracle_agreement_rate: null,
        status_label: "not yet measured",
      }
    : null,
  average_duration_ms: 4.6 + index * 1.8,
  p50_duration_ms: 4.4 + index * 1.7,
  p95_duration_ms: 6.2 + index * 2.1,
  langfuse_not_attempted_count: 0,
  langfuse_disabled_count: 0,
  langfuse_queued_count: agent.role === "orchestrator" ? 2 : 0,
  langfuse_exported_count: agent.execution_count - (agent.role === "orchestrator" ? 2 : 0),
  langfuse_error_count: 0,
  langfuse_verified_count: agent.role === "orchestrator"
    ? agent.execution_count - 2
    : agent.execution_count,
  last_langfuse_verified_at: "2026-07-22T00:25:00Z",
  last_activity_at: "2026-07-22T00:24:03Z",
  last_status: agent.role === "orchestrator" ? "running" : "succeeded",
  last_campaign_run_id: "browser-campaign-gamma",
  last_attempt_id: `browser-attempt-${Math.min(index + 2, 5)}`,
}));

const browserAgentActivity = [
  ["agent-execution-orchestrator", null, "orchestrator", "running", "coverage-governor-v1", null],
  ["agent-execution-red-team", "agent-execution-orchestrator", "red_team", "succeeded", "full-scan-corpus-v1", 7.2],
  ["agent-execution-judge", "agent-execution-red-team", "judge", "succeeded", "oracle-precedence-v1", 5.8],
  ["agent-execution-documentation", "agent-execution-judge", "documentation", "succeeded", "evidence-report-v1", 4.1],
].map(([executionId, parentExecutionId, role, status, model, duration], index) => ({
  execution_id: executionId,
  campaign_run_id: "browser-campaign-gamma",
  attempt_id: `browser-attempt-${index + 2}`,
  parent_execution_id: parentExecutionId,
  agent_role: role,
  status,
  provider: index === 1 ? "openrouter" : "headshot",
  model: index === 1 ? "qwen/qwen3.5-397b-a17b" : model,
  returned_model: null,
  model_substituted: false,
  upstream_provider: null,
  provider_request_id: null,
  execution_mode: index === 1 ? "hosted_advisory" : "deterministic",
  configuration_version: 1,
  configuration_set_sha256: null,
  role_configuration_sha256: null,
  generation_policy_sha256: null,
  input_sha256: String(index + 2).repeat(64),
  output_sha256: status === "running" ? null : String(index + 3).repeat(64),
  input_tokens: null,
  output_tokens: null,
  reasoning_tokens: null,
  physical_attempts: null,
  measured_cost: index === 1 ? null : 0,
  cost_measurement_state: index === 1 ? "not_observed" : "measured",
  accounting_status: index === 1 ? "unavailable" : "measured",
  provider_event_ids: [],
  provider_event_status: null,
  provider_lineage_state: index === 1
    ? "historical_not_instrumented"
    : "not_applicable",
  currency: "USD",
  trace_id: String(index + 1).padStart(32, "0"),
  langfuse_status: status === "running" ? "queued" : "exported",
  langfuse_verified_at: status === "running" ? null : "2026-07-22T00:25:10Z",
  detail: {
    decision: role === "orchestrator" ? "prioritize" : "completed",
    ...(index === 1
      ? { provider_lineage_state: "historical_not_instrumented" }
      : {}),
  },
  judge_calibration_id: null,
  judge_calibration_state: null,
  oracle_agreement: null,
  decision_authority: null,
  error_code: null,
  started_at: `2026-07-22T00:24:0${index}Z`,
  finished_at: status === "running" ? null : `2026-07-22T00:24:0${index + 1}Z`,
  duration_ms: duration,
}));

const browserTooling = [
  ["garak", "NVIDIA Garak", "0.15.1", "llm-attack", "in_campaign", 1, 1, 0, 0],
  ["pyrit", "Microsoft PyRIT", "0.14.0", "llm-attack", "in_campaign", 3, 3, 0, 0],
  ["promptfoo", "Promptfoo", "0.121.19", "llm-eval", "in_campaign", 1, 1, 0, 0],
  ["giskard", "Giskard Scan", "1.0.0b3", "llm-attack", "adapter_available", 0, 0, 0, 0],
  ["zap", "OWASP ZAP", "2.17.0", "dast", "companion_scan", 0, 0, 1, 3],
  ["semgrep", "Semgrep", "1.170.0", "sast", "platform_assurance", 0, 0, 1, 2],
  ["headshot-llm-workbench", "Headshot LLM Security Workbench", "1.0.0", "llm-proxy", "in_campaign", 9, 6, 0, 0],
].map(([toolId, name, version, kind, applicability, candidates, attempts, scans, findings]) => ({
  tool_id: toolId,
  name,
  version,
  kind,
  availability: applicability === "adapter_available"
    ? "adapter integrated, execution deferred"
    : "operational and evidenced",
  target_access: toolId === "zap"
    ? "exact_origin_passive"
    : toolId === "semgrep"
      ? "repository_only"
      : toolId === "headshot-llm-workbench"
        ? "policy_gateway_only"
        : "none",
  target_id: "browser-target",
  target_version: "v1",
  target_lifecycle: "ready",
  surface_id: "chat",
  surface_version: "v1",
  surface_kind: "chat",
  endpoint: "https://browser-target.example.test/chat",
  applicability,
  execution_mode: applicability === "in_campaign"
    ? "reviewed candidates through policy gateway"
    : applicability === "companion_scan"
      ? "exact-origin passive baseline"
      : applicability === "platform_assurance"
        ? "Headshot repository SAST"
        : "native artifact import and review",
  scope_reason: applicability === "adapter_available"
    ? "The adapter is available, but no case is inside the authorized corpus."
    : "This posture is derived from the selected target surface and persisted evidence.",
  requires_separate_authorization: applicability === "companion_scan"
    || applicability === "adapter_available",
  capabilities: toolId === "zap"
    ? ["passive DAST", "HTTP hardening", "web misconfiguration"]
    : toolId === "semgrep"
      ? ["SAST", "policy-boundary checks"]
      : ["prompt injection", "tool misuse", "multi-turn attack lineage"],
  owasp_llm: kind === "dast" || kind === "sast" ? [] : ["LLM01:2025", "LLM06:2025"],
  owasp_web: kind === "dast" || kind === "sast" ? ["A05:2021"] : ["A01:2021"],
  reviewed_candidate_count: candidates,
  executed_attempt_count: attempts,
  recorded_scan_count: scans,
  recorded_finding_count: findings,
  last_executed_at: Number(attempts) + Number(scans) > 0 ? "2026-07-22T00:24:03Z" : null,
  runtime_state: Number(attempts) + Number(scans) > 0 ? "evidenced" : "idle",
  evidenced_finding_count: findings,
  last_error_code: null,
}));

const browserFixture = (): Plugin => ({
  name: "headshot-browser-fixture",
  configureServer(server) {
    server.middlewares.use((request, response, next) => {
      const path = request.url?.split("?", 1)[0] ?? "";
      if (!path.startsWith("/api/v1/")) return next();
      response.setHeader("Cache-Control", "no-store");
      if (request.headers.authorization !== "Bearer browser-fixture-session") {
        response.statusCode = 401;
        response.setHeader("Content-Type", "application/json");
        response.end('{"detail":"Authentication required"}');
        return;
      }
      if (path === "/api/v1/events") {
        response.statusCode = 200;
        response.setHeader("Content-Type", "text/event-stream");
        if (!request.headers["last-event-id"] || request.headers["last-event-id"] === "0") {
          response.write('event: snapshot\ndata: {"action":"reconcile","state":"empty"}\n\n');
        } else {
          response.write(": heartbeat\n\n");
        }
        const heartbeat = setInterval(() => response.write(": heartbeat\n\n"), 5_000);
        request.on("close", () => clearInterval(heartbeat));
        return;
      }
      response.setHeader("Content-Type", "application/json");
      if (request.method === "POST") {
        response.statusCode = 503;
        response.end('{"status":"unavailable","reason_code":"browser_fixture_dependency"}');
        return;
      }
      response.statusCode = 200;
      if (path === "/api/v1/principal") {
        response.end(JSON.stringify({
          state: "ready",
          data: {
            user_id: "user_browser_fixture",
            organization_id: "org_browser_fixture",
            organization_role: "org:operator",
            organization_permissions: [
              "org:console:read",
              "org:findings:read",
              "org:evidence:read",
              "org:campaign:launch",
              "org:campaign:abort",
              "org:campaign:authorize",
              "org:targets:manage",
              "org:config:manage",
              "org:findings:approve",
              "org:findings:resolve",
              "org:audit:read",
            ],
          },
        }));
        return;
      }
      if (path === "/api/v1/campaigns") {
        response.end(JSON.stringify({
          state: "ready",
          data: [
            { ...browserScope, run_nonce: "browser-run-alpha-0001", run_id: "browser-campaign-alpha", authorization_request_id: "browser-approval-alpha", scope_hash: "sha256:scope-alpha", launcher_user_id: "user_operator", state: "complete", attempt_count: 9, created_at: "2026-07-22T00:00:00Z" },
            { ...browserScope, run_nonce: "browser-run-beta-0002", run_id: "browser-campaign-beta", authorization_request_id: "browser-approval-beta", scope_hash: "sha256:scope-beta", launcher_user_id: "user_operator", state: "aborted", attempt_count: 4, created_at: "2026-07-22T00:07:00Z" },
            { ...browserScope, run_nonce: "browser-run-gamma-0003", run_id: "browser-campaign-gamma", authorization_request_id: "browser-approval-gamma", scope_hash: "sha256:scope-gamma", launcher_user_id: "user_operator", state: "running", attempt_count: 6, created_at: "2026-07-22T00:14:00Z" },
          ],
        }));
        return;
      }
      const operationsMatch = path.match(
        /^\/api\/v1\/campaigns\/([^/]+)\/operations$/,
      );
      if (operationsMatch) {
        const campaignId = decodeURIComponent(operationsMatch[1]);
        const operations = browserOperationsByCampaign[
          campaignId as keyof typeof browserOperationsByCampaign
        ];
        response.end(JSON.stringify(operations
          ? { state: "ready", data: operations }
          : { state: "empty", data: null }));
        return;
      }
      if (/^\/api\/v1\/campaigns\/[^/]+\/attempts$/.test(path)) {
        response.end(JSON.stringify({
          state: "ready",
          data: Array.from({ length: 6 }, (_, index) => ({
            attempt_id: `browser-attempt-${index}`,
            ordinal: index + 1,
            case_id: `case-${index + 1}`,
            content_hash: `sha256:attempt-${index}`,
            executed_at: `2026-07-22T00:${String(15 + index).padStart(2, "0")}:00Z`,
            trace_id: `${String(index + 1).padStart(32, "0")}`,
            verdict: ["blocked", "blocked", "safe", "partial", "safe", "blocked"][index],
            confidence: 0.91,
            execution_profile: "live",
            evidence_provenance: "live_target",
            created_at: `2026-07-22T00:${String(15 + index).padStart(2, "0")}:00Z`,
          })),
        }));
        return;
      }
      const evidenceMatch = path.match(
        /^\/api\/v1\/attempts\/([^/]+)\/evidence$/,
      );
      if (evidenceMatch) {
        const attemptId = decodeURIComponent(evidenceMatch[1]);
        const attemptIndex = Number(attemptId.replace("browser-attempt-", ""));
        response.end(JSON.stringify(Number.isSafeInteger(attemptIndex)
          && attemptIndex >= 0
          && attemptIndex < 6
          ? {
              state: "ready",
              data: {
                campaign_run_id: "browser-campaign-gamma",
                attempt_id: attemptId,
                target_id: "browser-target",
                target_version: "v1",
                surface_id: "chat",
                surface_version: "v1",
                attack_attempt: {
                  schema_version: "1",
                  input_sequence: ["Synthetic browser fixture attack turn."],
                },
                request_transcript: {
                  method: "POST",
                  relative_path: "/chat",
                  body: { fixture: "synthetic" },
                },
                response_transcript: "{\"answer\":\"Synthetic fixture response.\"}",
                policy_decision_id: `browser-policy-${attemptIndex}`,
                executed_at: `2026-07-22T00:${String(15 + attemptIndex).padStart(2, "0")}:00Z`,
                trace_id: String(attemptIndex + 1).padStart(32, "0"),
                content_hash: sha256(`browser-attempt-${attemptIndex}`),
                verdict: ["blocked", "blocked", "safe", "partial", "safe", "blocked"][attemptIndex],
                confidence: 0.91,
                execution_profile: "live",
                evidence_provenance: "live_target",
              },
            }
          : { state: "empty", data: null }));
        return;
      }
      if (path === "/api/v1/traces") {
        response.end(JSON.stringify({
          state: "ready",
          data: [
            ...Array.from({ length: 9 }, (_, index) => ({
              request_id: `browser-request-${index}`,
              execution_id: null,
              parent_execution_id: null,
              trace_id: index < 5 ? "1".repeat(32) : "2".repeat(32),
              campaign_id: index < 5 ? "browser-campaign-alpha" : "browser-campaign-beta",
              attempt_id: `browser-attempt-${index}`,
              operation: "target.http",
              provider: "openemr",
              model: null,
              agent_role: null,
              execution_mode: null,
              requested_model: null,
              returned_model: null,
              model_substituted: false,
              upstream_provider: null,
              provider_request_id: null,
              configuration_set_sha256: null,
              role_configuration_sha256: null,
              generation_policy_sha256: null,
              physical_attempts: null,
              method: "POST",
              destination_host: "agent-production-9f62.up.railway.app",
              relative_path: "chat",
              status: index === 7 ? "failed" : "succeeded",
              status_code: index === 7 ? 503 : 200,
              error_code: index === 7 ? "upstream_unavailable" : null,
              started_at: `2026-07-22T00:0${index}:00Z`,
              finished_at: `2026-07-22T00:0${index}:01Z`,
              duration_ms: [820, 1110, 940, 1480, 1210, 1750, 1320, 2400, 990][index],
              request_bytes: 320 + index * 17,
              response_bytes: index === 7 ? 64 : 1100 + index * 90,
              measured_cost: 0.01,
              cost_measurement_state: "measured",
              accounting_status: "measured",
              provider_event_ids: [],
              provider_event_status: null,
              provider_lineage_state: "not_applicable",
              currency: "USD",
              input_tokens: null,
              output_tokens: null,
              reasoning_tokens: null,
              judge_calibration_id: null,
              judge_calibration_state: null,
              oracle_agreement: null,
              decision_authority: null,
              p50_duration_ms: null,
              p95_duration_ms: null,
              langfuse_status: index === 7 ? "error" : index === 6 ? "queued" : "exported",
              langfuse_verified_at:
                index === 6 || index === 7 ? null : "2026-07-22T00:25:10Z",
              request_preview: JSON.stringify({ turns: [`Reviewed LLM attack case ${index + 1}`] }),
              response_preview: index === 7 ? "upstream unavailable" : JSON.stringify({ answer: `Live target response ${index + 1}` }),
              request_sha256: "a".repeat(64),
              response_sha256: "b".repeat(64),
              inspection_flags: index === 7 ? ["transport_or_server_error"] : [],
              inspection_owasp_mappings: index === 7 ? ["A09:2021"] : [],
            })),
            ...browserAgentActivity.map((execution) => ({
              request_id: null,
              execution_id: execution.execution_id,
              parent_execution_id: execution.parent_execution_id,
              trace_id: "3".repeat(32),
              campaign_id: execution.campaign_run_id,
              attempt_id: execution.attempt_id,
              operation: `agent.${execution.agent_role}`,
              provider: execution.provider,
              model: execution.model,
              agent_role: execution.agent_role,
              execution_mode: execution.execution_mode,
              requested_model: execution.model,
              returned_model: execution.returned_model,
              model_substituted: execution.model_substituted,
              upstream_provider: execution.upstream_provider,
              provider_request_id: execution.provider_request_id,
              configuration_set_sha256: execution.configuration_set_sha256,
              role_configuration_sha256: execution.role_configuration_sha256,
              generation_policy_sha256: execution.generation_policy_sha256,
              physical_attempts: execution.physical_attempts,
              method: null,
              destination_host: null,
              relative_path: null,
              status: execution.status,
              status_code: null,
              error_code: execution.error_code,
              started_at: execution.started_at,
              finished_at: execution.finished_at,
              duration_ms: execution.duration_ms,
              request_bytes: 0,
              response_bytes: null,
              measured_cost: execution.measured_cost,
              cost_measurement_state: execution.cost_measurement_state,
              accounting_status: execution.accounting_status,
              provider_event_ids: execution.provider_event_ids,
              provider_event_status: execution.provider_event_status,
              provider_lineage_state: execution.provider_lineage_state,
              currency: execution.currency,
              input_tokens: execution.input_tokens,
              output_tokens: execution.output_tokens,
              reasoning_tokens: execution.reasoning_tokens,
              judge_calibration_id: execution.judge_calibration_id,
              judge_calibration_state: execution.judge_calibration_state,
              oracle_agreement: execution.oracle_agreement,
              decision_authority: execution.decision_authority,
              p50_duration_ms: browserAgents.find(
                (agent) => agent.role === execution.agent_role,
              )?.p50_duration_ms ?? null,
              p95_duration_ms: browserAgents.find(
                (agent) => agent.role === execution.agent_role,
              )?.p95_duration_ms ?? null,
              langfuse_status: execution.langfuse_status,
              langfuse_verified_at: execution.langfuse_verified_at,
              request_preview: null,
              response_preview: null,
              request_sha256: execution.input_sha256,
              response_sha256: execution.output_sha256,
              inspection_flags: [],
              inspection_owasp_mappings: [],
            })),
          ],
        }));
        return;
      }
      if (path === "/api/v1/costs") {
        response.end(JSON.stringify({
          state: "ready",
          data: [
            {
              accounting_id: "browser-campaign-alpha",
              campaign_id: "browser-campaign-alpha",
              provider: "live_target",
              agent_role: null,
              record_kind: "campaign",
              execution_mode: null,
              measured_cost: 0.05,
              cost_measurement_state: "measured",
              accounting_status: "measured",
              provider_event_ids: [],
              currency: "USD",
              request_count: 5,
              execution_count: 0,
              attempt_count: 5,
              confirmed_finding_count: 0,
              average_cost_per_request: 0.01,
              input_tokens: null,
              output_tokens: null,
              reasoning_tokens: null,
              token_observation_count: 0,
              physical_call_count: 0,
              physical_call_count_state: "not_applicable",
              provider_budget: null,
              p50_duration_ms: null,
              p95_duration_ms: null,
              budget_usd: 1,
              budget_utilization: 0.05,
              duration_ms: 385000,
              execution_profile: "live",
              started_at: "2026-07-22T00:00:00Z",
              ended_at: "2026-07-22T00:06:25Z",
              recorded_at: "2026-07-22T00:06:25Z",
            },
            {
              accounting_id: "browser-campaign-beta",
              campaign_id: "browser-campaign-beta",
              provider: "live_target",
              agent_role: null,
              record_kind: "campaign",
              execution_mode: null,
              measured_cost: 0.04,
              cost_measurement_state: "measured",
              accounting_status: "measured",
              provider_event_ids: [],
              currency: "USD",
              request_count: 4,
              execution_count: 0,
              attempt_count: 4,
              confirmed_finding_count: 1,
              average_cost_per_request: 0.01,
              input_tokens: null,
              output_tokens: null,
              reasoning_tokens: null,
              token_observation_count: 0,
              physical_call_count: 0,
              physical_call_count_state: "not_applicable",
              provider_budget: null,
              p50_duration_ms: null,
              p95_duration_ms: null,
              budget_usd: 1,
              budget_utilization: 0.04,
              duration_ms: 260000,
              execution_profile: "live",
              started_at: "2026-07-22T00:07:00Z",
              ended_at: "2026-07-22T00:11:20Z",
              recorded_at: "2026-07-22T00:11:20Z",
            },
            ...browserAgents.map((agent, index) => ({
              accounting_id: `browser-agent-cost-${agent.role}`,
              campaign_id: "browser-campaign-gamma",
              provider: agent.role === "red_team"
                ? "agent:red_team:openrouter/qwen/qwen3.5-397b-a17b"
                : `agent:${agent.role}:${agent.active_assignment.provider}/${agent.active_assignment.model}`,
              agent_role: agent.role,
              record_kind: "agent",
              execution_mode: agent.role === "red_team"
                ? "hosted_advisory"
                : "deterministic",
              measured_cost: agent.measured_cost,
              cost_measurement_state: agent.cost_measurement_state,
              accounting_status: agent.accounting_status,
              provider_event_ids: agent.provider_event_ids,
              currency: agent.currency,
              request_count: 0,
              execution_count: agent.execution_count,
              attempt_count: agent.role === "orchestrator" ? 0 : agent.execution_count,
              confirmed_finding_count: 0,
              average_cost_per_request: null,
              input_tokens: agent.input_tokens,
              output_tokens: agent.output_tokens,
              reasoning_tokens: agent.reasoning_tokens,
              token_observation_count: agent.token_observation_count,
              physical_call_count: agent.physical_call_count,
              physical_call_count_state: agent.physical_call_count_state,
              provider_budget: agent.provider_budget,
              p50_duration_ms: agent.p50_duration_ms,
              p95_duration_ms: agent.p95_duration_ms,
              budget_usd: null,
              budget_utilization: null,
              duration_ms: 1200 + index * 300,
              execution_profile: "live",
              started_at: "2026-07-22T00:20:00Z",
              ended_at: "2026-07-22T00:24:03Z",
              recorded_at: "2026-07-22T00:24:03Z",
            })),
          ],
        }));
        return;
      }
      if (path === "/api/v1/agents") {
        response.end(JSON.stringify({ state: "ready", data: browserAgents }));
        return;
      }
      if (/^\/api\/v1\/agent-prompts\/[^/]+\/[^/]+\/[a-f0-9]{64}\/[a-f0-9]{64}$/.test(path)) {
        const role = path.split("/")[4];
        const agent = browserAgents.find((record) => record.role === role);
        response.end(JSON.stringify(agent
          ? {
              state: "ready",
              data: {
                role,
                prompt_version: agent.staged_assignment.prompt_version,
                prompt_sha256: agent.staged_assignment.prompt_sha256,
                system_prompt: `Operate as the ${agent.display_name} using only authorized, synthetic, hash-bound inputs.`,
              },
            }
          : { state: "empty", data: null }));
        return;
      }
      if (path === "/api/v1/agent-activity") {
        response.end(JSON.stringify({ state: "ready", data: browserAgentActivity }));
        return;
      }
      const promptSnapshotMatch = path.match(
        /^\/api\/v1\/agent-executions\/([^/]+)\/prompt-snapshot$/,
      );
      if (promptSnapshotMatch) {
        const executionId = decodeURIComponent(promptSnapshotMatch[1]);
        const execution = browserAgentActivity.find(
          (candidate) => candidate.execution_id === executionId,
        );
        if (!execution || execution.execution_mode !== "hosted_advisory") {
          response.end('{"state":"empty","data":null}');
          return;
        }
        const systemPrompt = `Operate as the ${execution.agent_role} for a synthetic browser fixture. Enforce the approved target and safety scope.`;
        const providerMessages = [
          { role: "system", content: systemPrompt },
          {
            role: "user",
            content: "{\"fixture_identifier\":\"[REDACTED:SYNTHETIC_IDENTIFIER]\",\"instruction\":\"Evaluate only the authorized synthetic case.\"}",
          },
        ];
        response.end(JSON.stringify({
          state: "ready",
          data: {
            execution_id: execution.execution_id,
            campaign_run_id: execution.campaign_run_id,
            attempt_id: execution.attempt_id,
            agent_role: execution.agent_role,
            system_prompt_version: "browser-fixture-v1",
            system_prompt_sha256: sha256(systemPrompt),
            system_prompt_content: systemPrompt,
            provider_messages: providerMessages,
            transcript_sha256: sha256(canonicalJson({ messages: providerMessages })),
            redactions: [{
              path: "$.messages[1].content.fixture_identifier",
              reason: "synthetic_identifier",
              replacement: "[REDACTED:SYNTHETIC_IDENTIFIER]",
            }],
            created_at: "2026-07-22T00:24:00Z",
          },
        }));
        return;
      }
      if (path === "/api/v1/tooling") {
        response.end(JSON.stringify({ state: "ready", data: browserTooling }));
        return;
      }
      if (path === "/api/v1/findings") {
        response.end(JSON.stringify({ state: "ready", data: browserFindings }));
        return;
      }
      if (path.startsWith("/api/v1/findings/")) {
        const findingId = path.split("/").at(-1);
        const finding = browserFindings.find((record) => record.finding_id === findingId);
        response.end(JSON.stringify(finding
          ? {
              state: "ready",
              data: {
                ...finding,
                verification: finding.finding_id === browserVerification.finding_id
                  ? browserVerification
                  : unavailableBrowserVerification(finding.finding_id),
              },
            }
          : { state: "empty", data: null }));
        return;
      }
      if (path === "/api/v1/approvals") {
        response.end(JSON.stringify({
          state: "ready",
          data: browserApprovals,
        }));
        return;
      }
      if (path.startsWith("/api/v1/approvals/")) {
        const requestId = path.split("/").at(-1);
        const approval = browserApprovals.find((record) => record.request_id === requestId);
        const campaignRunId = requestId === "browser-approval-alpha"
          ? "browser-campaign-alpha"
          : requestId === "browser-approval-beta"
            ? "browser-campaign-beta"
            : null;
        response.end(JSON.stringify(approval
          ? {
              state: "ready",
              data: {
                ...approval,
                campaign_run_id: campaignRunId,
                verification_chain: requestId === "browser-approval-alpha"
                  ? [browserVerification]
                  : [],
              },
            }
          : { state: "empty", data: null }));
        return;
      }
      if (path === "/api/v1/reports") {
        response.end(JSON.stringify({ state: "ready", data: browserReports }));
        return;
      }
      if (path.startsWith("/api/v1/reports/")) {
        const reportId = path.split("/").at(-1);
        const report = browserReports.find((record) => record.report_id === reportId);
        response.end(JSON.stringify(report
          ? { state: "ready", data: report }
          : { state: "empty", data: null }));
        return;
      }
      if (path === "/api/v1/coverage") {
        response.end(JSON.stringify({ state: "ready", data: browserCoverage }));
        return;
      }
      if (path === "/api/v1/resilience") {
        response.end(JSON.stringify({ state: "ready", data: browserRegression }));
        return;
      }
      if (path === "/api/v1/configuration") {
        response.end(JSON.stringify({
          state: "ready",
          data: {
            snapshot_id: "configuration-snapshot-0042",
            version: 42,
            status: "published",
            configuration: {
              orchestration: { concurrency: 3, strategy: "coverage_gap" },
              observability: { langfuse: true, durable_request_ledger: true },
              safety: { synthetic_data_only: true, publication_gate: true },
              judge: { independent: true, calibration_set: "week3-v2" },
              security_workbench: {
                name: "Headshot LLM Security Workbench",
                burp_suite_installed: false,
                capabilities: [
                  { workflow: "Proxy + Logger + Inspector", headshot_control: "Traces", state: "operational", llm_focus: "Sanitized prompt/response exchange inspection with correlation and cost", safeguard: "Secrets are redacted before Postgres and Langfuse persistence", evidence: "outbound_http_requests + Langfuse trace ID" },
                  { workflow: "Repeater", headshot_control: "Regression replay", state: "governed", llm_focus: "Replay a confirmed synthetic case against a versioned target", safeguard: "New corpus hash and fresh exact-scope authorization", evidence: "regression attempt + immutable evidence hash" },
                  { workflow: "Intruder", headshot_control: "Garak + PyRIT + Giskard + Promptfoo", state: "governed", llm_focus: "Prompt injection, exfiltration, tool misuse and multi-turn mutation", safeguard: "PolicyGateway applies all caps", evidence: "ToolAttackBundle + mutation lineage" },
                  { workflow: "Scanner", headshot_control: "OWASP ZAP + independent Judge", state: "operational", llm_focus: "Passive web DAST plus behavioral agent evaluation", safeguard: "Exact-origin passive ZAP and human publication gate", evidence: "ToolFinding + Judge verdict" },
                  { workflow: "Comparer", headshot_control: "Judge + evidence + resilience", state: "operational", llm_focus: "Compare invariants, outputs, prior fixes and verdicts", safeguard: "Attack generation cannot approve its own result", evidence: "AttemptResult + Verdict" },
                ],
              },
            },
            published_at: "2026-07-22T00:10:00Z",
            published_by: "user_configuration_admin",
          },
        }));
        return;
      }
      if (path === "/api/v1/birdseye") {
        response.end(JSON.stringify({ state: "ready", data: browserBirdseye }));
        return;
      }
      if (path === "/api/v1/components") {
        response.end(JSON.stringify({
          state: "ready",
          data: [
            { component_id: "orchestrator", name: "Orchestrator", kind: "agent", availability: "operational and evidenced", environment: "staging", detail: "Coverage-gap scheduling and bounded dispatch are active.", version: "1", target_access: "policy_gateway_only", capabilities: ["coverage scheduling"], owasp_llm: [], owasp_web: [], operational_scope: ["campaign orchestration"], adapter_only_scope: [], execution_evidence: ["campaign ledger"], heartbeat_at: "2026-07-22T00:24:00Z" },
            { component_id: "red-team", name: "Red Team", kind: "agent", availability: "operational and evidenced", environment: "staging", detail: "Live mutation worker is consuming authorized work.", version: "1", target_access: "policy_gateway_only", capabilities: ["attack mutation"], owasp_llm: ["LLM01:2025"], owasp_web: [], operational_scope: ["authorized candidates"], adapter_only_scope: [], execution_evidence: ["attempt ledger"], heartbeat_at: "2026-07-22T00:24:02Z" },
            { component_id: "judge", name: "Independent Judge", kind: "agent", availability: "operational and evidenced", environment: "staging", detail: "Independent verdict projection is current.", version: "1", target_access: "none", capabilities: ["independent verdict"], owasp_llm: [], owasp_web: [], operational_scope: ["evidence adjudication"], adapter_only_scope: [], execution_evidence: ["verdict ledger"], heartbeat_at: "2026-07-22T00:24:03Z" },
            { component_id: "security-tool:zap", name: "OWASP ZAP", kind: "security-tool:dast", availability: "operational and evidenced", environment: "isolated-ci-tooling", detail: "Exact-origin passive DAST is normalized into advisory findings.", version: "2.17.0", target_access: "exact_origin_passive", capabilities: ["passive DAST"], owasp_llm: [], owasp_web: ["A05:2021"], operational_scope: ["passive baseline"], adapter_only_scope: ["active DAST"], execution_evidence: ["ci://security-tools/zap.json"], heartbeat_at: "2026-07-22T00:23:59Z" },
            { component_id: "security-tool:headshot-llm-workbench", name: "Headshot LLM Security Workbench", kind: "security-tool:llm-proxy", availability: "operational and evidenced", environment: "staging", detail: "Governed Burp-style LLM workflow over real Headshot controls.", version: "1.0.0", target_access: "policy_gateway_only", capabilities: ["inspect", "replay", "fuzz", "scan", "compare"], owasp_llm: ["LLM01:2025", "LLM02:2025", "LLM06:2025"], owasp_web: ["A05:2021", "A07:2021", "A09:2021"], operational_scope: ["traffic inspector", "governed mutation", "independent comparison"], adapter_only_scope: ["active DAST", "public OOB listener"], execution_evidence: ["postgres://outbound_http_requests", "langfuse://target-http-request"], heartbeat_at: "2026-07-22T00:24:04Z" },
          ],
        }));
        return;
      }
      if (path === "/api/v1/audit") {
        response.end(JSON.stringify({
          state: "ready",
          data: [
            { cursor: 65, event_type: "campaign.completed", aggregate_type: "campaign", aggregate_id: "browser-campaign-alpha", actor_user_id: null, payload: { attempts: 9 }, created_at: "2026-07-22T00:06:25Z" },
            { cursor: 66, event_type: "finding.confirmed", aggregate_type: "finding", aggregate_id: "finding-prompt-injection", actor_user_id: "user_independent_judge", payload: { severity: "critical" }, created_at: "2026-07-22T00:07:10Z" },
            { cursor: 67, event_type: "configuration.published", aggregate_type: "configuration", aggregate_id: "configuration-snapshot-0042", actor_user_id: "user_configuration_admin", payload: { version: 42 }, created_at: "2026-07-22T00:10:00Z" },
            { cursor: 68, event_type: "campaign.authorization_requested", aggregate_type: "approval", aggregate_id: "browser-approval-gamma", actor_user_id: "user_operator", payload: { target_id: "browser-target" }, created_at: "2026-07-22T00:14:00Z" },
          ],
        }));
        return;
      }
      if (path === "/api/v1/target-catalog") {
        response.end(JSON.stringify({
          state: "ready",
          data: [{
            target_id: "browser-target",
            version: "v1",
            name: "Browser Test Target",
            environment: "staging",
            synthetic_data_only: true,
            surface_count: 1,
            registration_state: "registered",
          }],
        }));
        return;
      }
      if (path === "/api/v1/targets") {
        response.end(JSON.stringify({
          state: "ready",
          data: [{
            target_id: "browser-target",
            version: "v1",
            content_hash: "sha256:browser-target",
            name: "Browser Test Target",
            adapter_kind: "bruno",
            environment: "test",
            base_url: "https://browser-target.example.test",
            auth_mode: "header",
            credential_configured: true,
            synthetic_data_only: true,
            safety_caps: browserScope.caps,
            lifecycle: "ready",
            allowed_lifecycle_transitions: ["disabled"],
            surfaces: [{
              surface_id: "chat",
              version: "v1",
              target_version: "v1",
              content_hash: "sha256:browser-surface",
              kind: "chat",
              protocol: "https",
              method: "POST",
              relative_path: "/chat",
              trust_boundary: "external",
              authentication_required: true,
              risk: "high",
              owasp_mappings: [],
              oracle_refs: [],
              enabled: true,
              created_at: "2026-07-22T00:00:00Z",
            }],
            campaign_template: {
              target_id: "browser-target",
              target_version: "v1",
              surface_id: "chat",
              surface_version: "v1",
              corpus_id: "browser-corpus",
              corpus_hash: "sha256:browser-corpus",
              case_count: 9,
              physical_request_count: 9,
              tool_sources: [],
              execution_profile: "live",
              maximum_caps: browserScope.caps,
              hosted_run: browserHostedRun,
            },
            campaign_suite_templates: [browserCampaignSuite],
            created_at: "2026-07-22T00:00:00Z",
          }],
        }));
        return;
      }
      response.end(
        '{"state":"unavailable","data":null,"reason_code":"browser_fixture_dependency"}',
      );
    });
  },
});

// Same-origin SPA. Development intentionally has no cross-origin API proxy; protected
// requests always target /api/v1 on the current application origin. The browser-test mode
// alone swaps Clerk and API dependencies for deterministic test-only boundaries.
export default defineConfig(({ mode }) => {
  const browserTest = mode === "browser-test";
  const fixture = (name: string) =>
    fileURLToPath(new URL(`./tests/browser/fixtures/${name}`, import.meta.url));
  return {
    plugins: [react(), ...(browserTest ? [browserFixture()] : [])],
    resolve: browserTest
      ? {
          alias: {
            "@clerk/react": fixture("clerk-react.tsx"),
            "@clerk/clerk-js": fixture("clerk-js.ts"),
            "@clerk/ui": fixture("clerk-ui.ts"),
          },
        }
      : undefined,
    server: { port: 5173 },
    // Production source maps disabled: don't ship readable source to the browser / Railway.
    build: {
      outDir: "dist",
      sourcemap: false,
      rollupOptions: {
        output: {
          manualChunks: {
            "clerk-vendor": ["@clerk/clerk-js", "@clerk/react", "@clerk/ui"],
            "react-vendor": ["react", "react-dom"],
          },
        },
      },
    },
  };
});
