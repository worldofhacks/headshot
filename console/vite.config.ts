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
  },
  execution_profile: "live",
} as const;

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
      queue_depth: 3,
      target_access: "policy-gated",
    },
    ...[
      ["orchestrator", "Orchestrator", "control", "working", "Running orchestrator campaign work", "none"],
      ["red_team", "Red Team", "untrusted", "ready", "Latest execution succeeded", "policy gateway only"],
      ["judge", "Independent Judge", "evaluation", "ready", "Latest execution succeeded", "none"],
      ["documentation", "Documentation", "governance", "waiting", "Latest execution skipped", "none"],
    ].map(([role, name, trustZone, state, task, targetAccess]) => ({
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
      p50_latency_ms: null,
      p95_latency_ms: null,
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
    evidence_content_hash: "sha256:finding-one",
    history: [{
      decision: "confirmed",
      actor_user_id: "user_independent_judge",
      rationale: "Independent replay reproduced the boundary violation.",
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
    evidence_content_hash: "sha256:finding-two",
    history: [],
  },
  {
    finding_id: "finding-cache-review",
    state: "resolved",
    severity: "informational",
    category: "response caching",
    target_version: "v1",
    publication_status: "published",
    evidence_integrity: "bound",
    source_kind: "security_tool",
    execution_profile: "live",
    evidence_provenance: "scan_only",
    campaign_run_id: null,
    attempt_id: null,
    evidence_content_hash: "sha256:finding-three",
    history: [{
      decision: "resolved",
      actor_user_id: "user_security_reviewer",
      rationale: "Reviewed against the non-sensitive public response contract.",
      created_at: "2026-07-22T00:12:20Z",
    }],
  },
];

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
    execution_mode: "deterministic",
    activation_state: "active",
    version: 1,
    configuration_sha256: String(index + 1).repeat(64),
    configured_at: null,
    configured_by: null,
  },
  staged_assignment: agent.role === "red_team"
    ? {
        role: agent.role,
        provider: "openrouter",
        model: "reviewed/red-team-advisory-v1",
        execution_mode: "hosted_advisory",
        activation_state: "staged_pending_authorization",
        version: 2,
        configuration_sha256: "a".repeat(64),
        configured_at: "2026-07-22T00:13:00Z",
        configured_by: "user_configuration_admin",
      }
    : null,
  running_count: agent.role === "orchestrator" ? 1 : 0,
  succeeded_count: agent.execution_count - agent.skipped_count,
  failed_count: 0,
  measured_cost: 0,
  currency: "USD",
  input_tokens: null,
  output_tokens: null,
  token_observation_count: 0,
  average_duration_ms: 4.6 + index * 1.8,
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
  provider: "headshot",
  model,
  execution_mode: "deterministic",
  configuration_version: 1,
  input_sha256: String(index + 2).repeat(64),
  output_sha256: status === "running" ? null : String(index + 3).repeat(64),
  input_tokens: null,
  output_tokens: null,
  measured_cost: 0,
  currency: "USD",
  trace_id: String(index + 1).padStart(32, "0"),
  detail: { decision: role === "orchestrator" ? "prioritize" : "completed" },
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
            session_id: "session_browser_fixture",
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
      if (path === "/api/v1/traces") {
        response.end(JSON.stringify({
          state: "ready",
          data: Array.from({ length: 9 }, (_, index) => ({
            request_id: `browser-request-${index}`,
            trace_id: `${String(index + 1).padStart(32, "0")}`,
            campaign_id: index < 5 ? "browser-campaign-alpha" : "browser-campaign-beta",
            attempt_id: `browser-attempt-${index}`,
            operation: "target.http",
            provider: "openemr",
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
            currency: "USD",
            langfuse_status: index === 7 ? "error" : "exported",
            request_preview: JSON.stringify({ turns: [`Synthetic LLM attack case ${index + 1}`] }),
            response_preview: index === 7 ? "upstream unavailable" : JSON.stringify({ answer: `Synthetic target response ${index + 1}` }),
            request_sha256: "a".repeat(64),
            response_sha256: "b".repeat(64),
            inspection_flags: index === 7 ? ["transport_or_server_error"] : [],
            inspection_owasp_mappings: index === 7 ? ["A09:2021"] : [],
          })),
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
              measured_cost: 0.05,
              currency: "USD",
              request_count: 5,
              attempt_count: 5,
              confirmed_finding_count: 0,
              average_cost_per_request: 0.01,
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
              measured_cost: 0.04,
              currency: "USD",
              request_count: 4,
              attempt_count: 4,
              confirmed_finding_count: 1,
              average_cost_per_request: 0.01,
              budget_usd: 1,
              budget_utilization: 0.04,
              duration_ms: 260000,
              execution_profile: "live",
              started_at: "2026-07-22T00:07:00Z",
              ended_at: "2026-07-22T00:11:20Z",
              recorded_at: "2026-07-22T00:11:20Z",
            },
          ],
        }));
        return;
      }
      if (path === "/api/v1/agents") {
        response.end(JSON.stringify({ state: "ready", data: browserAgents }));
        return;
      }
      if (path === "/api/v1/agent-activity") {
        response.end(JSON.stringify({ state: "ready", data: browserAgentActivity }));
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
          ? { state: "ready", data: finding }
          : { state: "empty", data: null }));
        return;
      }
      if (path === "/api/v1/approvals") {
        response.end(JSON.stringify({
          state: "ready",
          data: [
            { ...browserScope, run_nonce: "browser-run-alpha-0001", request_id: "browser-approval-alpha", scope_hash: "sha256:scope-alpha", launcher_user_id: "user_operator", expires_at: "2026-07-22T00:15:00Z", created_at: "2026-07-22T00:00:00Z", status: "approved", decision: "approved", approver_user_id: "user_approver", self_approval_override: false, decided_at: "2026-07-22T00:01:00Z" },
            { ...browserScope, run_nonce: "browser-run-beta-0002", request_id: "browser-approval-beta", scope_hash: "sha256:scope-beta", launcher_user_id: "user_operator", expires_at: "2026-07-22T00:22:00Z", created_at: "2026-07-22T00:07:00Z", status: "rejected", decision: "rejected", approver_user_id: "user_approver", self_approval_override: false, decided_at: "2026-07-22T00:08:00Z" },
            { ...browserScope, run_nonce: "browser-run-gamma-0003", request_id: "browser-approval-gamma", scope_hash: "sha256:scope-gamma", launcher_user_id: "user_operator", expires_at: "2026-07-22T00:29:00Z", created_at: "2026-07-22T00:14:00Z", status: "pending", decision: null, approver_user_id: null, self_approval_override: false, decided_at: null },
          ],
        }));
        return;
      }
      if (path === "/api/v1/coverage") {
        response.end(JSON.stringify({
          state: "ready",
          data: [
            {
              target_version: "v1.0.0",
              verified_attempt_count: 9,
              total_case_count: 9,
              category_count: 3,
              execution_profile: "live",
              evidence_provenance: "live_target",
              classifications: ["boundary", "invariant", "regression"],
              owasp_web: ["A01:2021", "A05:2021"],
              owasp_llm: ["LLM01:2025", "LLM06:2025"],
              verdict_counts: { blocked: 6, safe: 2, partial: 1 },
              covered: true,
              as_of: "2026-07-22T00:20:00Z",
            },
            {
              target_version: "v1.1.0",
              verified_attempt_count: 6,
              total_case_count: 9,
              category_count: 3,
              execution_profile: "live",
              evidence_provenance: "live_target",
              classifications: ["boundary", "invariant", "regression"],
              owasp_web: ["A01:2021", "A05:2021", "A07:2021"],
              owasp_llm: ["LLM01:2025", "LLM02:2025", "LLM06:2025"],
              verdict_counts: { blocked: 4, safe: 1, partial: 1 },
              covered: false,
              as_of: "2026-07-22T00:24:00Z",
            },
          ],
        }));
        return;
      }
      if (path === "/api/v1/resilience") {
        response.end(JSON.stringify({
          state: "ready",
          data: [
            { regression_id: "reg-prompt-injection", version: "v1.0.0", status: "passed", recorded_at: "2026-07-22T00:05:00Z" },
            { regression_id: "reg-tool-boundary", version: "v1.0.0", status: "passed", recorded_at: "2026-07-22T00:06:00Z" },
            { regression_id: "reg-data-exfiltration", version: "v1.0.0", status: "failed", recorded_at: "2026-07-22T00:07:00Z" },
            { regression_id: "reg-prompt-injection", version: "v1.1.0", status: "passed", recorded_at: "2026-07-22T00:22:00Z" },
            { regression_id: "reg-data-exfiltration", version: "v1.1.0", status: "review pending", recorded_at: "2026-07-22T00:23:00Z" },
          ],
        }));
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
            safety_caps: {
              budget_usd: 1,
              max_attempts_per_run: 9,
              target_requests_per_second: 1,
              run_timeout_seconds: 900,
            },
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
              tool_sources: [],
              execution_profile: "live",
              maximum_caps: {
                budget_usd: 1,
                max_attempts_per_run: 9,
                target_requests_per_second: 1,
                run_timeout_seconds: 900,
              },
            },
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
