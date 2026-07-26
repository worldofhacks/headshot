import { renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import activeRunningAgentBudget from "../../tests/fixtures/read_models/active_running_agent_budget.json";
import { createApiClient } from "../src/api/client";
import {
  decodeApprovals,
  decodeApprovalDetail,
  decodeAgentActivity,
  decodeAgentPrompt,
  decodeAgents,
  decodeAttempts,
  decodeAuditHistory,
  decodeBirdseye,
  decodeCampaigns,
  decodeComponents,
  decodeConfiguration,
  decodeCosts,
  decodeCoverage,
  decodeEvidence,
  decodeFinding,
  decodeFindings,
  decodePrincipal,
  decodeReports,
  decodeResilience,
  decodeTargetCatalog,
  decodeTargets,
  decodeTooling,
  decodeTraces,
} from "../src/api/read-models";
import { useResource } from "../src/hooks/useResource";

const at = "2026-07-21T00:00:00Z";
const caps = {
  budget_usd: 1,
  max_attempts_per_run: 2,
  target_requests_per_second: 0.5,
  run_timeout_seconds: 60,
  logical_case_limit: null,
  physical_request_limit: null,
  target_retries_per_turn: null,
};
const scope = {
  target_id: "target-1",
  target_version: "1.0.0",
  surface_id: "surface-1",
  surface_version: "1.0.0",
  adapter_kind: "openemr",
  environment: "staging",
  exact_host: "target.invalid",
  auth_mode: "bearer",
  explicit_no_auth: false,
  auth_posture: "bearer",
  protocol: "https",
  method: "POST",
  relative_path: "api",
  endpoint: "https://target.invalid/api",
  corpus_id: "m11-seed-corpus-v1",
  corpus_hash: "corpus-1",
  caps,
  run_nonce: "nonce-1",
  execution_profile: "live",
  hosted_run: null,
};
const unavailableProviderBudget = {
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
const finding = {
  finding_id: "finding-1",
  state: "confirmed",
  severity: "high",
  category: "prompt_injection",
  target_version: "1.0.0",
  publication_status: "pending",
  evidence_integrity: "verified",
  source_kind: "campaign",
  execution_profile: "synthetic",
  evidence_provenance: "synthetic_offline",
  campaign_run_id: "run-1",
  attempt_id: "attempt-1",
  evidence_content_hash: "c".repeat(64),
  history: [{
    decision: "confirmed",
    actor_user_id: "user-1",
    rationale: "evidence",
    reason_code: null,
    created_at: at,
  }],
};
const verification = {
  availability: "ready",
  reason_code: null,
  finding_id: "finding-1",
  campaign_run_id: "run-1",
  attempt_id: "attempt-1",
  attack_case: {
    case_id: "case-1",
    case_content_sha256: "a".repeat(64),
    category: "prompt_injection",
    attack_class: "boundary",
    owasp_mappings: [{ framework: "OWASP LLM", id: "LLM01" }],
    oracle_expectation: { kind: "canary" },
    corpus_reconciliation: "verified",
  },
  attack_attempt: { schema_version: "1", input_sequence: ["redacted input"] },
  input_sequence: ["redacted input"],
  request_transcript: { method: "POST" },
  response_transcript: "redacted response",
  policy_decision_id: "policy-1",
  executed_at: at,
  trace_id: "trace-1",
  judge: {
    state: "EXPLOIT_CONFIRMED",
    confidence: 1,
    reason_codes: ["canary_hit"],
    confirmation_source: "canary",
    oracle_refs: ["oracle://synthetic/case-1"],
    canary_refs: ["canary://synthetic/case-1"],
    rationale: null,
    rationale_availability: "unavailable",
    rationale_detail: "This contract stores typed reason codes.",
    error_code: null,
  },
  report_id: "report-1",
  minimal_reproduction: ["Submit the redacted input."],
  reproduction_sha256: "b".repeat(64),
  regression: {
    disposition_id: "disposition-1",
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
    observability_detail: "No durable span transcript hash.",
  },
  redaction_state: "synthetic_identifiers_redacted",
};

const validResources: Array<[string, (value: unknown) => unknown, unknown]> = [
  [
    "principal",
    decodePrincipal,
    { user_id: "user-1", organization_id: "org-1", organization_role: "org:operator", organization_permissions: ["org:console:read"] },
  ],
  [
    "campaigns",
    decodeCampaigns,
    [{ ...scope, run_id: "run-1", authorization_request_id: "request-1", state: "queued", scope_hash: "scope-1", launcher_user_id: "user-1", attempt_count: 0, created_at: at }],
  ],
  [
    "attempts",
    decodeAttempts,
    [{ attempt_id: "attempt-1", ordinal: 0, case_id: "case-1", content_hash: null, executed_at: null, trace_id: null, verdict: null, confidence: null, execution_profile: null, evidence_provenance: null, created_at: at }],
  ],
  [
    "evidence",
    decodeEvidence,
    { attempt_id: "attempt-1", campaign_run_id: "run-1", target_id: "target-1", target_version: "1.0.0", surface_id: "surface-1", surface_version: "1.0.0", attack_attempt: {}, request_transcript: {}, response_transcript: "response", policy_decision_id: "policy-1", executed_at: at, trace_id: null, content_hash: "content-1", verdict: null, confidence: null, execution_profile: null, evidence_provenance: null },
  ],
  [
    "findings",
    decodeFindings,
    [finding],
  ],
  [
    "finding detail and history",
    decodeFinding,
    { ...finding, verification },
  ],
  [
    "approvals",
    decodeApprovals,
    [{ ...scope, request_id: "request-1", status: "pending", decision: null, scope_hash: "scope-1", launcher_user_id: "user-1", approver_user_id: null, self_approval_override: false, decided_at: null, expired: false, consumed: false, created_at: at, expires_at: "2026-07-21T00:15:00Z" }],
  ],
  [
    "approval detail",
    decodeApprovalDetail,
    { ...scope, request_id: "request-1", status: "approved", decision: "approved", scope_hash: "scope-1", launcher_user_id: "user-1", approver_user_id: "user-2", self_approval_override: false, decided_at: at, expired: false, consumed: true, created_at: at, expires_at: "2026-07-21T00:15:00Z", campaign_run_id: "run-1", verification_chain: [verification] },
  ],
  [
    "coverage",
    decodeCoverage,
    [{
      target_version: "target-1@1.0.0",
      verified_attempt_count: 9,
      total_case_count: 9,
      category_count: 3,
      execution_profile: "synthetic",
      evidence_provenance: "synthetic_offline",
      classifications: ["boundary", "invariant", "regression"],
      owasp_web: ["A01:2021"],
      owasp_llm: ["LLM01:2025"],
      verdict_counts: { NO_EXPLOIT_OBSERVED: 8, EXPLOIT_CONFIRMED: 1 },
      covered: true,
      as_of: at,
    }],
  ],
  [
    "resilience",
    decodeResilience,
    [{
      regression_id: "regression-1",
      version: "1.0.0",
      status: "NO_EXPLOIT_OBSERVED",
      recorded_at: at,
    }],
  ],
  [
    "reports",
    decodeReports,
    [{
      schema_version: "1",
      report_id: "report-1",
      finding_id: "finding-1",
      campaign_run_id: "run-1",
      attempt_id: "attempt-1",
      source_case_id: "case-1",
      severity: "high",
      category: "prompt_injection",
      description: "A verified synthetic finding.",
      clinical_impact: "Synthetic clinical scope crossed.",
      minimal_reproduction: ["Submit the redacted input."],
      reproduction_sha256: "b".repeat(64),
      observed_behavior: "Canary observed.",
      expected_behavior: "Request refused.",
      recommended_remediation: "Preserve trusted instruction priority.",
      status: "draft",
      fix_validation: { state: "not_run", summary: "No fix tested.", evidence_references: [] },
      evidence_references: [`evidence://sha256/${"c".repeat(64)}`],
      publication_state: "draft_unpublished",
      regression: verification.regression,
      report_integrity: "verified",
      created_at: at,
      verification,
    }],
  ],
  [
    "agent prompt",
    decodeAgentPrompt,
    { role: "judge", prompt_version: "1", prompt_sha256: "d".repeat(64), system_prompt: "Evaluate only bound evidence." },
  ],
  [
    "traces",
    decodeTraces,
    [{ request_id: "request-1", execution_id: null, parent_execution_id: null, trace_id: "trace-1", campaign_id: "run-1", attempt_id: "attempt-1", operation: "target.http", provider: "openemr", model: null, agent_role: null, execution_mode: null, requested_model: null, returned_model: null, model_substituted: false, upstream_provider: null, provider_request_id: null, configuration_set_sha256: null, role_configuration_sha256: null, generation_policy_sha256: null, physical_attempts: null, method: "POST", destination_host: "target.invalid", relative_path: "chat", status: "succeeded", status_code: 200, error_code: null, started_at: at, finished_at: "2026-07-21T00:00:00.012Z", duration_ms: 12.5, request_bytes: 25, response_bytes: 50, measured_cost: 0.01, cost_measurement_state: "measured", accounting_status: "measured", provider_event_ids: [], provider_event_status: null, provider_lineage_state: "not_applicable", currency: "USD", input_tokens: null, output_tokens: null, reasoning_tokens: null, judge_calibration_id: null, judge_calibration_state: null, oracle_agreement: null, decision_authority: null, p50_duration_ms: null, p95_duration_ms: null, langfuse_status: "queued", langfuse_verified_at: null, request_preview: '{"turns":["synthetic"]}', response_preview: '{"answer":"safe"}', request_sha256: "a".repeat(64), response_sha256: "b".repeat(64), inspection_flags: [], inspection_owasp_mappings: [] }],
  ],
  [
    "costs",
    decodeCosts,
    [{ accounting_id: "accounting-1", campaign_id: "run-1", provider: "provider", agent_role: null, record_kind: "campaign", execution_mode: null, measured_cost: 0.25, cost_measurement_state: "measured", accounting_status: "measured", provider_event_ids: [], currency: "USD", request_count: 5, execution_count: 0, attempt_count: 5, confirmed_finding_count: 1, average_cost_per_request: 0.05, input_tokens: null, output_tokens: null, reasoning_tokens: null, token_observation_count: 0, physical_call_count: 0, physical_call_count_state: "not_applicable", provider_budget: null, p50_duration_ms: null, p95_duration_ms: null, budget_usd: 1, budget_utilization: 0.25, duration_ms: 2500, execution_profile: "live", started_at: at, ended_at: "2026-07-21T00:00:02.500Z", recorded_at: at }],
  ],
  [
    "targets and surfaces",
    decodeTargets,
    [{ target_id: "target-1", name: "Registered target", version: "1.0.0", content_hash: "target-hash", lifecycle: "ready", environment: "staging", adapter_kind: "openemr", base_url: "https://target.invalid", auth_mode: "bearer", credential_configured: true, synthetic_data_only: true, safety_caps: caps, allowed_lifecycle_transitions: ["disabled"], campaign_template: null, created_at: at, surfaces: [{ surface_id: "surface-1", version: "1.0.0", target_version: "1.0.0", content_hash: "surface-hash", kind: "chat", protocol: "https", method: "POST", relative_path: "api", trust_boundary: "external-target", authentication_required: true, risk: "high", owasp_mappings: [], oracle_refs: [], enabled: true, created_at: at }] }],
  ],
  [
    "trusted target catalog",
    decodeTargetCatalog,
    [{
      target_id: "target-1",
      version: "1.0.0",
      name: "Reviewed target",
      environment: "staging",
      synthetic_data_only: true,
      surface_count: 2,
      registration_state: "available",
    }],
  ],
  [
    "configuration",
    decodeConfiguration,
    { snapshot_id: "snapshot-1", version: 1, status: "published", configuration: {}, published_at: at, published_by: "user-1" },
  ],
  [
    "components",
    decodeComponents,
    [{ component_id: "runner-1", name: "runner", kind: "runner", availability: "operational and evidenced", environment: "staging", detail: "private worker heartbeat", version: "1", target_access: "none", capabilities: [], owasp_llm: [], owasp_web: [], operational_scope: [], adapter_only_scope: [], execution_evidence: [], heartbeat_at: at }],
  ],
  [
    "tooling",
    decodeTooling,
    [{
      tool_id: "promptfoo",
      name: "Promptfoo",
      version: "1",
      kind: "llm-eval",
      availability: "operational and evidenced",
      target_access: "policy_gateway_only",
      target_id: "target-1",
      target_version: "1.0.0",
      target_lifecycle: "ready",
      surface_id: "surface-1",
      surface_version: "1.0.0",
      surface_kind: "chat",
      endpoint: "https://target.invalid/api",
      applicability: "in_campaign",
      execution_mode: "reviewed candidates through policy gateway",
      scope_reason: "The case is inside the authorized corpus.",
      requires_separate_authorization: false,
      capabilities: ["prompt injection"],
      owasp_llm: ["LLM01:2025"],
      owasp_web: ["A03:2021"],
      reviewed_candidate_count: 1,
      executed_attempt_count: 1,
      recorded_scan_count: 0,
      recorded_finding_count: 1,
      last_executed_at: at,
      runtime_state: "evidenced",
      evidenced_finding_count: 1,
      last_error_code: null,
    }],
  ],
  [
    "agents",
    decodeAgents,
    [{
      role: "orchestrator",
      display_name: "Orchestrator",
      responsibility: "Select authorized work.",
      trust_level: "trusted governor",
      target_access: "none",
      input_contract: "Snapshot",
      output_contract: "Directive",
      active_assignment: {
        role: "orchestrator",
        provider: "headshot",
        model: "coverage-governor-v1",
        resolved_model: null,
        upstream_provider: null,
        prompt_sha256: "d".repeat(64),
        prompt_version: "1",
        execution_mode: "deterministic",
        activation_state: "active",
        version: 1,
        configuration_sha256: "a".repeat(64),
        configured_at: null,
        configured_by: null,
      },
      staged_assignment: null,
      latest_acceptance_execution: null,
      execution_count: 1,
      hosted_execution_count: 0,
      running_count: 0,
      succeeded_count: 1,
      failed_count: 0,
      skipped_count: 0,
      measured_cost: 0,
      cost_measurement_state: "measured",
      accounting_status: "measured",
      provider_event_ids: [],
      currency: "USD",
      input_tokens: null,
      output_tokens: null,
      reasoning_tokens: null,
      token_observation_count: 0,
      physical_call_count: 0,
      physical_call_count_state: "not_applicable",
      provider_budget: unavailableProviderBudget,
      judge_calibration: null,
      average_duration_ms: 5,
      p50_duration_ms: 5,
      p95_duration_ms: 5,
      langfuse_not_attempted_count: 0,
      langfuse_disabled_count: 0,
      langfuse_queued_count: 0,
      langfuse_exported_count: 1,
      langfuse_error_count: 0,
      langfuse_verified_count: 1,
      last_langfuse_verified_at: at,
      last_activity_at: at,
      last_status: "succeeded",
      last_campaign_run_id: "run-1",
      last_attempt_id: null,
    }],
  ],
  [
    "Birdseye snapshot",
    decodeBirdseye,
    {
      campaign: {
        run_id: "run-1",
        target_id: "target-1",
        target_name: "Registered target",
        target_version: "1.0.0",
        state: "running",
        execution_profile: "live",
        scope_hash: "scope-1",
        attempt_count: 2,
      },
      instrumentation: {
        budget_usd: 1,
        measured_cost_usd: 0.25,
        budget_utilization: 0.25,
        requests_per_second_cap: 0.5,
        queue_queued: 1,
        queue_leased: 1,
        queue_dead_letter: 0,
        confirmed_count: 1,
        confirmed_finding_count: 1,
        likely_count: 0,
        review_count: 1,
        healthy_components: 2,
        total_components: 2,
        system_state: "nominal",
      },
      security_posture: {
        tested_categories: 2,
        required_categories: 3,
        verified_case_count: 2,
        held_count: 1,
        exploited_count: 1,
        review_count: 0,
        observed_hold_rate: 0.5,
        open_finding_count: 1,
        in_progress_finding_count: 0,
        resolved_finding_count: 0,
        critical_open_finding_count: 1,
        resilience_direction: "unavailable",
        current_regression_hold_rate: null,
        previous_regression_hold_rate: null,
        resilience_delta: null,
        cost_per_attempt_usd: 0.125,
        cost_velocity_usd_per_minute: 0.25,
        projected_cost_at_attempt_cap_usd: 1.125,
        priority_category: "prompt_injection",
        priority_reason: "Coverage gap",
        priority_source: "coverage_policy",
        priority_at: null,
      },
      category_outcomes: [{
        target_version: "1.0.0",
        category: "prompt_injection",
        verified_case_count: 1,
        verified_attempt_count: 1,
        held_count: 0,
        exploited_count: 1,
        review_count: 0,
        last_evaluated_at: at,
      }],
      agent_activity: [{
        execution_id: "execution-1",
        parent_execution_id: null,
        agent_role: "orchestrator",
        status: "succeeded",
        phase: "coverage_governance",
        attempt_id: null,
        category: null,
        verdict_state: null,
        finding_id: null,
        error_code: null,
        started_at: at,
        finished_at: at,
        duration_ms: 5,
      }],
      nodes: [{
        component_id: "runner",
        name: "Campaign runner",
        kind: "worker",
        trust_zone: "execution",
        availability: "operational and evidenced",
        runtime_state: "working",
        detail: "private runner heartbeat",
        current_task: "Processing 1 leased job(s)",
        heartbeat_at: at,
        freshness_seconds: 1,
        is_fresh: true,
        healthy_instances: 1,
        total_instances: 1,
        p50_latency_ms: 10,
        p95_latency_ms: 25,
        execution_count: null,
        measured_cost_usd: null,
        accounting_status: null,
        currency: null,
        input_tokens: null,
        output_tokens: null,
        token_observation_count: null,
        langfuse_not_attempted_count: null,
        langfuse_disabled_count: null,
        langfuse_queued_count: null,
        langfuse_exported_count: null,
        langfuse_error_count: null,
        langfuse_verified_count: null,
        last_langfuse_verified_at: null,
        langfuse_status: null,
        queue_depth: 2,
        target_access: "policy-gated",
      }],
      edges: [{
        edge_id: "postgres-to-runner",
        source_component_id: "postgres",
        target_component_id: "runner",
        contract_name: "CampaignDirective",
        state: "active",
        attempt_id: "attempt-1",
        last_event_at: at,
        detail: "Durable work delivery",
      }],
      attention: [{
        attention_id: "approval:request-1",
        priority: 1,
        kind: "approval",
        title: "Campaign authorization requires a decision",
        detail: "Exact-scope request is pending.",
        continuation: "No live campaign may start before approval.",
        record_type: "approval",
        record_id: "request-1",
        route: "/approvals/request-1",
        created_at: at,
      }],
      timeline: [{
        cursor: 1,
        event_type: "campaign.started",
        actor: "user-1",
        summary: "campaign · started",
        aggregate_type: "campaign",
        aggregate_id: "run-1",
        created_at: at,
      }],
      cursor: 1,
      as_of: at,
    },
  ],
  [
    "audit history",
    decodeAuditHistory,
    [{ cursor: 1, event_type: "target.created", aggregate_type: "target", aggregate_id: "target-1", actor_user_id: "user-1", payload: {}, created_at: at }],
  ],
];

const arrayFixtureRecord = (name: string): Record<string, unknown> => {
  const fixture = validResources.find(([candidate]) => candidate === name)?.[2];
  if (!Array.isArray(fixture) || fixture.length === 0) {
    throw new Error(`Missing array fixture: ${name}`);
  }
  return structuredClone(fixture[0]) as Record<string, unknown>;
};

const objectFixture = (name: string): Record<string, unknown> => {
  const fixture = validResources.find(([candidate]) => candidate === name)?.[2];
  if (fixture === null || Array.isArray(fixture) || typeof fixture !== "object") {
    throw new Error(`Missing object fixture: ${name}`);
  }
  return structuredClone(fixture) as Record<string, unknown>;
};

describe("v1 read-model decoders", () => {
  it.each(validResources)("accepts the explicit %s contract", (_name, decode, value) => {
    expect(decode(value)).toEqual(value);
  });

  it.each(validResources)("rejects malformed ready %s data", (_name, decode, value) => {
    const malformed = Array.isArray(value) ? [{ unexpected: true }] : { unexpected: true };
    expect(() => decode(malformed)).toThrow("Invalid");
  });

  it("accepts an unavailable security-tool artifact binding without invented labels", () => {
    const unverifiedToolFinding = {
      ...finding,
      source_kind: "security_tool",
      category: null,
      target_version: null,
      evidence_integrity: "unavailable",
      evidence_content_hash: null,
      campaign_run_id: null,
      attempt_id: null,
      evidence_provenance: "scan_only",
    };

    expect(decodeFindings([unverifiedToolFinding])).toEqual([unverifiedToolFinding]);
  });

  it("keeps coverage and regression projections exact-keyed", () => {
    const coverage = arrayFixtureRecord("coverage");
    const resilience = arrayFixtureRecord("resilience");

    expect(decodeCoverage([coverage])).toEqual([coverage]);
    expect(decodeResilience([resilience])).toEqual([resilience]);
    expect(() => decodeCoverage([{ ...coverage, unexpected: true }]))
      .toThrow("Invalid coverage read model");
    expect(() => decodeCoverage([{
      ...coverage,
      verdict_counts: { NO_EXPLOIT_OBSERVED: -1 },
    }])).toThrow("Invalid coverage read model");
    expect(() => decodeResilience([{ ...resilience, unexpected: true }]))
      .toThrow("Invalid resilience read model");
  });

  it("rejects browser authority fields in the trusted target catalog projection", () => {
    const entry = {
      target_id: "target-1",
      version: "1.0.0",
      name: "Reviewed target",
      environment: "staging",
      synthetic_data_only: true,
      surface_count: 1,
      registration_state: "available",
    };

    expect(decodeTargetCatalog([entry])).toEqual([entry]);
    for (const field of [
      "base_url",
      "allowlisted_hosts",
      "adapter_kind",
      "credential_ref",
      "ownership_authorization_ref",
    ]) {
      expect(() => decodeTargetCatalog([{ ...entry, [field]: "forbidden" }]))
        .toThrow("Invalid target catalog entry read model");
    }
  });

  it.each([
    ["verified without a hash", { evidence_integrity: "verified", evidence_content_hash: null }],
    ["verified with a short hash", { evidence_integrity: "verified", evidence_content_hash: "abc" }],
    ["verified with uppercase hex", { evidence_integrity: "verified", evidence_content_hash: "A".repeat(64) }],
    ["unavailable with a hash", { evidence_integrity: "unavailable", evidence_content_hash: "a".repeat(64) }],
  ])("rejects a finding that is %s", (_label, binding) => {
    expect(() => decodeFindings([{ ...finding, ...binding }])).toThrow("Invalid finding read model");
  });

  it("echoes a closed finding decision reason and rejects an unknown one", () => {
    const reviewed = {
      ...finding,
      history: [{
        ...finding.history[0],
        decision: "rejected",
        reason_code: "not_a_real_exploit",
      }],
    };

    expect(decodeFindings([reviewed])).toEqual([reviewed]);
    expect(() => decodeFindings([{
      ...reviewed,
      history: [{ ...reviewed.history[0], reason_code: "open_ended_reason" }],
    }])).toThrow("Invalid finding history read model");
  });

  it.each([
    ["approved", "not_a_real_exploit"],
    ["rejected", "human_confirmed"],
    ["resolved", "duplicate_finding"],
  ])("rejects a %s history row carrying %s", (decision, reasonCode) => {
    expect(() => decodeFindings([{
      ...finding,
      history: [{
        ...finding.history[0],
        decision,
        reason_code: reasonCode,
      }],
    }])).toThrow("Invalid finding history read model");
  });

  it.each(["approved", "rejected", "resolved", "confirmed"])(
    "keeps a legacy %s history row with a null reason readable",
    (decision) => {
      const legacy = {
        ...finding,
        history: [{
          ...finding.history[0],
          decision,
          reason_code: null,
        }],
      };

      expect(decodeFindings([legacy])).toEqual([legacy]);
    },
  );

  it("decodes a non-null hosted campaign binding without weakening exact keys", () => {
    const hostedRun = {
      configuration_set_sha256: "a".repeat(64),
      generation_policy_sha256: "b".repeat(64),
      session_generation: "generation-1",
      provider_model_call_limit: 8,
      provider_model_spend_limit_usd: "1.250000",
      provider_max_retries: 1,
      provider_max_concurrency: 1,
      provider_timeout_seconds: 45,
    };
    const campaign = {
      ...scope,
      hosted_run: hostedRun,
      run_id: "run-hosted-1",
      authorization_request_id: "request-hosted-1",
      state: "queued",
      scope_hash: "scope-hosted-1",
      launcher_user_id: "user-1",
      attempt_count: 0,
      created_at: at,
    };

    expect(decodeCampaigns([campaign])).toEqual([campaign]);
    expect(() => decodeCampaigns([{
      ...campaign,
      hosted_run: { ...hostedRun, unexpected: true },
    }])).toThrow("Invalid hosted run binding read model");
    expect(() => decodeCampaigns([{
      ...campaign,
      hosted_run: { ...hostedRun, configuration_set_sha256: "A".repeat(64) },
    }])).toThrow("Invalid hosted run binding read model");
    expect(() => decodeCampaigns([{
      ...campaign,
      hosted_run: {
        ...hostedRun,
        credential_reference: "secretref://staging/openrouter/orchestrator/generation-1",
      },
    }])).toThrow("Invalid hosted run binding read model");
  });

  it("decodes the explicit null hosted campaign binding", () => {
    const campaign = {
      ...scope,
      run_id: "run-deterministic-1",
      authorization_request_id: "request-deterministic-1",
      state: "queued",
      scope_hash: "scope-deterministic-1",
      launcher_user_id: "user-1",
      attempt_count: 0,
      created_at: at,
    };

    expect(decodeCampaigns([campaign])).toEqual([campaign]);
  });

  it("decodes only a secret-free server-derived hosted target template", () => {
    const target = arrayFixtureRecord("targets and surfaces");
    const hostedRun = {
      configuration_set_sha256: "a".repeat(64),
      generation_policy_sha256: "b".repeat(64),
      session_generation: "generation-1",
      provider_model_call_limit: 136,
      provider_model_spend_limit_usd: "5",
      provider_max_retries: 1,
      provider_max_concurrency: 1,
      provider_timeout_seconds: 180,
    };
    const campaignTemplate = {
      target_id: "target-1",
      target_version: "1.0.0",
      surface_id: "surface-1",
      surface_version: "1.0.0",
      corpus_id: "m11-seed-corpus-v1",
      corpus_hash: "c".repeat(64),
      case_count: 2,
      tool_sources: [],
      execution_profile: "live",
      maximum_caps: caps,
      hosted_run: hostedRun,
    };

    expect(decodeTargets([{ ...target, campaign_template: campaignTemplate }]))
      .toEqual([{ ...target, campaign_template: campaignTemplate }]);
    expect(() => decodeTargets([{
      ...target,
      campaign_template: {
        ...campaignTemplate,
        hosted_run: {
          ...hostedRun,
          provider_model_call_limit: 137,
        },
      },
    }])).toThrow("Invalid hosted run binding read model");
    expect(decodeTargets([{
      ...target,
      campaign_template: { ...campaignTemplate, hosted_run: null },
    }])).toEqual([{
      ...target,
      campaign_template: { ...campaignTemplate, hosted_run: null },
    }]);
    expect(() => decodeTargets([{
      ...target,
      campaign_template: {
        ...campaignTemplate,
        hosted_run: {
          ...hostedRun,
          credential_reference: "secretref://staging/openrouter/generation-1",
        },
      },
    }])).toThrow("Invalid hosted run binding read model");
  });

  it("fails a malformed ready envelope closed without exposing its payload", async () => {
    const client = createApiClient({
      origin: "https://headshot.test",
      getToken: async () => "fixture-session",
      fetchImpl: vi.fn<typeof fetch>().mockResolvedValue(
        new Response(JSON.stringify({ state: "ready", data: [{ run_id: 42 }] })),
      ),
    });

    const { result } = renderHook(() =>
      useResource(client, "campaigns", decodeCampaigns),
    );

    await waitFor(() => expect(result.current.result.state).toBe("error"));
    expect(result.current.result).toEqual({
      state: "error",
      data: null,
      reason_code: "invalid_response_contract",
    });
  });

  it("preserves an unavailable envelope without invoking its data decoder", async () => {
    const decode = vi.fn(decodeCampaigns);
    const client = createApiClient({
      origin: "https://headshot.test",
      getToken: async () => "fixture-session",
      fetchImpl: vi.fn<typeof fetch>().mockResolvedValue(
        new Response(JSON.stringify({ state: "unavailable", data: null, reason_code: "repository_missing" })),
      ),
    });

    const { result } = renderHook(() => useResource(client, "campaigns", decode));

    await waitFor(() => expect(result.current.result.state).toBe("unavailable"));
    expect(result.current.result.reason_code).toBe("repository_missing");
    expect(decode).not.toHaveBeenCalled();
  });

  it("reconciles cost token observations while allowing one-sided provider usage", () => {
    const cost = arrayFixtureRecord("costs");
    const oneSided = {
      ...cost,
      input_tokens: 120,
      output_tokens: null,
      token_observation_count: 1,
    };

    expect(decodeCosts([oneSided])).toEqual([oneSided]);
    expect(() => decodeCosts([{
      ...cost,
      input_tokens: 120,
      token_observation_count: 0,
    }])).toThrow("Invalid cost read model");
    expect(() => decodeCosts([{
      ...cost,
      input_tokens: null,
      output_tokens: null,
      token_observation_count: 1,
    }])).toThrow("Invalid cost read model");
  });

  it("keeps unavailable provider-call average cost null", () => {
    const campaign = arrayFixtureRecord("costs");
    const unavailable = {
      ...campaign,
      accounting_id: "agent-cost-unavailable",
      provider: "agent:documentation:openrouter/openai/gpt-5.4",
      agent_role: "documentation",
      record_kind: "agent",
      execution_mode: "hosted_advisory",
      measured_cost: null,
      cost_measurement_state: "not_observed",
      accounting_status: "unavailable",
      provider_event_ids: ["f".repeat(64)],
      request_count: 1,
      execution_count: 1,
      attempt_count: 0,
      confirmed_finding_count: 0,
      average_cost_per_request: null,
      physical_call_count: 1,
      physical_call_count_state: "exact",
      provider_budget: unavailableProviderBudget,
      p50_duration_ms: 10,
      p95_duration_ms: 10,
      budget_usd: null,
      budget_utilization: null,
    };

    expect(decodeCosts([unavailable])).toEqual([unavailable]);
    expect(() => decodeCosts([{
      ...unavailable,
      average_cost_per_request: 0,
    }])).toThrow("Invalid cost read model");
  });

  it("requires authoritative paired role latency only for completed agent costs", () => {
    const campaign = arrayFixtureRecord("costs");
    const agent = {
      ...campaign,
      accounting_id: "agent-cost-1",
      provider: "agent:red_team:headshot/full-scan-corpus-v1",
      agent_role: "red_team",
      record_kind: "agent",
      execution_mode: "deterministic",
      request_count: 0,
      execution_count: 1,
      attempt_count: 1,
      confirmed_finding_count: 0,
      average_cost_per_request: null,
      provider_budget: unavailableProviderBudget,
      budget_usd: null,
      budget_utilization: null,
      p50_duration_ms: 10,
      p95_duration_ms: 20,
    };

    expect(decodeCosts([agent])).toEqual([agent]);
    for (const malformed of [
      { ...campaign, p50_duration_ms: 10, p95_duration_ms: 20 },
      { ...agent, p95_duration_ms: null },
      { ...agent, p50_duration_ms: 30 },
      { ...agent, execution_count: 0 },
    ]) {
      expect(() => decodeCosts([malformed])).toThrow("Invalid cost read model");
    }
  });

  it("only treats query-back verified Langfuse records as remotely observed", () => {
    const trace = arrayFixtureRecord("traces");
    const observed = { ...trace, langfuse_status: "exported", langfuse_verified_at: at };
    const historical = { ...trace, langfuse_status: "historical_not_instrumented" };

    expect(decodeTraces([trace])).toEqual([trace]);
    expect(decodeTraces([observed])).toEqual([observed]);
    expect(decodeTraces([historical])).toEqual([historical]);
    expect(() => decodeTraces([{
      ...trace,
      langfuse_status: "exported",
    }])).toThrow("Invalid trace read model");
    expect(() => decodeTraces([{
      ...observed,
      langfuse_status: "error",
    }])).toThrow("Invalid trace read model");
  });

  it("accepts server-projected role latency only on agent traces", () => {
    const physical = arrayFixtureRecord("traces");
    const agent = {
      ...physical,
      request_id: null,
      execution_id: "execution-1",
      model: "full-scan-corpus-v1",
      agent_role: "red_team",
      execution_mode: "deterministic",
      requested_model: "headshot/full-scan-corpus-v1",
      method: null,
      destination_host: null,
      relative_path: null,
      status_code: null,
      request_bytes: 0,
      response_bytes: null,
      p50_duration_ms: 10,
      p95_duration_ms: 20,
    };

    expect(decodeTraces([agent])).toEqual([agent]);
    for (const malformed of [
      { ...physical, p50_duration_ms: 10, p95_duration_ms: 20 },
      { ...agent, p95_duration_ms: null },
      { ...agent, p50_duration_ms: 30 },
    ]) {
      expect(() => decodeTraces([malformed])).toThrow("Invalid trace read model");
    }
  });

  it("allows a provider event gap only while an agent trace is running", () => {
    const physical = arrayFixtureRecord("traces");
    const running = {
      ...physical,
      request_id: null,
      execution_id: "execution-running-provider-gap",
      agent_role: "red_team",
      execution_mode: "hosted_advisory",
      provider: "openrouter",
      model: "qwen/qwen3.5-397b-a17b",
      requested_model: "qwen/qwen3.5-397b-a17b",
      configuration_set_sha256: "c".repeat(64),
      role_configuration_sha256: "d".repeat(64),
      generation_policy_sha256: "e".repeat(64),
      physical_attempts: 2,
      method: null,
      destination_host: null,
      relative_path: null,
      status: "running",
      status_code: null,
      finished_at: null,
      duration_ms: null,
      request_bytes: 0,
      response_bytes: null,
      measured_cost: null,
      cost_measurement_state: "not_observed",
      accounting_status: "unavailable",
      provider_event_ids: ["f".repeat(64)],
      provider_event_status: "retryable_failure",
      provider_lineage_state: "canonical_physical",
      p50_duration_ms: null,
      p95_duration_ms: null,
    };

    expect(decodeTraces([running])).toEqual([running]);
    const inputOnlyWithoutCost = {
      ...running,
      input_tokens: 37,
    };
    const outputOnlyWithoutCost = {
      ...running,
      output_tokens: 11,
    };
    expect(decodeTraces([inputOnlyWithoutCost])).toEqual([
      inputOnlyWithoutCost,
    ]);
    expect(decodeTraces([outputOnlyWithoutCost])).toEqual([
      outputOnlyWithoutCost,
    ]);
    const historical = {
      ...running,
      status: "failed",
      finished_at: at,
      duration_ms: 10,
      measured_cost: 0.01,
      cost_measurement_state: "partial",
      accounting_status: "partial",
      provider_event_ids: [],
      provider_event_status: null,
      provider_lineage_state: "historical_not_instrumented",
      p50_duration_ms: 10,
      p95_duration_ms: 10,
    };
    expect(decodeTraces([historical])).toEqual([historical]);
    expect(() => decodeTraces([{
      ...running,
      status: "failed",
      finished_at: at,
      duration_ms: 10,
      p50_duration_ms: 10,
      p95_duration_ms: 10,
    }])).toThrow("Invalid trace read model");
  });

  it("uses the latest provider event to classify safe model substitution", () => {
    const physical = arrayFixtureRecord("traces");
    const identityInvalid = {
      ...physical,
      request_id: null,
      execution_id: "execution-identity-invalid",
      agent_role: "red_team",
      execution_mode: "hosted_advisory",
      provider: "openrouter",
      model: "qwen/qwen3.5-397b-a17b",
      requested_model: "qwen/qwen3.5-397b-a17b",
      returned_model: "unsafe-provider-text-redacted",
      model_substituted: false,
      upstream_provider: "redacted",
      provider_request_id: "redacted",
      configuration_set_sha256: "c".repeat(64),
      role_configuration_sha256: "d".repeat(64),
      generation_policy_sha256: "e".repeat(64),
      physical_attempts: 1,
      method: null,
      destination_host: null,
      relative_path: null,
      status: "failed",
      status_code: null,
      error_code: "provider_identity_invalid",
      request_bytes: 0,
      response_bytes: null,
      measured_cost: null,
      cost_measurement_state: "invalid",
      accounting_status: "unavailable",
      provider_event_ids: ["f".repeat(64)],
      provider_event_status: "identity_invalid",
      provider_lineage_state: "canonical_physical",
      p50_duration_ms: 12.5,
      p95_duration_ms: 12.5,
    };
    const safeSubstitution = {
      ...identityInvalid,
      returned_model: "openai/gpt-5.4",
      model_substituted: true,
      upstream_provider: "OpenAI",
      provider_request_id: "provider-request-1",
      error_code: "provider_model_substituted",
      provider_event_status: "model_mismatch",
    };

    expect(decodeTraces([identityInvalid])).toEqual([identityInvalid]);
    expect(decodeTraces([safeSubstitution])).toEqual([safeSubstitution]);
    expect(() => decodeTraces([{
      ...safeSubstitution,
      model_substituted: false,
    }])).toThrow("Invalid trace read model");
    expect(() => decodeTraces([{
      ...identityInvalid,
      model_substituted: true,
    }])).toThrow("Invalid trace read model");
  });

  it("reconciles aggregate agent execution, delivery, token, and latency metrics", () => {
    const agent = arrayFixtureRecord("agents");
    const oneSidedTokens = {
      ...agent,
      input_tokens: null,
      output_tokens: 30,
      token_observation_count: 1,
    };
    const runningOnly = {
      ...agent,
      execution_count: 1,
      running_count: 1,
      succeeded_count: 0,
      average_duration_ms: null,
      p50_duration_ms: null,
      p95_duration_ms: null,
      langfuse_queued_count: 1,
      langfuse_exported_count: 0,
      langfuse_verified_count: 0,
      last_langfuse_verified_at: null,
      last_status: "running",
    };

    expect(decodeAgents([oneSidedTokens])).toEqual([oneSidedTokens]);
    expect(decodeAgents([runningOnly])).toEqual([runningOnly]);
    for (const malformed of [
      { ...agent, running_count: 1 },
      { ...agent, langfuse_error_count: 1 },
      { ...agent, token_observation_count: 1 },
      { ...agent, p95_duration_ms: null },
      { ...agent, langfuse_verified_count: 2 },
      { ...agent, last_langfuse_verified_at: null },
      { ...runningOnly, p50_duration_ms: 5 },
    ]) {
      expect(() => decodeAgents([malformed])).toThrow("Invalid agent read model");
    }
  });

  it("accepts an unavailable or durably observed provider-served model identity", () => {
    const agent = arrayFixtureRecord("agents");
    const assignment = agent.active_assignment;
    if (assignment === null || typeof assignment !== "object" || Array.isArray(assignment)) {
      throw new Error("Missing active assignment fixture");
    }
    const observed = {
      ...agent,
      active_assignment: {
        ...assignment,
        resolved_model: "anthropic/claude-opus-4.8",
        upstream_provider: "Anthropic",
      },
    };

    expect(decodeAgents([agent])).toEqual([agent]);
    expect(decodeAgents([observed])).toEqual([observed]);
    for (const partialOrMalformed of [
      { ...assignment, resolved_model: "anthropic/claude-opus-4.8", upstream_provider: null },
      { ...assignment, resolved_model: null, upstream_provider: "Anthropic" },
      { ...assignment, resolved_model: 42, upstream_provider: null },
    ]) {
      expect(() => decodeAgents([{
        ...agent,
        active_assignment: partialOrMalformed,
      }])).toThrow("Invalid agent assignment read model");
    }
  });

  it("keeps target-free acceptance evidence separate from campaign activation", () => {
    const agent = arrayFixtureRecord("agents");
    const acceptance = {
      scope: "agent_acceptance",
      agent_role: "orchestrator",
      acceptance_run_id: "AR-live-acceptance",
      acceptance_attempt_id: "b".repeat(64),
      execution_id: "acceptance-execution-1",
      parent_execution_id: null,
      configuration_set_sha256: "c".repeat(64),
      returned_model: "anthropic/claude-opus-4.8",
      upstream_provider: "Anthropic",
      trace_id: "d".repeat(32),
      measured_cost: 0.03,
      cost_measurement_state: "measured",
      provider_event_ids: ["e".repeat(64)],
      currency: "USD",
      input_tokens: 100,
      output_tokens: 20,
      reasoning_tokens: 10,
      langfuse_status: "exported",
      langfuse_verified_at: at,
      finished_at: at,
    };
    const observed = {
      ...agent,
      latest_acceptance_execution: acceptance,
    };
    const redTeamObserved = {
      ...agent,
      role: "red_team",
      active_assignment: {
        ...(agent.active_assignment as Record<string, unknown>),
        role: "red_team",
      },
      staged_assignment: agent.staged_assignment === null
        ? null
        : {
          ...(agent.staged_assignment as Record<string, unknown>),
          role: "red_team",
        },
      latest_acceptance_execution: {
        ...acceptance,
        agent_role: "red_team",
        parent_execution_id: "acceptance-execution-planner",
        returned_model: "qwen/qwen3.5-397b-a17b",
        upstream_provider: "Together",
      },
    };

    expect(decodeAgents([observed])).toEqual([observed]);
    expect(decodeAgents([redTeamObserved])).toEqual([redTeamObserved]);
    expect(observed.active_assignment).toEqual(agent.active_assignment);
    for (const malformed of [
      { ...acceptance, scope: "campaign" },
      { ...acceptance, agent_role: "unreviewed_generator" },
      { ...acceptance, acceptance_run_id: "campaign-1" },
      { ...acceptance, acceptance_attempt_id: "not-an-attempt" },
      { ...acceptance, provider_event_ids: [] },
      { ...acceptance, provider_event_ids: ["e".repeat(32)] },
      { ...acceptance, cost_measurement_state: "partial" },
      { ...acceptance, langfuse_verified_at: null },
      { ...acceptance, measured_cost: -0.01 },
      { ...acceptance, extra: "schema drift" },
    ]) {
      expect(() => decodeAgents([{
        ...agent,
        latest_acceptance_execution: malformed,
      }])).toThrow();
    }
  });

  it("reconciles hosted subcaps and honestly labels evaluator authority", () => {
    const base = arrayFixtureRecord("agents");
    const assignment = base.active_assignment;
    if (assignment === null || typeof assignment !== "object" || Array.isArray(assignment)) {
      throw new Error("Missing active assignment fixture");
    }
    const budget = {
      status: "active",
      campaign_run_id: "run-1",
      configuration_set_sha256: "c".repeat(64),
      role_cost_measurement_state: "measured",
      role_usd_cap: 4,
      role_usd_spent: 0.25,
      role_unresolved_usd_exposure: 0,
      role_usd_remaining: 3.75,
      role_usd_remaining_upper_bound: 3.75,
      role_usd_overrun: 0,
      role_call_cap: 10,
      role_physical_calls: 1,
      role_unresolved_physical_calls: 0,
      role_call_count_state: "exact",
      role_calls_remaining: 9,
      role_call_overrun: 0,
      global_cost_measurement_state: "measured",
      global_usd_cap: 10,
      global_usd_spent: 0.25,
      global_unresolved_usd_exposure: 0,
      global_usd_remaining: 9.75,
      global_usd_remaining_upper_bound: 9.75,
      global_usd_overrun: 0,
      global_call_cap: 56,
      global_physical_calls: 1,
      global_unresolved_physical_calls: 0,
      global_call_count_state: "exact",
      global_calls_remaining: 55,
      global_call_overrun: 0,
    };
    const calibration = {
      state: "failed",
      calibration_id: "judge-calibration-1",
      decision_authority: "oracle",
      oracle_comparison_count: 3,
      oracle_agreement_count: 2,
      oracle_agreement_rate: 2 / 3,
      status_label: "live, verified against oracle",
    };
    const judge = {
      ...base,
      role: "judge",
      display_name: "Evaluator",
      active_assignment: {
        ...assignment,
        role: "judge",
        provider: "openrouter",
        model: "google/gemini-2.5-pro",
        resolved_model: "google/gemini-2.5-pro",
        upstream_provider: "Google",
        execution_mode: "hosted_advisory",
        configuration_sha256: "c".repeat(64),
      },
      measured_cost: 0.25,
      cost_measurement_state: "measured",
      provider_event_ids: ["f".repeat(64)],
      hosted_execution_count: 1,
      input_tokens: 100,
      output_tokens: 20,
      reasoning_tokens: 10,
      token_observation_count: 1,
      physical_call_count: 1,
      physical_call_count_state: "exact",
      provider_budget: budget,
      judge_calibration: calibration,
    };
    const partiallyMeasured = {
      ...judge,
      provider_budget: {
        ...budget,
        role_cost_measurement_state: "partial",
        role_unresolved_usd_exposure: 0.5,
        role_usd_remaining: 3.25,
        role_unresolved_physical_calls: 2,
        role_call_count_state: "lower_bound",
        role_calls_remaining: 7,
        global_cost_measurement_state: "not_observed",
        global_unresolved_usd_exposure: 0.5,
        global_usd_remaining: 9.25,
        global_unresolved_physical_calls: 2,
        global_call_count_state: "lower_bound",
        global_calls_remaining: 53,
      },
    };

    expect(decodeAgents([judge])).toEqual([judge]);
    expect(decodeAgents([{
      ...judge,
      provider_budget: { ...budget, status: "historical" },
    }])).toEqual([{
      ...judge,
      provider_budget: { ...budget, status: "historical" },
    }]);
    expect(decodeAgents([partiallyMeasured])).toEqual([partiallyMeasured]);
    expect(decodeAgents([{
      ...judge,
      provider_budget: {
        ...budget,
        status: "agent_acceptance",
        campaign_run_id: "AR-live-acceptance",
      },
    }])).toEqual([{
      ...judge,
      provider_budget: {
        ...budget,
        status: "agent_acceptance",
        campaign_run_id: "AR-live-acceptance",
      },
    }]);
    expect(() => decodeAgents([{
      ...judge,
      provider_budget: {
        ...budget,
        status: "agent_acceptance",
        campaign_run_id: "campaign-1",
      },
    }])).toThrow("Invalid agent budget read model");
    expect(() => decodeAgents([{
      ...judge,
      judge_calibration: {
        ...calibration,
        decision_authority: "model",
      },
    }])).toThrow("Invalid judge calibration read model");
    expect(() => decodeAgents([{
      ...judge,
      provider_budget: {
        ...budget,
        role_usd_remaining: 3.5,
      },
    }])).toThrow("Invalid agent budget read model");
    expect(() => decodeAgents([{
      ...judge,
      provider_budget: {
        ...budget,
        role_unresolved_physical_calls: 1,
      },
    }])).toThrow("Invalid agent budget read model");
    const missingExposure: Record<string, unknown> = { ...budget };
    delete missingExposure.global_unresolved_usd_exposure;
    expect(() => decodeAgents([{
      ...judge,
      provider_budget: missingExposure,
    }])).toThrow("Invalid agent budget read model");
  });

  it("accepts Python-serialized active reservations without weakening terminal budgets", () => {
    const base = arrayFixtureRecord("agents");
    const assignment = base.active_assignment;
    if (assignment === null || typeof assignment !== "object" || Array.isArray(assignment)) {
      throw new Error("Missing active assignment fixture");
    }
    const activeAgent = {
      ...base,
      active_assignment: {
        ...assignment,
        provider: "openrouter",
        model: "anthropic/claude-opus-4.8",
        resolved_model: "anthropic/claude-opus-4.8",
        upstream_provider: "Anthropic",
        execution_mode: "hosted_advisory",
        configuration_sha256: "c".repeat(64),
      },
      execution_count: 2,
      hosted_execution_count: 2,
      running_count: 1,
      succeeded_count: 1,
      measured_cost: 0.1,
      cost_measurement_state: "measured",
      provider_event_ids: ["d".repeat(64), "e".repeat(64)],
      input_tokens: 100,
      output_tokens: 20,
      reasoning_tokens: 5,
      token_observation_count: 1,
      physical_call_count: 2,
      physical_call_count_state: "exact",
      provider_budget: activeRunningAgentBudget,
      langfuse_queued_count: 1,
      langfuse_exported_count: 1,
      langfuse_verified_count: 1,
      last_status: "running",
    };

    expect(decodeAgents([activeAgent])).toEqual([activeAgent]);
    const nonActiveCostReservation = {
      ...activeRunningAgentBudget,
      status: "historical",
      role_unresolved_physical_calls: 0,
      role_calls_remaining: 17,
      global_unresolved_physical_calls: 0,
      global_calls_remaining: 54,
    };
    const nonActiveCallReservation = {
      ...activeRunningAgentBudget,
      status: "historical",
      role_unresolved_usd_exposure: 0,
      role_usd_remaining: 2.4,
      global_unresolved_usd_exposure: 0,
      global_usd_remaining: 4.9,
    };
    for (const impossibleTerminalBudget of [
      nonActiveCostReservation,
      nonActiveCallReservation,
    ]) {
      expect(() => decodeAgents([{
        ...activeAgent,
        provider_budget: impossibleTerminalBudget,
      }])).toThrow("Invalid agent budget read model");
    }
  });

  it("enforces running and terminal agent activity shapes", () => {
    const terminal = {
      execution_id: "execution-1",
      campaign_run_id: "run-1",
      attempt_id: null,
      parent_execution_id: null,
      agent_role: "orchestrator",
      status: "succeeded",
      provider: "headshot",
      model: "coverage-governor-v1",
      returned_model: null,
      model_substituted: false,
      upstream_provider: null,
      provider_request_id: null,
      execution_mode: "deterministic",
      configuration_version: 1,
      configuration_set_sha256: null,
      role_configuration_sha256: null,
      generation_policy_sha256: null,
      input_sha256: "a".repeat(64),
      output_sha256: "b".repeat(64),
      input_tokens: null,
      output_tokens: null,
      reasoning_tokens: null,
      physical_attempts: null,
      measured_cost: 0,
      cost_measurement_state: "measured",
      accounting_status: "measured",
      provider_event_ids: [],
      provider_event_status: null,
      provider_lineage_state: "not_applicable",
      currency: "USD",
      trace_id: "trace-1",
      langfuse_status: "exported",
      langfuse_verified_at: at,
      detail: {},
      judge_calibration_id: null,
      judge_calibration_state: null,
      oracle_agreement: null,
      decision_authority: null,
      error_code: null,
      started_at: at,
      finished_at: at,
      duration_ms: 5,
    };
    const running = {
      ...terminal,
      status: "running",
      output_sha256: null,
      finished_at: null,
      duration_ms: null,
      langfuse_status: "queued",
      langfuse_verified_at: null,
    };
    const hostedMeasured = {
      ...terminal,
      execution_mode: "hosted_advisory",
      provider: "openrouter",
      model: "anthropic/claude-opus-4.8",
      returned_model: "anthropic/claude-opus-4.8",
      model_substituted: false,
      upstream_provider: "Anthropic",
      provider_request_id: "openrouter-request-1",
      configuration_set_sha256: "c".repeat(64),
      role_configuration_sha256: "d".repeat(64),
      generation_policy_sha256: "e".repeat(64),
      input_tokens: 100,
      output_tokens: 20,
      reasoning_tokens: 0,
      physical_attempts: 1,
      measured_cost: 0.01,
      cost_measurement_state: "measured",
      provider_event_ids: ["f".repeat(64)],
      provider_event_status: "succeeded",
      provider_lineage_state: "canonical_physical",
      detail: { provider_lineage_state: "canonical_physical" },
    };
    const hostedUnavailable = {
      ...terminal,
      execution_mode: "hosted_advisory",
      measured_cost: null,
      cost_measurement_state: "not_observed",
      accounting_status: "unavailable",
      provider_lineage_state: "canonical_physical",
      detail: { provider_lineage_state: "canonical_physical" },
    };
    const hostedPartial = {
      ...hostedUnavailable,
      physical_attempts: 2,
      measured_cost: 0,
      cost_measurement_state: "partial",
      accounting_status: "partial",
      provider_event_ids: ["e".repeat(64), "f".repeat(64)],
      provider_event_status: "retryable_failure",
    };
    const hostedRunningReservationGap = {
      ...running,
      execution_mode: "hosted_advisory",
      configuration_set_sha256: "c".repeat(64),
      role_configuration_sha256: "d".repeat(64),
      generation_policy_sha256: "e".repeat(64),
      physical_attempts: 2,
      measured_cost: null,
      cost_measurement_state: "not_observed",
      accounting_status: "unavailable",
      provider_event_ids: ["f".repeat(64)],
      provider_event_status: "retryable_failure",
      provider_lineage_state: "canonical_physical",
      detail: { provider_lineage_state: "canonical_physical" },
    };
    const evaluatorMeasured = {
      ...hostedMeasured,
      agent_role: "judge",
      judge_calibration_id: "judge-calibration-1",
      judge_calibration_state: "failed",
      oracle_agreement: false,
      decision_authority: "oracle",
    };
    const historical = {
      ...hostedPartial,
      provider_event_ids: [],
      provider_event_status: null,
      provider_lineage_state: "historical_not_instrumented",
      detail: { provider_lineage_state: "historical_not_instrumented" },
    };

    expect(decodeAgentActivity([terminal])).toEqual([terminal]);
    expect(decodeAgentActivity([running])).toEqual([running]);
    expect(decodeAgentActivity([hostedMeasured])).toEqual([hostedMeasured]);
    expect(decodeAgentActivity([hostedUnavailable])).toEqual([hostedUnavailable]);
    expect(decodeAgentActivity([{
      ...hostedUnavailable,
      input_tokens: 1,
    }])).toEqual([{
      ...hostedUnavailable,
      input_tokens: 1,
    }]);
    expect(decodeAgentActivity([hostedPartial])).toEqual([hostedPartial]);
    expect(decodeAgentActivity([hostedRunningReservationGap])).toEqual([
      hostedRunningReservationGap,
    ]);
    expect(decodeAgentActivity([evaluatorMeasured])).toEqual([evaluatorMeasured]);
    expect(decodeAgentActivity([historical])).toEqual([historical]);
    for (const malformed of [
      { ...running, finished_at: at },
      { ...terminal, output_sha256: null },
      { ...terminal, output_sha256: "not-a-sha256" },
      { ...terminal, duration_ms: null },
      { ...running, langfuse_verified_at: at },
      { ...terminal, accounting_status: "unavailable" },
      { ...hostedUnavailable, accounting_status: "measured" },
      { ...hostedUnavailable, accounting_status: "partial" },
      { ...hostedUnavailable, measured_cost: 0.01 },
      {
        ...evaluatorMeasured,
        decision_authority: "model",
      },
      {
        ...hostedMeasured,
        provider_event_ids: ["d".repeat(64), "e".repeat(64)],
      },
      {
        ...hostedMeasured,
        provider_event_ids: ["not-a-sha256"],
      },
      {
        ...hostedRunningReservationGap,
        status: "failed",
        output_sha256: "b".repeat(64),
        finished_at: at,
        duration_ms: 5,
      },
    ]) {
      expect(() => decodeAgentActivity([malformed])).toThrow(
        "Invalid agent activity read model",
      );
    }
  });

  it("requires internally consistent observability on Birdseye agent nodes", () => {
    const snapshot = objectFixture("Birdseye snapshot");
    const existingNode = (
      snapshot.nodes as Array<Record<string, unknown>>
    )[0];
    const agentNode = {
      ...existingNode,
      component_id: "agent:judge",
      name: "Judge",
      kind: "agent:judge",
      trust_zone: "evaluation",
      runtime_state: "ready",
      current_task: "Latest execution succeeded",
      p50_latency_ms: 5,
      p95_latency_ms: 8,
      execution_count: 1,
      measured_cost_usd: 0,
      accounting_status: "measured",
      currency: "USD",
      input_tokens: 25,
      output_tokens: null,
      token_observation_count: 1,
      langfuse_not_attempted_count: 0,
      langfuse_disabled_count: 0,
      langfuse_queued_count: 0,
      langfuse_exported_count: 1,
      langfuse_error_count: 0,
      langfuse_verified_count: 1,
      last_langfuse_verified_at: at,
      langfuse_status: "exported",
      queue_depth: null,
    };
    const unobservedAgentNode = {
      ...agentNode,
      runtime_state: "unavailable",
      p50_latency_ms: null,
      p95_latency_ms: null,
      execution_count: 0,
      measured_cost_usd: null,
      accounting_status: "not_applicable",
      currency: null,
      input_tokens: null,
      output_tokens: null,
      token_observation_count: 0,
      langfuse_exported_count: 0,
      langfuse_verified_count: 0,
      last_langfuse_verified_at: null,
      langfuse_status: null,
    };
    const staleRunningAgentNode = {
      ...agentNode,
      runtime_state: "stale",
      current_task: "Running judge campaign work",
      p50_latency_ms: null,
      p95_latency_ms: null,
    };
    const unavailableAccountingAgentNode = {
      ...agentNode,
      measured_cost_usd: 0,
      accounting_status: "unavailable",
      input_tokens: 25,
      output_tokens: null,
      token_observation_count: 1,
    };

    expect(decodeBirdseye({ ...snapshot, nodes: [agentNode] })).toEqual({
      ...snapshot,
      nodes: [agentNode],
    });
    expect(decodeBirdseye({ ...snapshot, nodes: [unobservedAgentNode] })).toEqual({
      ...snapshot,
      nodes: [unobservedAgentNode],
    });
    expect(decodeBirdseye({ ...snapshot, nodes: [staleRunningAgentNode] })).toEqual({
      ...snapshot,
      nodes: [staleRunningAgentNode],
    });
    expect(decodeBirdseye({
      ...snapshot,
      nodes: [unavailableAccountingAgentNode],
    })).toEqual({
      ...snapshot,
      nodes: [unavailableAccountingAgentNode],
    });
    for (const malformedNode of [
      { ...agentNode, execution_count: null },
      { ...agentNode, langfuse_error_count: 1 },
      { ...agentNode, token_observation_count: 0 },
      { ...agentNode, measured_cost_usd: null },
      { ...agentNode, p95_latency_ms: null },
      { ...agentNode, langfuse_verified_count: 2 },
      { ...agentNode, last_langfuse_verified_at: null },
      { ...agentNode, accounting_status: "not_applicable" },
    ]) {
      expect(() => decodeBirdseye({
        ...snapshot,
        nodes: [malformedNode],
      })).toThrow("Invalid Birdseye node read model");
    }
  });

  it("keeps agent-only observability null on non-agent Birdseye nodes", () => {
    const snapshot = objectFixture("Birdseye snapshot");
    const existingNode = (
      snapshot.nodes as Array<Record<string, unknown>>
    )[0];

    expect(() => decodeBirdseye({
      ...snapshot,
      nodes: [{ ...existingNode, execution_count: 0 }],
    })).toThrow("Invalid Birdseye node read model");
  });

  it("enforces running and terminal Birdseye agent activity timing", () => {
    const snapshot = objectFixture("Birdseye snapshot");
    const terminal = (
      snapshot.agent_activity as Array<Record<string, unknown>>
    )[0];
    const running = {
      ...terminal,
      status: "running",
      finished_at: null,
      duration_ms: null,
    };

    expect(decodeBirdseye({ ...snapshot, agent_activity: [running] })).toEqual({
      ...snapshot,
      agent_activity: [running],
    });
    expect(() => decodeBirdseye({
      ...snapshot,
      agent_activity: [{ ...terminal, duration_ms: null }],
    })).toThrow("Invalid Birdseye agent activity read model");
  });
});
