import { renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { createApiClient } from "../src/api/client";
import {
  decodeApprovals,
  decodeApprovalDetail,
  decodeAgentPrompt,
  decodeAgents,
  decodeAttempts,
  decodeAuditHistory,
  decodeBirdseye,
  decodeCampaigns,
  decodeComponents,
  decodeConfiguration,
  decodeCosts,
  decodeEvidence,
  decodeFinding,
  decodeFindings,
  decodePrincipal,
  decodeReports,
  decodeTargets,
  decodeTraces,
} from "../src/api/read-models";
import { useResource } from "../src/hooks/useResource";

const at = "2026-07-21T00:00:00Z";
const caps = {
  budget_usd: 1,
  max_attempts_per_run: 2,
  target_requests_per_second: 0.5,
  run_timeout_seconds: 60,
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
  evidence_content_hash: "content-1",
  history: [{ decision: "confirmed", actor_user_id: "user-1", rationale: "evidence", created_at: at }],
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
    [{ request_id: "request-1", execution_id: null, parent_execution_id: null, trace_id: "trace-1", campaign_id: "run-1", attempt_id: "attempt-1", operation: "target.http", provider: "openemr", agent_role: null, execution_mode: null, method: "POST", destination_host: "target.invalid", relative_path: "chat", status: "succeeded", status_code: 200, error_code: null, started_at: at, finished_at: "2026-07-21T00:00:00.012Z", duration_ms: 12.5, request_bytes: 25, response_bytes: 50, measured_cost: 0.01, currency: "USD", input_tokens: null, output_tokens: null, langfuse_status: "exported", request_preview: '{"turns":["synthetic"]}', response_preview: '{"answer":"safe"}', request_sha256: "a".repeat(64), response_sha256: "b".repeat(64), inspection_flags: [], inspection_owasp_mappings: [] }],
  ],
  [
    "costs",
    decodeCosts,
    [{ accounting_id: "accounting-1", campaign_id: "run-1", provider: "provider", agent_role: null, record_kind: "campaign", measured_cost: 0.25, currency: "USD", request_count: 5, execution_count: 0, attempt_count: 5, confirmed_finding_count: 1, average_cost_per_request: 0.05, input_tokens: null, output_tokens: null, token_observation_count: 0, budget_usd: 1, budget_utilization: 0.25, duration_ms: 2500, execution_profile: "live", started_at: at, ended_at: "2026-07-21T00:00:02.500Z", recorded_at: at }],
  ],
  [
    "targets and surfaces",
    decodeTargets,
    [{ target_id: "target-1", name: "Registered target", version: "1.0.0", content_hash: "target-hash", lifecycle: "ready", environment: "staging", adapter_kind: "openemr", base_url: "https://target.invalid", auth_mode: "bearer", credential_configured: true, synthetic_data_only: true, safety_caps: caps, allowed_lifecycle_transitions: ["disabled"], campaign_template: null, created_at: at, surfaces: [{ surface_id: "surface-1", version: "1.0.0", target_version: "1.0.0", content_hash: "surface-hash", kind: "chat", protocol: "https", method: "POST", relative_path: "api", trust_boundary: "external-target", authentication_required: true, risk: "high", owasp_mappings: [], oracle_refs: [], enabled: true, created_at: at }] }],
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
        resolved_model: "coverage-governor-v1",
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
      execution_count: 1,
      running_count: 0,
      succeeded_count: 1,
      failed_count: 0,
      skipped_count: 0,
      measured_cost: 0,
      currency: "USD",
      input_tokens: null,
      output_tokens: null,
      token_observation_count: 0,
      average_duration_ms: 5,
      p50_duration_ms: 5,
      p95_duration_ms: 5,
      langfuse_exported_count: 1,
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
        currency: null,
        langfuse_exported_count: null,
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

describe("v1 read-model decoders", () => {
  it.each(validResources)("accepts the explicit %s contract", (_name, decode, value) => {
    expect(decode(value)).toEqual(value);
  });

  it.each(validResources)("rejects malformed ready %s data", (_name, decode, value) => {
    const malformed = Array.isArray(value) ? [{ unexpected: true }] : { unexpected: true };
    expect(() => decode(malformed)).toThrow("Invalid");
  });

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
});
