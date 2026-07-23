import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Birdseye } from "../src/components/Birdseye";
import type { BirdseyeSnapshotReadModel } from "../src/types";

const at = "2026-07-23T12:00:00Z";

const snapshot: BirdseyeSnapshotReadModel = {
  campaign: {
    run_id: "run-live-001",
    target_id: "openemr-copilot",
    target_name: "OpenEMR Clinical Co-Pilot",
    target_version: "2.0.0",
    state: "running",
    execution_profile: "live",
    scope_hash: "scope-001",
    attempt_count: 4,
  },
  instrumentation: {
    budget_usd: 5,
    measured_cost_usd: 1.25,
    budget_utilization: 0.25,
    requests_per_second_cap: 1,
    queue_queued: 2,
    queue_leased: 1,
    queue_dead_letter: 0,
    confirmed_count: 1,
    likely_count: 1,
    review_count: 0,
    healthy_components: 2,
    total_components: 2,
    system_state: "nominal",
  },
  security_posture: {
    tested_categories: 2,
    required_categories: 3,
    verified_case_count: 4,
    held_count: 2,
    exploited_count: 1,
    review_count: 1,
    observed_hold_rate: 2 / 3,
    open_finding_count: 1,
    in_progress_finding_count: 1,
    resolved_finding_count: 2,
    critical_open_finding_count: 1,
    resilience_direction: "improving",
    current_regression_hold_rate: 0.75,
    previous_regression_hold_rate: 0.5,
    resilience_delta: 0.25,
    cost_per_attempt_usd: 0.3125,
    cost_velocity_usd_per_minute: 0.5,
    projected_cost_at_attempt_cap_usd: 2.8125,
    priority_category: "prompt_injection",
    priority_reason: "Coverage gap requires another verified case.",
    priority_source: "orchestrator_decision",
    priority_at: at,
  },
  category_outcomes: [{
    target_version: "2.0.0",
    category: "prompt_injection",
    verified_case_count: 2,
    verified_attempt_count: 2,
    held_count: 1,
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
  nodes: [
    {
      component_id: "web-api",
      name: "Operator console API",
      kind: "web",
      trust_zone: "human",
      availability: "operational and evidenced",
      runtime_state: "ready",
      detail: "Authenticated snapshot responded",
      current_task: "Serving the protected console snapshot",
      heartbeat_at: at,
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
      heartbeat_at: at,
      freshness_seconds: 2,
      is_fresh: true,
      healthy_instances: 1,
      total_instances: 1,
      p50_latency_ms: 18,
      p95_latency_ms: 40,
      queue_depth: 3,
      target_access: "policy-gated",
    },
  ],
  edges: [{
    edge_id: "web-to-runner",
    source_component_id: "web-api",
    target_component_id: "runner",
    contract_name: "CampaignDirective",
    state: "active",
    attempt_id: "attempt-1",
    last_event_at: at,
    detail: "Authorized handoff",
  }],
  attention: [{
    attention_id: "approval:request-1",
    priority: 1,
    kind: "approval",
    title: "Campaign authorization requires a decision",
    detail: "Exact-scope request request-1 is pending.",
    continuation: "No live campaign may start before approval.",
    record_type: "approval",
    record_id: "request-1",
    route: "/approvals/request-1",
    created_at: at,
  }],
  timeline: [{
    cursor: 9,
    event_type: "campaign.started",
    actor: "operator-1",
    summary: "campaign · started",
    aggregate_type: "campaign",
    aggregate_id: "run-live-001",
    created_at: at,
  }],
  cursor: 9,
  as_of: at,
};

describe("Birdseye", () => {
  it("renders server-owned instrumentation and supports node inspection and attention routing", () => {
    const openAttention = vi.fn();
    render(
      <Birdseye
        snapshot={snapshot}
        stream={{ state: "ready", data: [], cursor: 9 }}
        onOpenAttention={openAttention}
      />,
    );

    expect(screen.getByText("$1.25 / $5.00")).toBeTruthy();
    expect(screen.getByText("Cursor 9")).toBeTruthy();
    expect(screen.getByText("CampaignDirective")).toBeTruthy();
    expect(screen.getByText("2/3")).toBeTruthy();
    expect(screen.getAllByText("Prompt Injection")).toHaveLength(2);
    expect(screen.getByRole("heading", { name: "Observed agent sequence" })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /Campaign runner/ }));
    expect(screen.getByText("18.0 ms / 40.0 ms")).toBeTruthy();
    expect(screen.getByText("policy-gated")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", {
      name: /Campaign authorization requires a decision/,
    }));
    expect(openAttention).toHaveBeenCalledWith(snapshot.attention[0]);
  });
});
