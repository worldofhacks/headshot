import {
  cleanup,
  render,
  screen,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import { RESOURCE_PATHS } from "../src/api/paths";
import { shortId } from "../src/components/Analytics";
import {
  orderTracesForOperators,
  summarizeCampaignCosts,
  TracesScreen,
} from "../src/screens/ObservabilityScreens";
import type {
  CostReadModel,
  TraceReadModel,
} from "../src/types";

afterEach(cleanup);

const failedCampaignId = "50da0000-0000-0000-0000-000000000001";
const at = "2026-07-26T12:00:00Z";

const costRecord = (
  overrides: Partial<CostReadModel> & Pick<CostReadModel, "accounting_id" | "record_kind">,
): CostReadModel => ({
  accounting_id: overrides.accounting_id,
  campaign_id: failedCampaignId,
  provider: "openrouter",
  agent_role: overrides.record_kind === "campaign" ? null : "orchestrator",
  record_kind: overrides.record_kind,
  execution_mode: "hosted_advisory",
  measured_cost: 0,
  cost_measurement_state: "measured",
  accounting_status: "measured",
  provider_event_ids: [],
  currency: "USD",
  request_count: 0,
  execution_count: 0,
  attempt_count: 12,
  confirmed_finding_count: 0,
  average_cost_per_request: null,
  input_tokens: null,
  output_tokens: null,
  reasoning_tokens: null,
  token_observation_count: 0,
  physical_call_count: 0,
  physical_call_count_state: overrides.record_kind === "campaign"
    ? "not_applicable"
    : "exact",
  provider_budget: null,
  p50_duration_ms: null,
  p95_duration_ms: null,
  budget_usd: 5,
  budget_utilization: null,
  duration_ms: 865_000,
  execution_profile: "live",
  started_at: at,
  ended_at: at,
  recorded_at: at,
  ...overrides,
});

const failedCampaignCosts: CostReadModel[] = [
  costRecord({
    accounting_id: "campaign-target-spend",
    record_kind: "campaign",
    provider: "target-dispatch",
    measured_cost: 0.16,
    request_count: 16,
  }),
  costRecord({
    accounting_id: "agent-orchestrator-spend",
    record_kind: "agent",
    agent_role: "orchestrator",
    measured_cost: 0.2429,
    physical_call_count: 12,
  }),
  costRecord({
    accounting_id: "agent-judge-spend",
    record_kind: "agent",
    agent_role: "judge",
    measured_cost: 0.2217,
    physical_call_count: 12,
  }),
  costRecord({
    accounting_id: "agent-red-team-spend",
    record_kind: "agent",
    agent_role: "red_team",
    measured_cost: 0.14271395,
    physical_call_count: 12,
  }),
];

const traceRecord = (
  overrides: Partial<TraceReadModel> & Pick<TraceReadModel, "trace_id" | "execution_id">,
): TraceReadModel => ({
  request_id: null,
  execution_id: overrides.execution_id,
  parent_execution_id: null,
  trace_id: overrides.trace_id,
  campaign_id: failedCampaignId,
  attempt_id: "attempt-11",
  operation: "agent.judge",
  provider: "openrouter",
  model: "google/gemini-2.5-pro",
  agent_role: "judge",
  execution_mode: "hosted_advisory",
  requested_model: "google/gemini-2.5-pro",
  returned_model: "google/gemini-2.5-pro",
  model_substituted: false,
  upstream_provider: "Google",
  provider_request_id: "provider-request",
  configuration_set_sha256: null,
  role_configuration_sha256: null,
  generation_policy_sha256: null,
  physical_attempts: 1,
  method: null,
  destination_host: null,
  relative_path: null,
  status: "succeeded",
  status_code: null,
  error_code: null,
  started_at: at,
  finished_at: at,
  duration_ms: 1_000,
  request_bytes: 0,
  response_bytes: null,
  measured_cost: 0.02,
  cost_measurement_state: "measured",
  accounting_status: "measured",
  provider_event_ids: ["f".repeat(64)],
  provider_event_status: "succeeded",
  provider_lineage_state: "canonical_physical",
  currency: "USD",
  input_tokens: 1_000,
  output_tokens: 100,
  reasoning_tokens: 200,
  judge_calibration_id: null,
  judge_calibration_state: null,
  oracle_agreement: null,
  decision_authority: null,
  p50_duration_ms: 1_000,
  p95_duration_ms: 1_000,
  langfuse_status: "queued",
  langfuse_verified_at: null,
  request_preview: null,
  response_preview: null,
  request_sha256: null,
  response_sha256: null,
  inspection_flags: [],
  inspection_owasp_mappings: [],
  ...overrides,
});

describe("operator-first observability", () => {
  it("reconciles the known failed campaign without mixing global spend", () => {
    const summary = summarizeCampaignCosts(failedCampaignCosts, failedCampaignId);
    expect(summary.providerSpend.known).toBeCloseTo(0.60731395);
    expect(summary.targetSpend.known).toBeCloseTo(0.16);
    expect(summary.totalSpend.known).toBeCloseTo(0.76731395);
    expect(summary.providerCalls).toBe(36);
    expect(summary.targetRequests).toBe(16);
    expect(summary.attempts).toBe(12);
  });

  it("orders typed failures first and exposes their provider, model, and attempt", async () => {
    const newerSuccess = traceRecord({
      trace_id: "trace-success",
      execution_id: "execution-success",
      started_at: "2026-07-26T12:01:00Z",
    });
    const invalidJudgeOutput = traceRecord({
      trace_id: "trace-invalid-output",
      execution_id: "execution-invalid-output",
      attempt_id: "attempt-12",
      status: "failed",
      error_code: "invalid_structured_output",
      provider_event_status: "invalid_output",
      started_at: "2026-07-26T12:00:00Z",
    });

    expect(orderTracesForOperators([newerSuccess, invalidJudgeOutput])[0])
      .toBe(invalidJudgeOutput);

    const client = {
      read: vi.fn(async () => ({
        state: "ready" as const,
        data: [newerSuccess, invalidJudgeOutput],
      })),
      command: vi.fn(),
    } as unknown as ApiClient;

    render(<TracesScreen client={client} campaignId={failedCampaignId} />);

    expect(client.read).toHaveBeenCalledWith(
      RESOURCE_PATHS.campaignTraces(failedCampaignId),
      expect.any(AbortSignal),
    );
    const failure = (await screen.findByRole("heading", {
      name: "Execution failure",
    })).closest("section");
    expect(failure).not.toBeNull();
    expect(within(failure!).getByText("invalid_structured_output")).toBeTruthy();
    expect(within(failure!).getByText("openrouter")).toBeTruthy();
    expect(within(failure!).getByText("google/gemini-2.5-pro")).toBeTruthy();
    expect(within(failure!).getByText(shortId("attempt-12"))).toBeTruthy();

    const ledger = screen.getByRole("list", {
      name: "Campaign-correlated target requests and agent executions",
    });
    expect(within(ledger).getAllByRole("listitem")[0]?.textContent)
      .toContain("invalid_structured_output");
  });

  it("labels partial trace cost as known rather than complete", async () => {
    const partialTrace = traceRecord({
      trace_id: "trace-partial-cost",
      execution_id: "execution-partial-cost",
      cost_measurement_state: "partial",
      accounting_status: "partial",
      measured_cost: 0.02,
    });
    const client = {
      read: vi.fn(async () => ({
        state: "ready" as const,
        data: [partialTrace],
      })),
      command: vi.fn(),
    } as unknown as ApiClient;

    render(<TracesScreen client={client} campaignId={failedCampaignId} />);

    const metric = (await screen.findByText("Known trace cost")).parentElement;
    expect(metric).not.toBeNull();
    expect(metric?.textContent).toContain("$0.0200 known");
    expect(metric?.textContent).toContain(
      "1 observation(s) have partial or unavailable provider accounting",
    );
  });
});
