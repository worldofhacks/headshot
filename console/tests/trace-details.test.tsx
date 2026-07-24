import {
  cleanup,
  render,
  screen,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import { TracesScreen } from "../src/screens/ObservabilityScreens";
import type { TraceReadModel } from "../src/types";

afterEach(cleanup);

const agentTrace: TraceReadModel = {
  request_id: null,
  execution_id: "execution-1",
  parent_execution_id: null,
  trace_id: "trace-1",
  campaign_id: "campaign-1",
  attempt_id: "attempt-1",
  operation: "agent.orchestrator",
  provider: "openrouter",
  model: "anthropic/claude-opus-4.8",
  agent_role: "orchestrator",
  execution_mode: "hosted_advisory",
  returned_model: "anthropic/claude-opus-4.8-20260724",
  upstream_provider: "Anthropic",
  provider_request_id: "openrouter-request-1",
  configuration_set_sha256: "a".repeat(64),
  role_configuration_sha256: "b".repeat(64),
  generation_policy_sha256: "c".repeat(64),
  physical_attempts: 1,
  method: null,
  destination_host: null,
  relative_path: null,
  status: "succeeded",
  status_code: null,
  error_code: null,
  started_at: "2026-07-24T12:00:00Z",
  finished_at: "2026-07-24T12:00:01Z",
  duration_ms: 1_000,
  request_bytes: 0,
  response_bytes: null,
  measured_cost: 0.03,
  cost_measurement_state: "measured",
  accounting_status: "measured",
  provider_event_ids: ["f".repeat(64)],
  currency: "USD",
  input_tokens: 100,
  output_tokens: 20,
  reasoning_tokens: 10,
  judge_calibration_id: null,
  judge_calibration_state: null,
  oracle_agreement: null,
  decision_authority: null,
  p50_duration_ms: 1_000,
  p95_duration_ms: 1_000,
  langfuse_status: "exported",
  langfuse_verified_at: "2026-07-24T12:00:02Z",
  request_preview: null,
  response_preview: null,
  request_sha256: "d".repeat(64),
  response_sha256: "e".repeat(64),
  inspection_flags: [],
  inspection_owasp_mappings: [],
};

describe("agent trace identity", () => {
  it("renders provider, requested model, and provider-served model as distinct facts", async () => {
    const client = {
      read: vi.fn(async () => ({
        state: "ready" as const,
        data: [agentTrace],
      })),
      command: vi.fn(),
    } as unknown as ApiClient;

    render(<TracesScreen client={client} />);

    const provider = (await screen.findByText("Provider")).parentElement;
    const requestedModel = screen.getByText("Requested model").parentElement;
    const servedModel = screen.getByText("Provider-served model").parentElement;

    expect(provider).not.toBeNull();
    expect(requestedModel).not.toBeNull();
    expect(servedModel).not.toBeNull();
    expect(within(provider!).getByText("openrouter")).toBeTruthy();
    expect(within(requestedModel!).getByText("anthropic/claude-opus-4.8")).toBeTruthy();
    expect(
      within(servedModel!).getByText("anthropic/claude-opus-4.8-20260724"),
    ).toBeTruthy();
  });
});
