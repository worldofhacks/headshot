import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import type { Principal } from "../src/api/contracts";
import { decodeCampaignOperations } from "../src/api/read-models";
import { RESOURCE_PATHS } from "../src/api/paths";
import {
  RunOperationsScreen,
  RunOperationsView,
  runNextAction,
  selectOperationsCampaign,
} from "../src/screens/RunOperationsScreen";
import type {
  CampaignOperationsReadModel,
  CampaignReadModel,
} from "../src/types";

const at = "2026-07-26T22:00:00Z";

const operations: CampaignOperationsReadModel = {
  campaign_id: "campaign-failed",
  state: "failed",
  created_at: "2026-07-26T21:45:00Z",
  progress: {
    planned: 34,
    started: 12,
    running: 0,
    completed: 11,
    failed: 1,
    skipped: 0,
    remaining: 22,
  },
  executions: {
    logical_attempts: 12,
    physical_target_requests: 16,
    provider_calls: 36,
  },
  current_work: null,
  costs: {
    provider_measured_usd: 0.60731395,
    target_measured_usd: 0.16,
    total_measured_usd: 0.76731395,
    provider_measurement_state: "measured",
    target_measurement_state: "measured",
    measurement_state: "measured",
    currency: "USD",
  },
  limits: {
    target_budget_usd: 5,
    target_budget_remaining_usd: 4.84,
    provider_budget_usd: 3,
    provider_budget_remaining_usd: 2.39268605,
    logical_case_limit: 34,
    physical_request_limit: 121,
    physical_requests_remaining: 105,
    provider_call_limit: 136,
    provider_calls_remaining: 100,
    target_requests_per_second: 1,
    run_timeout_seconds: 180,
    max_attempts_per_run: 34,
    target_retries_per_turn: 0,
    provider_max_retries: 1,
    provider_max_concurrency: 1,
    provider_timeout_seconds: 120,
  },
  verdict_distribution: {
    INDETERMINATE: 11,
  },
  queue: {
    queued_jobs: 0,
    leased_jobs: 0,
    dead_lettered_jobs: 1,
    rate_limit_active: false,
  },
  terminal_failure: {
    stage: "judge",
    error_code: "invalid_structured_output",
    attempt_id: "attempt-12",
    execution_id: "execution-judge-12",
    agent_role: "judge",
    provider: "google",
    model: "gemini-2.5-pro",
    retryable: true,
    retries_remaining: 1,
    occurred_at: at,
    operator_summary: "Judge returned schema-invalid structured output.",
  },
  as_of: at,
  cursor: 88,
};

const unknownOperations: CampaignOperationsReadModel = {
  ...operations,
  campaign_id: "campaign-unknown-plan",
  state: "aborted",
  progress: {
    planned: null,
    started: 2,
    running: 0,
    completed: 1,
    failed: 1,
    skipped: null,
    remaining: null,
  },
  costs: {
    provider_measured_usd: null,
    target_measured_usd: null,
    total_measured_usd: null,
    provider_measurement_state: "unavailable",
    target_measurement_state: "unavailable",
    measurement_state: "unavailable",
    currency: "USD",
  },
  limits: {
    target_budget_usd: null,
    target_budget_remaining_usd: null,
    provider_budget_usd: null,
    provider_budget_remaining_usd: null,
    logical_case_limit: null,
    physical_request_limit: null,
    physical_requests_remaining: null,
    provider_call_limit: null,
    provider_calls_remaining: null,
    target_requests_per_second: null,
    run_timeout_seconds: null,
    max_attempts_per_run: null,
    target_retries_per_turn: null,
    provider_max_retries: null,
    provider_max_concurrency: null,
    provider_timeout_seconds: null,
  },
  queue: {
    ...operations.queue,
    rate_limit_active: null,
  },
  terminal_failure: null,
};

const campaign = (
  runId: string,
  state: CampaignReadModel["state"],
  createdAt: string,
): CampaignReadModel => ({
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
  relative_path: "/api",
  endpoint: "https://target.invalid/api",
  corpus_id: "corpus-1",
  corpus_hash: "hash-1",
  caps: {
    budget_usd: 1,
    max_attempts_per_run: 34,
    target_requests_per_second: 1,
    run_timeout_seconds: 180,
    logical_case_limit: 34,
    physical_request_limit: 121,
    target_retries_per_turn: 0,
  },
  run_nonce: "nonce-1",
  execution_profile: "live",
  hosted_run: null,
  run_id: runId,
  authorization_request_id: "request-1",
  scope_hash: "scope-1",
  launcher_user_id: "user-1",
  state,
  attempt_count: 12,
  created_at: createdAt,
});

const freshness = {
  state: "snapshot" as const,
  refreshing: false,
  stale: false,
  lastUpdatedAt: at,
  lastEventAt: null,
};

describe("campaign operations read model", () => {
  it("strictly decodes the latest failed campaign projection", () => {
    expect(decodeCampaignOperations(structuredClone(operations))).toEqual(operations);
    expect(() => decodeCampaignOperations({
      ...structuredClone(operations),
      unsupported_retry_command: "/retry",
    })).toThrow("Invalid campaign operations read model");
  });

  it("preserves authoritative nullable values instead of coercing them to zero", () => {
    expect(decodeCampaignOperations(structuredClone(unknownOperations)))
      .toEqual(unknownOperations);
    expect(decodeCampaignOperations({
      ...structuredClone(operations),
      state: "running",
      costs: {
        provider_measured_usd: 0.60731395,
        target_measured_usd: null,
        total_measured_usd: 0.60731395,
        provider_measurement_state: "measured",
        target_measurement_state: "unavailable",
        measurement_state: "partial",
        currency: "USD",
      },
      current_work: {
        stage: "target_dispatch",
        agent_role: null,
        execution_id: null,
        attempt_id: "attempt-12",
        started_at: at,
      },
      terminal_failure: null,
    }).current_work).toEqual(expect.objectContaining({
      agent_role: null,
      execution_id: null,
    }));
  });

  it("rejects internally inconsistent progress, spend, and failure state", () => {
    expect(() => decodeCampaignOperations({
      ...structuredClone(operations),
      progress: { ...operations.progress, remaining: 23 },
    })).toThrow();
    expect(() => decodeCampaignOperations({
      ...structuredClone(operations),
      costs: { ...operations.costs, total_measured_usd: 0.5 },
    })).toThrow();
    expect(() => decodeCampaignOperations({
      ...structuredClone(operations),
      terminal_failure: null,
    })).toThrow();
  });

  it("encodes the campaign operations resource path", () => {
    expect(RESOURCE_PATHS.campaignOperations("campaign/with spaces"))
      .toBe("campaigns/campaign%2Fwith%20spaces/operations");
  });
});

describe("run operations selection and presentation", () => {
  it("selects the requested campaign, otherwise the latest active or latest terminal run", () => {
    const olderRunning = campaign("running-old", "running", "2026-07-26T20:00:00Z");
    const latestFailed = campaign("failed-latest", "failed", "2026-07-26T22:00:00Z");
    const queued = campaign("queued-new", "queued", "2026-07-26T21:00:00Z");

    expect(selectOperationsCampaign(
      [olderRunning, latestFailed, queued],
      "failed-latest",
    )?.run_id).toBe("failed-latest");
    expect(selectOperationsCampaign(
      [olderRunning, latestFailed, queued],
      "outside-bounded-list",
    )).toBeNull();
    expect(selectOperationsCampaign(
      [olderRunning, latestFailed, queued],
      null,
    )?.run_id).toBe("queued-new");
    expect(selectOperationsCampaign(
      [campaign("complete-old", "complete", "2026-07-26T20:00:00Z"), latestFailed],
      null,
    )?.run_id).toBe("failed-latest");
  });

  it("loads an explicit campaign scope even when the bounded campaign resource is empty", async () => {
    const explicitCampaignId = "campaign-outside-bounded-list";
    const client = {
      read: vi.fn(async () => ({ state: "empty" as const, data: null })),
      command: vi.fn(),
    } as unknown as ApiClient;
    const principal: Principal = {
      user_id: "user-1",
      organization_id: "org-1",
      organization_role: "org:operator",
      organization_permissions: ["org:console:read"],
    };

    render(
      <RunOperationsScreen
        client={client}
        principal={principal}
        campaignId={explicitCampaignId}
      />,
    );

    await waitFor(() => expect(client.read).toHaveBeenCalledWith(
      RESOURCE_PATHS.campaignOperations(explicitCampaignId),
      expect.any(AbortSignal),
    ));
    expect((screen.getByLabelText("Campaign scope") as HTMLSelectElement).value)
      .toBe(explicitCampaignId);
    expect(screen.getByText(
      "Selected campaign metadata is unavailable in the bounded campaign list. Loading the exact campaign-scoped operations projection.",
    )).not.toBeNull();
  });

  it("leads with exact failed progress, execution units, cost, and typed cause", () => {
    render(<RunOperationsView operations={operations} freshness={freshness} />);

    expect(screen.getAllByText("FAILED")).toHaveLength(2);
    expect(screen.getByText("11/34 completed")).not.toBeNull();
    expect(screen.getByText("Judge returned schema-invalid structured output.")).not.toBeNull();
    expect(screen.getByText("invalid_structured_output")).not.toBeNull();
    expect(screen.getByText("36")).not.toBeNull();
    expect(screen.getAllByText("$0.7673")).toHaveLength(2);
    expect(screen.getByText(/submit a new campaign authorization request/)).not.toBeNull();
  });

  it("renders unknown plan, cost, limits, and rate state as unavailable", () => {
    render(<RunOperationsView operations={unknownOperations} freshness={freshness} />);

    expect(screen.getByText("1 completed")).not.toBeNull();
    expect(screen.getAllByText("Unavailable").length).toBeGreaterThan(5);
    expect(screen.queryByText("1/0 completed")).toBeNull();
    expect(runNextAction(unknownOperations)).not.toContain("retry");
  });
});
