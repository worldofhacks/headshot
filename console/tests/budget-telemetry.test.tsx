import {
  cleanup,
  render,
  screen,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import { AgentBudgetSummary } from "../src/components/AgentBudgetSummary";
import { CostsScreen } from "../src/screens/ObservabilityScreens";
import type {
  AgentBudgetReadModel,
  CostReadModel,
} from "../src/types";

afterEach(cleanup);

const at = "2026-07-24T12:00:00Z";

const activeBudget: AgentBudgetReadModel = {
  status: "active",
  campaign_run_id: "run-active",
  configuration_set_sha256: "a".repeat(64),
  role_usd_cap: 4,
  role_usd_spent: 1,
  role_unresolved_usd_exposure: 0.5,
  role_usd_remaining: 2.5,
  role_usd_overrun: 0,
  role_call_cap: 10,
  role_physical_calls: 2,
  role_unresolved_physical_calls: 1,
  role_calls_remaining: 7,
  role_call_overrun: 0,
  global_usd_cap: 10,
  global_usd_spent: 2,
  global_unresolved_usd_exposure: 1,
  global_usd_remaining: 7,
  global_usd_overrun: 0,
  global_call_cap: 20,
  global_physical_calls: 4,
  global_unresolved_physical_calls: 2,
  global_calls_remaining: 14,
  global_call_overrun: 0,
};

const historicalBudget: AgentBudgetReadModel = {
  ...activeBudget,
  status: "historical",
  campaign_run_id: "run-historical",
};

const historicalCost: CostReadModel = {
  accounting_id: "agent-cost-historical",
  campaign_id: "run-historical",
  provider: "openrouter",
  agent_role: "orchestrator",
  record_kind: "agent",
  measured_cost: 1,
  accounting_status: "partial",
  currency: "USD",
  request_count: 0,
  execution_count: 1,
  attempt_count: 0,
  confirmed_finding_count: 0,
  average_cost_per_request: 0.5,
  input_tokens: 100,
  output_tokens: 20,
  reasoning_tokens: 10,
  token_observation_count: 1,
  physical_call_count: 2,
  provider_budget: historicalBudget,
  p50_duration_ms: 50,
  p95_duration_ms: 75,
  budget_usd: null,
  budget_utilization: null,
  duration_ms: 75,
  execution_profile: "live",
  started_at: at,
  ended_at: at,
  recorded_at: at,
};

describe("conservative provider budget telemetry", () => {
  it("renders known spend, unresolved exposure, and remaining active headroom", () => {
    render(<AgentBudgetSummary budget={activeBudget} />);

    const unresolved = screen.getByText("Role unresolved USD exposure").parentElement;
    const remaining = screen.getByText("Role USD remaining").parentElement;
    const unresolvedCalls = screen.getByText("Role unresolved provider calls").parentElement;
    expect(unresolved).not.toBeNull();
    expect(remaining).not.toBeNull();
    expect(unresolvedCalls).not.toBeNull();
    expect(within(unresolved!).getByText("$0.5000")).toBeTruthy();
    expect(within(remaining!).getByText("$2.50 / $4.00")).toBeTruthy();
    expect(within(unresolvedCalls!).getByText("1")).toBeTruthy();
    expect(screen.getByText(/Remaining headroom already subtracts/)).toBeTruthy();
  });

  it("labels historical headroom as closed on Agents and Costs", async () => {
    const read = vi.fn(async (path: string) => {
      if (path === "costs") {
        return { state: "ready" as const, data: [historicalCost] };
      }
      if (path === "traces") {
        return { state: "empty" as const, data: null };
      }
      throw new Error(`Unexpected read path: ${path}`);
    });
    const client = {
      read,
      command: vi.fn(),
    } as unknown as ApiClient;

    const agent = render(<AgentBudgetSummary budget={historicalBudget} />);
    expect(screen.getByText("historical · closed")).toBeTruthy();
    expect(screen.getByText("Role USD unused at close")).toBeTruthy();
    expect(screen.getByText(/cannot authorize new provider calls/)).toBeTruthy();
    agent.unmount();

    const costs = render(<CostsScreen client={client} />);
    expect(await screen.findByRole("heading", { name: "Costs", level: 1 })).toBeTruthy();
    expect(await screen.findByText("No active hosted budget")).toBeTruthy();
    expect(screen.getAllByText("historical · closed")).toHaveLength(1);
    expect(screen.getByText("$2.50 unused at close")).toBeTruthy();
    expect(screen.getByText("7 unused at close")).toBeTruthy();
    expect(screen.getAllByText("$0.5000")).not.toHaveLength(0);
    expect(costs.container.querySelector(".cost-unresolved")).not.toBeNull();
  });
});
