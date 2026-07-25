import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import type { Principal } from "../src/api/contracts";
import {
  ApprovalsScreen,
  TargetsScreen,
} from "../src/screens/ConsoleScreens";
import { AgentsScreen } from "../src/screens/AgentToolScreens";
import { CostsScreen } from "../src/screens/ObservabilityScreens";
import { PERMISSIONS } from "../src/types";

afterEach(cleanup);

const principal: Principal = {
  user_id: "operator-1",
  organization_id: "org-1",
  organization_role: "org:operator",
  organization_permissions: [PERMISSIONS.consoleRead, PERMISSIONS.targetsManage],
};

const target = (enabled: boolean) => ({
  target_id: "target-1",
  version: "1.0.0",
  content_hash: "target-content",
  name: "Registered target",
  adapter_kind: "openemr",
  environment: "staging",
  base_url: "https://target.invalid",
  auth_mode: "bearer",
  credential_configured: true,
  synthetic_data_only: true,
  safety_caps: {
    budget_usd: 1,
    max_attempts_per_run: 2,
    target_requests_per_second: 0.5,
    run_timeout_seconds: 60,
    logical_case_limit: null,
    physical_request_limit: null,
    target_retries_per_turn: null,
  },
  lifecycle: "ready",
  allowed_lifecycle_transitions: ["disabled"],
  surfaces: [{
    surface_id: "chat",
    version: "1.0.0",
    target_version: "1.0.0",
    content_hash: "surface-content",
    kind: "chat",
    protocol: "https",
    method: "POST",
    relative_path: "/chat",
    trust_boundary: "external-target",
    authentication_required: true,
    risk: "high",
    owasp_mappings: [],
    oracle_refs: [],
    enabled,
    created_at: "2026-07-24T00:00:00Z",
  }],
  campaign_template: null,
  created_at: "2026-07-24T00:00:00Z",
});

const configurationHash = "a".repeat(64);
const generationPolicyHash = "b".repeat(64);

const approval = {
  target_id: "target-1",
  target_version: "1.0.0",
  surface_id: "chat",
  surface_version: "1.0.0",
  adapter_kind: "openemr",
  environment: "staging",
  exact_host: "target.invalid",
  auth_mode: "bearer",
  explicit_no_auth: false,
  auth_posture: "sealed_secretref",
  protocol: "https",
  method: "POST",
  relative_path: "/chat",
  endpoint: "https://target.invalid/chat",
  corpus_id: "week-3",
  corpus_hash: "corpus-hash",
  caps: {
    budget_usd: 1,
    max_attempts_per_run: 2,
    target_requests_per_second: 0.5,
    run_timeout_seconds: 60,
    logical_case_limit: null,
    physical_request_limit: null,
    target_retries_per_turn: null,
  },
  run_nonce: "run-nonce",
  execution_profile: "live",
  hosted_run: {
    configuration_set_sha256: configurationHash,
    generation_policy_sha256: generationPolicyHash,
    session_generation: "week3-authorization",
    provider_model_call_limit: 8,
    provider_model_spend_limit_usd: "7.500000",
    provider_max_retries: 1,
    provider_max_concurrency: 1,
    provider_timeout_seconds: 45,
  },
  request_id: "approval-1",
  scope_hash: "scope-hash",
  launcher_user_id: "operator-1",
  expires_at: "2026-07-25T00:00:00Z",
  created_at: "2026-07-24T00:00:00Z",
  status: "approved",
  decision: "approved",
  approver_user_id: "approver-1",
  self_approval_override: false,
  decided_at: "2026-07-24T00:01:00Z",
  expired: false,
  consumed: true,
} as const;

const activity = (
  campaignRunId: string,
  executionId: string,
  returnedModel: string,
) => ({
  execution_id: executionId,
  campaign_run_id: campaignRunId,
  attempt_id: null,
  parent_execution_id: null,
  agent_role: "orchestrator",
  status: "succeeded",
  provider: "openrouter",
  model: "anthropic/claude-opus-4.8",
  returned_model: returnedModel,
  model_substituted: returnedModel !== null && returnedModel !== "anthropic/claude-opus-4.8",
  upstream_provider: "Anthropic",
  provider_request_id: `provider-${executionId}`,
  execution_mode: "hosted_advisory",
  configuration_version: 1,
  configuration_set_sha256: configurationHash,
  role_configuration_sha256: "c".repeat(64),
  generation_policy_sha256: generationPolicyHash,
  input_sha256: "d".repeat(64),
  output_sha256: "e".repeat(64),
  input_tokens: 100,
  output_tokens: 20,
  reasoning_tokens: 10,
  physical_attempts: 1,
  measured_cost: 0.03,
  accounting_status: "measured",
  currency: "USD",
  trace_id: `trace-${executionId}`,
  langfuse_status: "exported",
  langfuse_verified_at: "2026-07-24T00:02:01Z",
  detail: {},
  judge_calibration_id: null,
  judge_calibration_state: null,
  oracle_agreement: null,
  decision_authority: null,
  error_code: null,
  started_at: "2026-07-24T00:02:00Z",
  finished_at: "2026-07-24T00:02:01Z",
  duration_ms: 1_000,
});

const campaignCost = {
  accounting_id: "campaign-cost",
  campaign_id: "run-selected",
  provider: "target",
  agent_role: null,
  record_kind: "campaign",
  measured_cost: 0.2,
  accounting_status: "measured",
  currency: "USD",
  request_count: 4,
  execution_count: 0,
  attempt_count: 4,
  confirmed_finding_count: 1,
  average_cost_per_request: 0.05,
  input_tokens: null,
  output_tokens: null,
  reasoning_tokens: null,
  token_observation_count: 0,
  physical_call_count: 0,
  provider_budget: null,
  p50_duration_ms: null,
  p95_duration_ms: null,
  budget_usd: 1,
  budget_utilization: 0.2,
  duration_ms: 1_000,
  execution_profile: "live",
  started_at: "2026-07-24T00:00:00Z",
  ended_at: "2026-07-24T00:00:01Z",
  recorded_at: "2026-07-24T00:00:02Z",
} as const;

const agentCost = {
  accounting_id: "judge-cost",
  campaign_id: "run-selected",
  provider: "openrouter",
  agent_role: "judge",
  record_kind: "agent",
  measured_cost: 0.04,
  accounting_status: "measured",
  currency: "USD",
  request_count: 2,
  execution_count: 1,
  attempt_count: 1,
  confirmed_finding_count: 0,
  average_cost_per_request: 0.02,
  input_tokens: 100,
  output_tokens: 20,
  reasoning_tokens: 5,
  token_observation_count: 1,
  physical_call_count: 2,
  provider_budget: {
    status: "active",
    campaign_run_id: "run-selected",
    configuration_set_sha256: configurationHash,
    role_usd_cap: 4,
    role_usd_spent: 0.04,
    role_unresolved_usd_exposure: 0,
    role_usd_remaining: 3.96,
    role_usd_overrun: 0,
    role_call_cap: 10,
    role_physical_calls: 2,
    role_unresolved_physical_calls: 0,
    role_calls_remaining: 8,
    role_call_overrun: 0,
    global_usd_cap: 10,
    global_usd_spent: 0.04,
    global_unresolved_usd_exposure: 0,
    global_usd_remaining: 9.96,
    global_usd_overrun: 0,
    global_call_cap: 56,
    global_physical_calls: 2,
    global_unresolved_physical_calls: 0,
    global_calls_remaining: 54,
    global_call_overrun: 0,
  },
  p50_duration_ms: 5,
  p95_duration_ms: 7,
  budget_usd: null,
  budget_utilization: null,
  duration_ms: 5,
  execution_profile: "live",
  started_at: "2026-07-24T00:00:00Z",
  ended_at: "2026-07-24T00:00:00.005Z",
  recorded_at: "2026-07-24T00:00:02Z",
} as const;

const acceptanceAgent = {
  role: "orchestrator",
  display_name: "Planner",
  responsibility: "Prioritizes authorized synthetic evaluation work.",
  trust_level: "trusted governor",
  target_access: "none",
  input_contract: "Coverage snapshot",
  output_contract: "Workload plan",
  active_assignment: {
    role: "orchestrator",
    provider: "headshot",
    model: "coverage-governor-v1",
    resolved_model: null,
    upstream_provider: null,
    prompt_sha256: null,
    prompt_version: null,
    execution_mode: "deterministic",
    activation_state: "active",
    version: 1,
    configuration_sha256: "1".repeat(64),
    configured_at: null,
    configured_by: null,
  },
  staged_assignment: {
    role: "orchestrator",
    provider: "openrouter",
    model: "anthropic/claude-opus-4.8",
    resolved_model: null,
    upstream_provider: null,
    prompt_sha256: "2".repeat(64),
    prompt_version: "1",
    execution_mode: "hosted_advisory",
    activation_state: "staged_pending_authorization",
    version: 1,
    configuration_sha256: configurationHash,
    configured_at: "2026-07-24T00:00:00Z",
    configured_by: "system:agent-acceptance-cli",
  },
  latest_acceptance_execution: {
    scope: "agent_acceptance",
    agent_role: "orchestrator",
    acceptance_run_id: "AR-live-acceptance",
    acceptance_attempt_id: "5".repeat(64),
    execution_id: "acceptance-execution-planner",
    parent_execution_id: null,
    configuration_set_sha256: configurationHash,
    returned_model: "anthropic/claude-opus-4.8",
    upstream_provider: "Anthropic",
    trace_id: "3".repeat(32),
    measured_cost: 0.03,
    cost_measurement_state: "measured",
    provider_event_ids: ["4".repeat(32)],
    currency: "USD",
    input_tokens: 100,
    output_tokens: 20,
    reasoning_tokens: 10,
    langfuse_status: "exported",
    langfuse_verified_at: "2026-07-24T00:02:01Z",
    finished_at: "2026-07-24T00:02:00Z",
  },
  execution_count: 1,
  running_count: 0,
  succeeded_count: 1,
  failed_count: 0,
  skipped_count: 0,
  measured_cost: 0.03,
  accounting_status: "measured",
  currency: "USD",
  input_tokens: 100,
  output_tokens: 20,
  reasoning_tokens: 10,
  token_observation_count: 1,
  physical_call_count: 1,
  provider_budget: {
    status: "agent_acceptance",
    campaign_run_id: "AR-live-acceptance",
    configuration_set_sha256: configurationHash,
    role_usd_cap: 1.5,
    role_usd_spent: 0.03,
    role_unresolved_usd_exposure: 0,
    role_usd_remaining: 1.47,
    role_usd_overrun: 0,
    role_call_cap: 1,
    role_physical_calls: 1,
    role_unresolved_physical_calls: 0,
    role_calls_remaining: 0,
    role_call_overrun: 0,
    global_usd_cap: 10,
    global_usd_spent: 0.03,
    global_unresolved_usd_exposure: 0,
    global_usd_remaining: 9.97,
    global_usd_overrun: 0,
    global_call_cap: 3,
    global_physical_calls: 1,
    global_unresolved_physical_calls: 0,
    global_calls_remaining: 2,
    global_call_overrun: 0,
  },
  judge_calibration: null,
  average_duration_ms: 1_000,
  p50_duration_ms: 1_000,
  p95_duration_ms: 1_000,
  langfuse_not_attempted_count: 0,
  langfuse_disabled_count: 0,
  langfuse_queued_count: 0,
  langfuse_exported_count: 1,
  langfuse_error_count: 0,
  langfuse_verified_count: 1,
  last_langfuse_verified_at: "2026-07-24T00:02:01Z",
  last_activity_at: "2026-07-24T00:02:00Z",
  last_status: "succeeded",
  last_campaign_run_id: "AR-live-acceptance",
  last_attempt_id: "5".repeat(64),
} as const;

describe("target console operability", () => {
  it("keeps selection bound to refreshed records and exposes only safe surface transitions", async () => {
    let enabled = true;
    const command = vi.fn(async (_path: string, payload: object) => {
      expect(payload).toEqual({ version: "1.0.0", enabled: false });
      enabled = false;
      return {
        status: "completed" as const,
        acknowledgement_id: "surface-state-ack",
        resource_id: "chat",
      };
    });
    const client = {
      read: vi.fn(async () => ({
        state: "ready" as const,
        data: [target(enabled)],
      })),
      command,
    } as unknown as ApiClient;

    render(
      <TargetsScreen
        client={client}
        principal={principal}
        entityId={null}
        getToken={async () => "session"}
      />,
    );

    fireEvent.click(await screen.findByText("Registered target"));
    const disable = await screen.findByRole("button", { name: "Disable surface" });
    expect((disable as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(disable);

    await waitFor(() => expect(command).toHaveBeenCalledTimes(1));
    const enable = await screen.findByRole("button", { name: "Enable surface" });
    expect((enable as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", {
      name: "Create target from trusted catalog",
    }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/browser never supplies target URLs/i)).toBeTruthy();
  });
});

describe("agent-only acceptance identity", () => {
  it("renders canonical served identity as acceptance evidence, not campaign activation", async () => {
    const client = {
      read: vi.fn(async (path: string) => {
        if (path === "agents") {
          return { state: "ready" as const, data: [acceptanceAgent] };
        }
        if (path === "agent-activity") {
          return { state: "ready" as const, data: [] };
        }
        throw new Error(`Unexpected read: ${path}`);
      }),
      command: vi.fn(),
    } as unknown as ApiClient;

    render(<AgentsScreen client={client} principal={principal} />);

    expect(await screen.findByText("Latest target-free agent acceptance")).toBeTruthy();
    expect(screen.getByText(/does not activate this assignment for campaign execution/i))
      .toBeTruthy();
    expect(screen.getAllByText("anthropic/claude-opus-4.8").length).toBeGreaterThan(0);
    expect(screen.getByText("Anthropic")).toBeTruthy();
    expect(screen.getByText("AR-live-acceptance")).toBeTruthy();
    expect(screen.getByText("5".repeat(64))).toBeTruthy();
    expect(screen.getByText("3".repeat(32))).toBeTruthy();
    expect(screen.getAllByText("$0.0300").length).toBeGreaterThan(0);
    expect(
      screen.getAllByText("unavailable — no campaign execution recorded").length,
    ).toBe(2);
  });
});

describe("approval execution visibility", () => {
  it("renders the exact hosted binding and scopes activity to the consumed campaign", async () => {
    const selectedModel = "anthropic/claude-opus-4.8-served";
    const unrelatedModel = "unrelated-served-model";
    const client = {
      read: vi.fn(async (path: string) => {
        if (path === "approvals") {
          return { state: "ready" as const, data: [approval] };
        }
        if (path === "approvals/approval-1") {
          return {
            state: "ready" as const,
            data: {
              ...approval,
              campaign_run_id: "run-selected",
              verification_chain: [],
            },
          };
        }
        if (path === "agent-activity") {
          return {
            state: "ready" as const,
            data: [
              activity("run-selected", "execution-selected", selectedModel),
              activity("run-other", "execution-other", unrelatedModel),
            ],
          };
        }
        throw new Error(`Unexpected read: ${path}`);
      }),
      command: vi.fn(),
    } as unknown as ApiClient;

    render(
      <ApprovalsScreen
        client={client}
        principal={principal}
        entityId="approval-1"
        getToken={async () => "session"}
      />,
    );

    expect(await screen.findByText("Exact hosted four-role binding")).toBeTruthy();
    expect(screen.getByText(configurationHash)).toBeTruthy();
    expect(screen.getByText(generationPolicyHash)).toBeTruthy();
    expect(screen.getByText("$7.500000")).toBeTruthy();
    expect(screen.queryByText("Approval rate")).toBeNull();

    const scopedPanel = await screen.findByRole("heading", {
      name: "Selected authorization agents",
    });
    const panel = scopedPanel.closest("section");
    expect(panel).not.toBeNull();
    expect(within(panel as HTMLElement).getByText(new RegExp(selectedModel))).toBeTruthy();
    expect(within(panel as HTMLElement).queryByText(new RegExp(unrelatedModel))).toBeNull();
  });
});

describe("cost accounting labels", () => {
  it("does not present target requests or campaign findings as agent metrics", async () => {
    const client = {
      read: vi.fn(async (path: string) => {
        if (path === "costs") {
          return {
            state: "ready" as const,
            data: [campaignCost, agentCost],
          };
        }
        if (path === "traces") {
          return { state: "ready" as const, data: [] };
        }
        throw new Error(`Unexpected read: ${path}`);
      }),
      command: vi.fn(),
    } as unknown as ApiClient;

    render(<CostsScreen client={client} />);

    const table = await screen.findByRole("table", {
      name: "Campaign and agent accounting records",
    });
    expect(within(table).getByRole("columnheader", {
      name: "Target requests",
    })).toBeTruthy();
    expect(within(table).getByRole("columnheader", {
      name: "Campaign findings",
    })).toBeTruthy();
    expect(within(table).getByRole("columnheader", {
      name: "Cost / provider call",
    })).toBeTruthy();

    const judgeRow = within(table).getByRole("row", { name: /judge/ });
    const judgeCells = within(judgeRow).getAllByRole("cell");
    expect(judgeCells[3]?.textContent).toBe("Not applicable");
    expect(judgeCells[4]?.textContent).toBe("2");
    expect(judgeCells[7]?.textContent).toBe("Not applicable");
    expect(judgeCells[13]?.textContent).toBe("Not applicable");
    expect(judgeCells[14]?.textContent).toBe("$0.0200");
  });
});
