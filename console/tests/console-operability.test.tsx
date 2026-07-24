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
      read: vi.fn(async (path: string) => path === "target-catalog"
        ? {
            state: "ready" as const,
            data: [{
              target_id: "target-1",
              version: "1.0.0",
              name: "Registered target",
              environment: "staging",
              synthetic_data_only: true,
              surface_count: 1,
              registration_state: "registered",
            }],
          }
        : {
            state: "ready" as const,
            data: [target(enabled)],
          }),
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
      name: "Register exact catalog target",
    }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/browser submits only the selected target ID and version/i)).toBeTruthy();
  });

  it("registers only the exact selected server-owned catalog identity", async () => {
    let registrationState: "available" | "registered" = "available";
    const command = vi.fn(async (path: string, payload: object) => {
      expect(path).toBe("targets");
      expect(payload).toEqual({ target_id: "target-2", version: "2.0.0" });
      registrationState = "registered";
      return {
        status: "completed" as const,
        acknowledgement_id: "2.0.0",
        resource_id: "target-2",
      };
    });
    const read = vi.fn(async (path: string) => path === "target-catalog"
      ? {
          state: "ready" as const,
          data: [{
            target_id: "target-2",
            version: "2.0.0",
            name: "Reviewed target",
            environment: "staging",
            synthetic_data_only: true,
            surface_count: 2,
            registration_state: registrationState,
          }],
        }
      : { state: "empty" as const, data: [] });
    const client = { read, command } as unknown as ApiClient;

    render(
      <TargetsScreen
        client={client}
        principal={principal}
        entityId={null}
        getToken={async () => "session"}
      />,
    );

    fireEvent.change(await screen.findByLabelText("Reviewed target version"), {
      target: { value: "target-2\n2.0.0" },
    });
    const register = screen.getByRole("button", { name: "Register exact catalog target" });
    expect((register as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(register);

    await waitFor(() => expect(command).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(read.mock.calls.filter(([path]) => path === "target-catalog"))
      .toHaveLength(2));
    expect(screen.queryByText("https://")).toBeNull();
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
