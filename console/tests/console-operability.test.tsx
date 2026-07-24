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
import {
  CostsScreen,
  TracesScreen,
} from "../src/screens/ObservabilityScreens";
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
const hostedRun = {
  configuration_set_sha256: configurationHash,
  generation_policy_sha256: generationPolicyHash,
  session_generation: "week3-authorization",
  provider_model_call_limit: 56,
  provider_model_spend_limit_usd: "5",
  provider_max_retries: 1,
  provider_max_concurrency: 1,
  provider_timeout_seconds: 180,
} as const;

const approval = {
  target_id: "target-1",
  target_version: "1.0.0",
  surface_id: "chat",
  surface_version: "1.0.0",
  adapter_kind: "openemr",
  environment: "staging",
  exact_host: "target.invalid",
  allowlisted_hosts: ["target.invalid"],
  synthetic_data_only: true,
  synthetic_data_attestation_ref: "attestation://fixtures/target-v1",
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
  hosted_run: hostedRun,
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
  cost_measurement_state: "measured",
  accounting_status: "measured",
  provider_event_ids: ["f".repeat(64)],
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
  cost_measurement_state: "measured",
  accounting_status: "measured",
  provider_event_ids: [],
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
  cost_measurement_state: "measured",
  accounting_status: "measured",
  provider_event_ids: ["d".repeat(64), "e".repeat(64)],
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
    role_cost_measurement_state: "measured",
    role_usd_cap: 4,
    role_usd_spent: 0.04,
    role_unresolved_usd_exposure: 0,
    role_usd_remaining: 3.96,
    role_usd_remaining_upper_bound: 3.96,
    role_usd_overrun: 0,
    role_call_cap: 10,
    role_physical_calls: 2,
    role_unresolved_physical_calls: 0,
    role_calls_remaining: 8,
    role_call_overrun: 0,
    global_cost_measurement_state: "measured",
    global_usd_cap: 10,
    global_usd_spent: 0.04,
    global_unresolved_usd_exposure: 0,
    global_usd_remaining: 9.96,
    global_usd_remaining_upper_bound: 9.96,
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

const partiallyAccountedAgent = {
  role: "orchestrator",
  display_name: "Orchestrator",
  responsibility: "Select authorized work.",
  trust_level: "trusted governor",
  target_access: "none",
  input_contract: "Snapshot",
  output_contract: "Directive",
  active_assignment: {
    role: "orchestrator",
    provider: "openrouter",
    model: "anthropic/claude-opus-4.8",
    resolved_model: "anthropic/claude-opus-4.8",
    upstream_provider: "Anthropic",
    prompt_sha256: "c".repeat(64),
    prompt_version: "v1",
    execution_mode: "hosted_advisory",
    activation_state: "active",
    version: 1,
    configuration_sha256: configurationHash,
    configured_at: "2026-07-24T00:00:00Z",
    configured_by: "operator-1",
  },
  staged_assignment: null,
  execution_count: 1,
  running_count: 0,
  succeeded_count: 1,
  failed_count: 0,
  skipped_count: 0,
  measured_cost: 0.03,
  cost_measurement_state: "partial",
  accounting_status: "partial",
  provider_event_ids: ["f".repeat(64), "9".repeat(64)],
  currency: "USD",
  input_tokens: 100,
  output_tokens: 20,
  reasoning_tokens: 10,
  token_observation_count: 1,
  physical_call_count: 2,
  provider_budget: {
    status: "active",
    campaign_run_id: "run-selected",
    configuration_set_sha256: configurationHash,
    role_cost_measurement_state: "partial",
    role_usd_cap: 4,
    role_usd_spent: 0.03,
    role_usd_remaining: null,
    role_usd_remaining_upper_bound: 3.97,
    role_usd_overrun: 0,
    role_call_cap: 10,
    role_physical_calls: 2,
    role_calls_remaining: 8,
    role_call_overrun: 0,
    global_cost_measurement_state: "partial",
    global_usd_cap: 10,
    global_usd_spent: 0.03,
    global_usd_remaining: null,
    global_usd_remaining_upper_bound: 9.97,
    global_usd_overrun: 0,
    global_call_cap: 56,
    global_physical_calls: 2,
    global_calls_remaining: 54,
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
  last_campaign_run_id: "run-selected",
  last_attempt_id: null,
} as const;

const partiallyAccountedActivity = {
  ...activity(
    "run-selected",
    "execution-partial",
    "anthropic/claude-opus-4.8",
  ),
  physical_attempts: 2,
  measured_cost: 0.03,
  cost_measurement_state: "partial",
  accounting_status: "partial",
  provider_event_ids: ["f".repeat(64), "9".repeat(64)],
} as const;

const partiallyAccountedTrace = {
  request_id: null,
  execution_id: "execution-partial",
  parent_execution_id: null,
  trace_id: "trace-execution-partial",
  campaign_id: "run-selected",
  attempt_id: null,
  operation: "agent.execute",
  provider: "openrouter",
  agent_role: "orchestrator",
  execution_mode: "hosted_advisory",
  returned_model: "anthropic/claude-opus-4.8",
  upstream_provider: "Anthropic",
  provider_request_id: "provider-execution-partial",
  configuration_set_sha256: configurationHash,
  role_configuration_sha256: "c".repeat(64),
  generation_policy_sha256: generationPolicyHash,
  physical_attempts: 2,
  method: null,
  destination_host: null,
  relative_path: null,
  status: "succeeded",
  status_code: null,
  error_code: null,
  started_at: "2026-07-24T00:02:00Z",
  finished_at: "2026-07-24T00:02:01Z",
  duration_ms: 1_000,
  request_bytes: 0,
  response_bytes: null,
  measured_cost: 0.03,
  cost_measurement_state: "partial",
  accounting_status: "partial",
  provider_event_ids: ["f".repeat(64), "9".repeat(64)],
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
  langfuse_verified_at: "2026-07-24T00:02:01Z",
  request_preview: null,
  response_preview: null,
  request_sha256: null,
  response_sha256: null,
  inspection_flags: [],
  inspection_owasp_mappings: [],
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

  it("binds the server-derived atomic hosted set without browser model or secret authority", async () => {
    const launchPrincipal: Principal = {
      ...principal,
      organization_permissions: [
        ...principal.organization_permissions,
        PERMISSIONS.campaignLaunch,
      ],
    };
    const campaignTarget = {
      ...target(true),
      campaign_template: {
        target_id: "target-1",
        target_version: "1.0.0",
        surface_id: "chat",
        surface_version: "1.0.0",
        corpus_id: "week-3",
        corpus_hash: "c".repeat(64),
        case_count: 2,
        tool_sources: [],
        execution_profile: "live" as const,
        maximum_caps: {
          ...target(true).safety_caps,
          logical_case_limit: 2,
          physical_request_limit: 6,
          target_retries_per_turn: 1,
        },
        hosted_run: hostedRun,
      },
    };
    const command = vi.fn(async () => ({
      status: "completed" as const,
      acknowledgement_id: "authorization-1",
      resource_id: "authorization-1",
    }));
    const client = {
      read: vi.fn(async (path: string) => path === "target-catalog"
        ? { state: "empty" as const, data: [] }
        : { state: "ready" as const, data: [campaignTarget] }),
      command,
    } as unknown as ApiClient;

    render(
      <TargetsScreen
        client={client}
        principal={launchPrincipal}
        entityId={null}
        getToken={async () => "session"}
      />,
    );

    fireEvent.click(await screen.findByText("Registered target"));
    expect(await screen.findByText(/activates the latest staged four-role set/i)).toBeTruthy();
    const authorize = screen.getByRole("button", {
      name: "Request exact campaign authorization",
    });
    expect((authorize as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(authorize);

    await waitFor(() => expect(command).toHaveBeenCalledTimes(1));
    const [path, payload] = command.mock.calls[0] as [string, Record<string, unknown>];
    expect(path).toBe("campaign-authorization-requests");
    expect(payload).toEqual(expect.objectContaining({
      target_id: "target-1",
      corpus_hash: "c".repeat(64),
      hosted_run: hostedRun,
      caps: {
        budget_usd: 1,
        max_attempts_per_run: 2,
        target_requests_per_second: 0.5,
        run_timeout_seconds: 60,
        logical_case_limit: 2,
        physical_request_limit: 6,
        target_retries_per_turn: 1,
      },
    }));
    expect(JSON.stringify(payload)).not.toContain("credential_reference");
    expect(JSON.stringify(payload)).not.toContain("model_id");
  });

  it("surfaces an unavailable exact workload envelope and does not submit invented limits", async () => {
    const launchPrincipal: Principal = {
      ...principal,
      organization_permissions: [
        ...principal.organization_permissions,
        PERMISSIONS.campaignLaunch,
      ],
    };
    const campaignTarget = {
      ...target(true),
      campaign_template: {
        target_id: "target-1",
        target_version: "1.0.0",
        surface_id: "chat",
        surface_version: "1.0.0",
        corpus_id: "week-3",
        corpus_hash: "c".repeat(64),
        case_count: 2,
        tool_sources: [],
        execution_profile: "live" as const,
        maximum_caps: target(true).safety_caps,
        hosted_run: hostedRun,
      },
    };
    const command = vi.fn();
    const client = {
      read: vi.fn(async (path: string) => path === "target-catalog"
        ? { state: "empty" as const, data: [] }
        : { state: "ready" as const, data: [campaignTarget] }),
      command,
    } as unknown as ApiClient;

    render(
      <TargetsScreen
        client={client}
        principal={launchPrincipal}
        entityId={null}
        getToken={async () => "session"}
      />,
    );

    fireEvent.click(await screen.findByText("Registered target"));
    expect(await screen.findByText(/did not bind a complete exact workload envelope/i))
      .toBeTruthy();
    const authorize = screen.getByRole("button", {
      name: "Request exact campaign authorization",
    });
    expect((authorize as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(authorize);
    expect(command).not.toHaveBeenCalled();
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
    expect(screen.getByText("$5")).toBeTruthy();
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

  it("labels partial activity cost and bounded budget remaining without inventing exact values", async () => {
    const client = {
      read: vi.fn(async (path: string) => {
        if (path === "agents") {
          return {
            state: "ready" as const,
            data: [partiallyAccountedAgent],
          };
        }
        if (path === "agent-activity") {
          return {
            state: "ready" as const,
            data: [partiallyAccountedActivity],
          };
        }
        throw new Error(`Unexpected read: ${path}`);
      }),
      command: vi.fn(),
    } as unknown as ApiClient;

    render(<AgentsScreen client={client} principal={principal} />);

    const records = await screen.findByLabelText("Authoritative records");
    expect(within(records).getByText("$0.0300 known · partial")).toBeTruthy();
    expect(
      screen.getByText("Role USD remaining").parentElement?.textContent,
    ).toBe("Role USD remaining≤ $3.97 / $4.00 (known-spend bound)");
    expect(
      screen.getByText("Global USD remaining").parentElement?.textContent,
    ).toBe("Global USD remaining≤ $9.97 / $10.00 (known-spend bound)");
  });

  it("labels partial trace cost as a known amount in list and detail views", async () => {
    const client = {
      read: vi.fn(async (path: string) => {
        if (path === "traces") {
          return {
            state: "ready" as const,
            data: [partiallyAccountedTrace],
          };
        }
        throw new Error(`Unexpected read: ${path}`);
      }),
      command: vi.fn(),
    } as unknown as ApiClient;

    render(<TracesScreen client={client} />);

    const traceRow = await screen.findByRole("listitem");
    expect(traceRow.textContent).toContain("$0.030 known · partial");
    expect(
      screen.getByText("Measured cost").parentElement?.textContent,
    ).toBe("Measured cost$0.0300 known · partial");
  });
});
