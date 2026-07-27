import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import type { Principal } from "../src/api/contracts";
import {
  authorizationLifetimeSeconds,
  buildSuiteBatchViews,
  summarizeSuiteProgress,
  TargetsScreen,
} from "../src/screens/ConsoleScreens";
import {
  PERMISSIONS,
  type ApprovalReadModel,
  type CampaignReadModel,
  type CampaignSuiteTemplateReadModel,
} from "../src/types";

afterEach(cleanup);

const caps = {
  budget_usd: 5,
  max_attempts_per_run: 34,
  target_requests_per_second: 1,
  run_timeout_seconds: 900,
  logical_case_limit: 34,
  physical_request_limit: 41,
  target_retries_per_turn: 0,
};
const hostedRun = {
  configuration_set_sha256: "a".repeat(64),
  generation_policy_sha256: "b".repeat(64),
  session_generation: "demo-generation",
  provider_model_call_limit: 56,
  provider_model_spend_limit_usd: "10",
  provider_max_retries: 0,
  provider_max_concurrency: 1 as const,
  provider_timeout_seconds: 180,
};
const suite: CampaignSuiteTemplateReadModel = {
  suite_id: "server-suite",
  title: "Full 100-case suite",
  case_count: 100,
  physical_request_count: 121,
  categories: ["PI", "DX", "TM", "SC", "DOS", "IR"],
  batches: [34, 33, 33].map((caseCount, index) => ({
    ordinal: index + 1,
    batch_id: `batch-${index + 1}`,
    target_id: "target-1",
    target_version: "1.0.0",
    surface_id: "chat",
    surface_version: "1.0.0",
    corpus_id: `server-corpus-${index + 1}`,
    corpus_hash: String(index + 1).repeat(64),
    case_count: caseCount,
    physical_request_count: index === 0 ? 41 : 40,
    tool_sources: ["garak"],
    execution_profile: "live" as const,
    maximum_caps: {
      ...caps,
      max_attempts_per_run: caseCount,
      logical_case_limit: caseCount,
      physical_request_limit: index === 0 ? 41 : 40,
    },
    hosted_run: hostedRun,
  })),
};

const campaign = (
  batchIndex: number,
  state: CampaignReadModel["state"],
): CampaignReadModel => {
  const batch = suite.batches[batchIndex];
  return {
    target_id: batch.target_id,
    target_version: batch.target_version,
    surface_id: batch.surface_id,
    surface_version: batch.surface_version,
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
    corpus_id: batch.corpus_id,
    corpus_hash: batch.corpus_hash,
    caps: batch.maximum_caps,
    run_nonce: `suite-run-nonce-${batchIndex}`,
    execution_profile: batch.execution_profile,
    hosted_run: batch.hosted_run,
    run_id: `run-${batchIndex}`,
    authorization_request_id: `approval-${batchIndex}`,
    scope_hash: `scope-${batchIndex}`,
    launcher_user_id: "operator-1",
    state,
    attempt_count: state === "complete" ? batch.case_count : 1,
    created_at: `2026-07-25T00:0${batchIndex}:00Z`,
  };
};

const approval = (batchIndex: number): ApprovalReadModel => {
  const batch = suite.batches[batchIndex];
  return {
  target_id: batch.target_id,
  target_version: batch.target_version,
  surface_id: batch.surface_id,
  surface_version: batch.surface_version,
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
  corpus_id: batch.corpus_id,
  corpus_hash: batch.corpus_hash,
  caps: batch.maximum_caps,
  run_nonce: `suite-run-nonce-${batchIndex}`,
  execution_profile: "live",
  hosted_run: batch.hosted_run,
  request_id: `approval-${batchIndex}`,
  scope_hash: `scope-${batchIndex}`,
  launcher_user_id: "operator-1",
  status: "pending",
  decision: null,
  approver_user_id: null,
  self_approval_override: false,
  decided_at: null,
  expires_at: "2026-07-26T00:00:00Z",
  created_at: `2026-07-25T00:0${batchIndex}:00Z`,
  expired: false,
  consumed: false,
  };
};

describe("full suite console", () => {
  it("keeps authorization valid beyond the complete run timeout", () => {
    expect(authorizationLifetimeSeconds(900)).toBe(1800);
    expect(authorizationLifetimeSeconds(3600)).toBe(4500);
    expect(authorizationLifetimeSeconds(7200)).toBe(8100);
  });

  it("counts only completed server-owned batches and requires all three for completion", () => {
    const partialViews = buildSuiteBatchViews(
      suite,
      [],
      [campaign(0, "complete"), campaign(1, "running")],
    );
    expect(summarizeSuiteProgress(suite, partialViews)).toEqual({
      completedBatches: 1,
      complete: false,
    });

    const completeViews = buildSuiteBatchViews(
      suite,
      [],
      [campaign(0, "complete"), campaign(1, "complete"), campaign(2, "complete")],
    );
    expect(summarizeSuiteProgress(suite, completeViews)).toEqual({
      completedBatches: 3,
      complete: true,
    });
  });

  it("does not cross-match campaign or approval state from another exact scope", () => {
    const matchingCampaign = campaign(0, "running");
    const wrongSurfaceCampaign: CampaignReadModel = {
      ...campaign(0, "complete"),
      run_id: "newer-wrong-surface",
      surface_id: "app",
      surface_version: "2.0.0",
      created_at: "2026-07-25T01:00:00Z",
    };
    const campaignView = buildSuiteBatchViews(
      suite,
      [],
      [matchingCampaign, wrongSurfaceCampaign],
    )[0];
    expect(campaignView.state).toBe("running");
    expect(campaignView.campaign?.run_id).toBe(matchingCampaign.run_id);

    const matchingApproval = approval(0);
    const wrongSurfaceApproval: ApprovalReadModel = {
      ...approval(0),
      request_id: "newer-wrong-surface-approval",
      surface_id: "app",
      surface_version: "2.0.0",
      status: "approved",
      decision: "approved",
      approver_user_id: "approver-1",
      decided_at: "2026-07-25T00:59:00Z",
      created_at: "2026-07-25T01:00:00Z",
    };
    const approvalView = buildSuiteBatchViews(
      suite,
      [matchingApproval, wrongSurfaceApproval],
      [],
    )[0];
    expect(approvalView.state).toBe("authorization pending");
    expect(approvalView.approval?.request_id).toBe(matchingApproval.request_id);

    const wrongHostedBinding: CampaignReadModel = {
      ...campaign(0, "complete"),
      hosted_run: {
        ...hostedRun,
        provider_model_call_limit: hostedRun.provider_model_call_limit + 1,
      },
    };
    const wrongBatchCaps: CampaignReadModel = {
      ...campaign(0, "complete"),
      caps: {
        ...suite.batches[0].maximum_caps,
        logical_case_limit: suite.batches[0].case_count - 1,
      },
    };
    const unmatchedView = buildSuiteBatchViews(
      suite,
      [],
      [wrongHostedBinding, wrongBatchCaps],
    )[0];
    expect(unmatchedView.state).toBe("ready");
    expect(unmatchedView.campaign).toBeNull();
  });

  it("shows one next Operator action and one distinct Approver decision", async () => {
    const target = {
      target_id: "target-1",
      version: "1.0.0",
      content_hash: "target-content",
      name: "Demo target",
      adapter_kind: "openemr",
      environment: "staging",
      base_url: "https://target.invalid",
      auth_mode: "bearer",
      credential_configured: true,
      synthetic_data_only: true,
      safety_caps: caps,
      lifecycle: "ready",
      allowed_lifecycle_transitions: ["disabled"],
      surfaces: [],
      campaign_template: null,
      campaign_suite_templates: [suite],
      created_at: "2026-07-25T00:00:00Z",
    };
    const operator: Principal = {
      user_id: "operator-1",
      organization_id: "org-1",
      organization_role: "org:operator",
      organization_permissions: [PERMISSIONS.consoleRead, PERMISSIONS.campaignLaunch],
    };
    const read = vi.fn(async (path: string) => ({
      state: "ready" as const,
      data: path === "targets"
        ? [target]
        : path === "approvals" || path === "campaigns"
          ? []
          : [],
    }));
    const client = { read, command: vi.fn() } as unknown as ApiClient;
    const view = render(
      <TargetsScreen
        client={client}
        principal={operator}
        entityId={null}
        getToken={async () => "session"}
      />,
    );

    expect(await screen.findAllByText("Demo target")).toHaveLength(2);
    expect(screen.getByText("1 ready")).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Request approval for batch 1" }))
      .toHaveLength(1);
    expect(screen.queryByRole("button", { name: "Request approval for batch 2" }))
      .toBeNull();
    expect(screen.getByText("Batch scopes")).toBeTruthy();
    expect(screen.getByText("Completed records")).toBeTruthy();
    expect(screen.queryByText("0/100")).toBeNull();
    expect(screen.queryByText("0/121")).toBeNull();

    view.unmount();
    const approver: Principal = {
      ...operator,
      user_id: "approver-1",
      organization_role: "org:approver",
      organization_permissions: [PERMISSIONS.consoleRead, PERMISSIONS.campaignAuthorize],
    };
    const approverClient = {
      read: vi.fn(async (path: string) => ({
        state: "ready" as const,
        data: path === "targets"
          ? [target]
          : path === "approvals"
            ? suite.batches.map((_, index) => approval(index))
            : [],
      })),
      command: vi.fn(),
    } as unknown as ApiClient;
    expect(buildSuiteBatchViews(
      suite,
      suite.batches.map((_, index) => approval(index)),
      [],
    ).map((entry) => entry.state)).toEqual([
      "authorization pending",
      "authorization pending",
      "authorization pending",
    ]);
    render(
      <TargetsScreen
        client={approverClient}
        principal={approver}
        entityId={null}
        getToken={async () => "session"}
      />,
    );
    expect(await screen.findAllByRole("button", { name: "Approve batch 1" }))
      .toHaveLength(1);
    expect(screen.getAllByRole("button", { name: "Reject" })).toHaveLength(1);
    expect(screen.queryByRole("button", { name: /Request approval/ })).toBeNull();
  });

  it("shows only ready targets that have a governed pilot suite", async () => {
    const pilot = (targetId: string, name: string) => ({
      target_id: targetId,
      version: "1.0.0",
      content_hash: `${targetId}-content`,
      name,
      adapter_kind: "openemr",
      environment: "staging",
      base_url: "https://target.invalid",
      auth_mode: "bearer",
      credential_configured: true,
      synthetic_data_only: true,
      safety_caps: caps,
      lifecycle: "ready",
      allowed_lifecycle_transitions: ["disabled"],
      surfaces: [],
      campaign_template: null,
      campaign_suite_templates: [{
        ...suite,
        suite_id: `${targetId}-suite`,
        batches: suite.batches.map((batch) => ({ ...batch, target_id: targetId })),
      }],
      created_at: "2026-07-25T00:00:00Z",
    });
    const records = [
      pilot("clinical-copilot-week1", "Clinical Co-Pilot Week 1"),
      pilot("clinical-copilot-week2", "Clinical Co-Pilot Week 2"),
      { ...pilot("obsolete-draft", "Obsolete draft"), lifecycle: "draft" },
      {
        ...pilot("historical-target", "Historical target"),
        campaign_suite_templates: [],
      },
    ];
    const client = {
      read: vi.fn(async (path: string) => ({
        state: "ready" as const,
        data: path === "targets" ? records : [],
      })),
      command: vi.fn(),
    } as unknown as ApiClient;
    const operator: Principal = {
      user_id: "operator-1",
      organization_id: "org-1",
      organization_role: "org:operator",
      organization_permissions: [PERMISSIONS.consoleRead, PERMISSIONS.campaignLaunch],
    };

    render(
      <TargetsScreen
        client={client}
        principal={operator}
        entityId={null}
        getToken={async () => "session"}
      />,
    );

    expect(await screen.findByText("2 ready")).toBeTruthy();
    expect(screen.getAllByText("Clinical Co-Pilot Week 1")).toHaveLength(2);
    expect(screen.getByText("Clinical Co-Pilot Week 2")).toBeTruthy();
    expect(screen.queryByText("Obsolete draft")).toBeNull();
    expect(screen.queryByText("Historical target")).toBeNull();
    expect(screen.queryByText("Trusted target catalog")).toBeNull();
    expect(screen.queryByText("Target registry")).toBeNull();
  });

  it("loads exact campaign operations even when no ready pilot target is available", async () => {
    const campaignId = "run-without-ready-pilot";
    const read = vi.fn(async (path: string) => {
      if (path === "targets") return { state: "empty" as const, data: null };
      if (path === "campaigns") return { state: "ready" as const, data: [] };
      if (path === `campaigns/${campaignId}/operations`) {
        return { state: "empty" as const, data: null };
      }
      return { state: "empty" as const, data: null };
    });
    const client = { read, command: vi.fn() } as unknown as ApiClient;
    const operator: Principal = {
      user_id: "operator-1",
      organization_id: "org-1",
      organization_role: "org:operator",
      organization_permissions: [PERMISSIONS.consoleRead, PERMISSIONS.campaignLaunch],
    };

    render(
      <TargetsScreen
        client={client}
        principal={operator}
        entityId={null}
        getToken={async () => "session"}
        campaignId={campaignId}
      />,
    );

    expect(await screen.findByText("Selected campaign")).toBeTruthy();
    expect(screen.getByText("Authoritative campaign operations")).toBeTruthy();
    expect(await screen.findByText(
      "No authoritative operations projection is available for this campaign.",
    )).toBeTruthy();
    expect(read).toHaveBeenCalledWith(
      `campaigns/${campaignId}/operations`,
      expect.anything(),
    );
  });

  it("maps a selected campaign only to the exact surface when suites share a corpus", async () => {
    const wrongSurfaceSuite: CampaignSuiteTemplateReadModel = {
      ...suite,
      suite_id: "wrong-surface-suite",
      batches: suite.batches.map((batch) => ({
        ...batch,
        ordinal: batch.ordinal === 1 ? 3 : batch.ordinal === 3 ? 1 : 2,
        batch_id: `wrong-surface-${batch.batch_id}`,
        surface_id: "app",
        surface_version: "2.0.0",
      })),
    };
    const exactSurfaceSuite: CampaignSuiteTemplateReadModel = {
      ...suite,
      suite_id: "exact-surface-suite",
      batches: suite.batches.map((batch) => ({
        ...batch,
        batch_id: `exact-surface-${batch.batch_id}`,
      })),
    };
    const target = {
      target_id: "target-1",
      version: "1.0.0",
      content_hash: "target-content",
      name: "Demo target",
      adapter_kind: "openemr",
      environment: "staging",
      base_url: "https://target.invalid",
      auth_mode: "bearer",
      credential_configured: true,
      synthetic_data_only: true,
      safety_caps: caps,
      lifecycle: "ready",
      allowed_lifecycle_transitions: ["disabled"],
      surfaces: [],
      campaign_template: null,
      campaign_suite_templates: [wrongSurfaceSuite, exactSurfaceSuite],
      created_at: "2026-07-25T00:00:00Z",
    };
    const selectedCampaign: CampaignReadModel = {
      ...campaign(0, "running"),
      run_id: "selected-exact-surface",
    };
    const read = vi.fn(async (path: string) => {
      if (path === "targets") return { state: "ready" as const, data: [target] };
      if (path === "campaigns") {
        return { state: "ready" as const, data: [selectedCampaign] };
      }
      if (path === "approvals") return { state: "ready" as const, data: [] };
      if (path === "campaigns/selected-exact-surface/operations") {
        return { state: "empty" as const, data: null };
      }
      return { state: "empty" as const, data: null };
    });
    const client = { read, command: vi.fn() } as unknown as ApiClient;
    const operator: Principal = {
      user_id: "operator-1",
      organization_id: "org-1",
      organization_role: "org:operator",
      organization_permissions: [PERMISSIONS.consoleRead, PERMISSIONS.campaignLaunch],
    };

    render(
      <TargetsScreen
        client={client}
        principal={operator}
        entityId={null}
        getToken={async () => "session"}
        campaignId="selected-exact-surface"
      />,
    );

    expect(await screen.findByText("Batch 1 · running")).toBeTruthy();
    expect(screen.queryByText("Batch 3 · running")).toBeNull();
    expect(screen.getAllByText("Demo target")).toHaveLength(2);
  });

  it("keeps full suite state while an older same-batch campaign supplies exact operations", async () => {
    const target = {
      target_id: "target-1",
      version: "1.0.0",
      content_hash: "target-content",
      name: "Demo target",
      adapter_kind: "openemr",
      environment: "staging",
      base_url: "https://target.invalid",
      auth_mode: "bearer",
      credential_configured: true,
      synthetic_data_only: true,
      safety_caps: caps,
      lifecycle: "ready",
      allowed_lifecycle_transitions: ["disabled"],
      surfaces: [],
      campaign_template: null,
      campaign_suite_templates: [suite],
      created_at: "2026-07-25T00:00:00Z",
    };
    const readCampaign = (
      batchIndex: number,
      state: CampaignReadModel["state"],
      runId: string,
      createdAt: string,
    ): CampaignReadModel => {
      const batch = suite.batches[batchIndex];
      return {
        target_id: batch.target_id,
        target_version: batch.target_version,
        surface_id: batch.surface_id,
        surface_version: batch.surface_version,
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
        corpus_id: batch.corpus_id,
        corpus_hash: batch.corpus_hash,
        caps: batch.maximum_caps,
        run_nonce: `suite-run-nonce-${runId}`,
        execution_profile: "live",
        hosted_run: batch.hosted_run,
        run_id: runId,
        authorization_request_id: `approval-${runId}`,
        scope_hash: `scope-${runId}`,
        launcher_user_id: "operator-1",
        state,
        attempt_count: state === "complete" ? batch.case_count : 1,
        created_at: createdAt,
      };
    };
    const selectedOlderCampaign = readCampaign(
      0,
      "failed",
      "run-selected-older",
      "2026-07-25T00:00:00Z",
    );
    const latestSameBatchCampaign = readCampaign(
      0,
      "complete",
      "run-latest-same-batch",
      "2026-07-25T00:10:00Z",
    );
    const activeOtherBatch = readCampaign(
      1,
      "running",
      "run-active-other-batch",
      "2026-07-25T00:11:00Z",
    );
    const read = vi.fn(async (path: string) => {
      if (path === "targets") return { state: "ready" as const, data: [target] };
      if (path === "campaigns") {
        return {
          state: "ready" as const,
          data: [selectedOlderCampaign, latestSameBatchCampaign, activeOtherBatch],
        };
      }
      if (path === "approvals") return { state: "ready" as const, data: [] };
      if (path === "campaigns/run-selected-older/operations") {
        return { state: "empty" as const, data: null };
      }
      return { state: "empty" as const, data: null };
    });
    const client = { read, command: vi.fn() } as unknown as ApiClient;
    const operator: Principal = {
      user_id: "operator-1",
      organization_id: "org-1",
      organization_role: "org:operator",
      organization_permissions: [PERMISSIONS.consoleRead, PERMISSIONS.campaignLaunch],
    };

    render(
      <TargetsScreen
        client={client}
        principal={operator}
        entityId={null}
        getToken={async () => "session"}
        campaignId="run-selected-older"
      />,
    );

    expect(await screen.findByText("Batch 1 · failed")).toBeTruthy();
    expect(screen.getByText("Authorization scope · completed")).toBeTruthy();
    expect(screen.getByText("Authorization scope · running")).toBeTruthy();
    expect(screen.getByText("Batch 2 of 3")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Request approval for batch 1" })).toBeNull();
    expect(read).toHaveBeenCalledWith(
      "campaigns/run-selected-older/operations",
      expect.anything(),
    );
  });

  it("uses the live operations projection instead of attempt or template progress", async () => {
    const target = {
      target_id: "target-1",
      version: "1.0.0",
      content_hash: "target-content",
      name: "Demo target",
      adapter_kind: "openemr",
      environment: "staging",
      base_url: "https://target.invalid",
      auth_mode: "bearer",
      credential_configured: true,
      synthetic_data_only: true,
      safety_caps: caps,
      lifecycle: "ready",
      allowed_lifecycle_transitions: ["disabled"],
      surfaces: [],
      campaign_template: null,
      campaign_suite_templates: [suite],
      created_at: "2026-07-25T00:00:00Z",
    };
    const otherSuite = {
      ...suite,
      suite_id: "other-suite",
      batches: suite.batches.map((batch) => ({
        ...batch,
        batch_id: `other-${batch.batch_id}`,
        target_id: "target-other",
        target_version: "2.0.0",
      })),
    };
    const otherTarget = {
      ...target,
      target_id: "target-other",
      version: "2.0.0",
      name: "Other pilot",
      campaign_suite_templates: [otherSuite],
    };
    const runningCampaign = {
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
      corpus_id: suite.batches[0].corpus_id,
      corpus_hash: suite.batches[0].corpus_hash,
      caps,
      run_nonce: "suite-run-nonce-live",
      execution_profile: "live",
      hosted_run: hostedRun,
      run_id: "run-live",
      authorization_request_id: "approval-live",
      scope_hash: "scope-live",
      launcher_user_id: "operator-1",
      state: "running",
      attempt_count: 1,
      created_at: "2026-07-25T00:00:00Z",
    };
    const newerCampaign = {
      ...runningCampaign,
      run_id: "run-newer",
      created_at: "2026-07-25T00:05:00Z",
    };
    const operations = {
      campaign_id: "run-live",
      state: "running",
      created_at: "2026-07-25T00:00:00Z",
      progress: {
        planned: null,
        started: 7,
        running: 1,
        completed: 5,
        failed: 1,
        skipped: null,
        remaining: null,
      },
      executions: {
        logical_attempts: 7,
        physical_target_requests: 9,
        provider_calls: 18,
      },
      current_work: {
        stage: "judge",
        agent_role: "judge",
        execution_id: "execution-live",
        attempt_id: "attempt-live",
        started_at: "2026-07-25T00:01:00Z",
      },
      costs: {
        provider_measured_usd: 0.04,
        target_measured_usd: 0.03,
        total_measured_usd: 0.07,
        provider_measurement_state: "measured",
        target_measurement_state: "partial",
        measurement_state: "partial",
        currency: "USD",
      },
      limits: {
        target_budget_usd: 5,
        target_budget_remaining_usd: 4.97,
        provider_budget_usd: 10,
        provider_budget_remaining_usd: 9.96,
        logical_case_limit: 34,
        physical_request_limit: 41,
        physical_requests_remaining: 32,
        provider_call_limit: 56,
        provider_calls_remaining: 38,
        target_requests_per_second: 1,
        run_timeout_seconds: 900,
        max_attempts_per_run: 34,
        target_retries_per_turn: 0,
        provider_max_retries: 0,
        provider_max_concurrency: 1,
        provider_timeout_seconds: 180,
      },
      verdict_distribution: { PASS: 5 },
      queue: {
        queued_jobs: 0,
        leased_jobs: 1,
        dead_lettered_jobs: 0,
        rate_limit_active: null,
      },
      terminal_failure: null,
      as_of: "2026-07-25T00:02:00Z",
      cursor: 9,
    };
    const read = vi.fn(async (path: string) => ({
      state: "ready" as const,
      data: path === "targets"
        ? [otherTarget, target]
        : path === "campaigns"
          ? [newerCampaign, runningCampaign]
          : path === "campaigns/run-live/operations"
            ? operations
            : [],
    }));
    const client = { read, command: vi.fn() } as unknown as ApiClient;
    const operator: Principal = {
      user_id: "operator-1",
      organization_id: "org-1",
      organization_role: "org:operator",
      organization_permissions: [PERMISSIONS.consoleRead, PERMISSIONS.campaignLaunch],
    };

    render(
      <TargetsScreen
        client={client}
        principal={operator}
        entityId={null}
        getToken={async () => "session"}
        campaignId="run-live"
      />,
    );

    const heading = await screen.findByText("Authoritative campaign operations");
    const operationsRegion = heading.closest(".suite-next-action");
    expect(operationsRegion).not.toBeNull();
    const live = within(operationsRegion as HTMLElement);
    await waitFor(() => expect(live.getAllByText("Unknown")).toHaveLength(4));
    expect(live.getAllByText("7")).toHaveLength(2);
    expect(live.getByText("Partial")).toBeTruthy();
    expect(live.getByText("$0.0700 known · Partial")).toBeTruthy();
    expect(screen.queryByText("1/34 cases recorded")).toBeNull();
    expect(screen.queryByText("34 cases and 41 requests recorded")).toBeNull();
    expect(screen.getAllByText("Demo target")).toHaveLength(2);
    expect(screen.queryByText("Other pilot")).toBeNull();
    expect(read).toHaveBeenCalledWith("campaigns/run-live/operations", expect.anything());
  });
});
