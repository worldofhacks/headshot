import { cleanup, render, screen } from "@testing-library/react";
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
): CampaignReadModel => ({
  ...suite.batches[batchIndex],
  run_id: `run-${batchIndex}`,
  authorization_request_id: `approval-${batchIndex}`,
  scope_hash: `scope-${batchIndex}`,
  launcher_user_id: "operator-1",
  state,
  attempt_count: state === "complete" ? suite.batches[batchIndex].case_count : 1,
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
  caps: suite.batches[batchIndex].maximum_caps,
  run_nonce: `suite-run-nonce-${batchIndex}`,
  created_at: `2026-07-25T00:0${batchIndex}:00Z`,
});

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
      completedCases: 34,
      completedRequests: 41,
      complete: false,
    });

    const completeViews = buildSuiteBatchViews(
      suite,
      [],
      [campaign(0, "complete"), campaign(1, "complete"), campaign(2, "complete")],
    );
    expect(summarizeSuiteProgress(suite, completeViews)).toEqual({
      completedBatches: 3,
      completedCases: 100,
      completedRequests: 121,
      complete: true,
    });
  });

  it("shows Operator request actions and distinct Approver decisions without browser authority", async () => {
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

    expect(
      await screen.findByText(
        "Full 100-case suite — Demo target (target-1@1.0.0)",
      ),
    ).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Request batch authorization" }))
      .toHaveLength(3);
    expect(screen.getByText("0/100")).toBeTruthy();
    expect(screen.getByText("0/121")).toBeTruthy();

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
    expect(await screen.findAllByRole("button", { name: "Approve exact batch" }))
      .toHaveLength(3);
    expect(screen.getAllByRole("button", { name: "Reject exact batch" })).toHaveLength(3);
    expect(screen.queryByRole("button", { name: "Request batch authorization" })).toBeNull();
  });
});
