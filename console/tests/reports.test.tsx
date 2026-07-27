import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import type { Principal } from "../src/api/contracts";
import { RESOURCE_PATHS } from "../src/api/paths";
import {
  campaignSecurityConclusion,
  ReportsScreen,
} from "../src/screens/ConsoleScreens";
import type {
  CampaignOperationsReadModel,
  CampaignReadModel,
} from "../src/types";
import { PERMISSIONS } from "../src/types";

const at = "2026-07-27T08:00:00Z";

const campaign: CampaignReadModel = {
  target_id: "clinical-copilot-week2",
  target_version: "1.0.1",
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
  corpus_id: "headshot-live-100-v1-batch-01",
  corpus_hash: "corpus-hash",
  caps: {
    budget_usd: 10,
    max_attempts_per_run: 34,
    target_requests_per_second: 0.5,
    run_timeout_seconds: 3600,
    logical_case_limit: 34,
    physical_request_limit: 41,
    target_retries_per_turn: 0,
  },
  run_nonce: "report-test",
  execution_profile: "live",
  hosted_run: null,
  run_id: "8cf233182ac94116b8f404021788a5b6",
  authorization_request_id: "approval-1",
  scope_hash: "scope-hash",
  launcher_user_id: "operator-1",
  state: "complete",
  attempt_count: 34,
  created_at: at,
};

const operations: CampaignOperationsReadModel = {
  campaign_id: campaign.run_id,
  state: "complete",
  created_at: at,
  progress: {
    planned: 34,
    started: 34,
    running: 0,
    completed: 33,
    failed: 1,
    skipped: null,
    remaining: 0,
  },
  executions: {
    logical_attempts: 34,
    physical_target_requests: 40,
    provider_calls: 101,
  },
  current_work: null,
  costs: {
    provider_measured_usd: 1.75,
    target_measured_usd: 0,
    total_measured_usd: 1.75,
    provider_measurement_state: "measured",
    target_measurement_state: "measured",
    measurement_state: "measured",
    currency: "USD",
  },
  limits: {
    target_budget_usd: 10,
    target_budget_remaining_usd: 10,
    provider_budget_usd: 10,
    provider_budget_remaining_usd: 8.25,
    logical_case_limit: 34,
    physical_request_limit: 41,
    physical_requests_remaining: 1,
    provider_call_limit: 136,
    provider_calls_remaining: 35,
    target_requests_per_second: 0.5,
    run_timeout_seconds: 3600,
    max_attempts_per_run: 34,
    target_retries_per_turn: 0,
    provider_max_retries: 0,
    provider_max_concurrency: 1,
    provider_timeout_seconds: 180,
  },
  verdict_distribution: {
    INDETERMINATE: 32,
    ERROR: 1,
  },
  queue: {
    queued_jobs: 0,
    leased_jobs: 0,
    dead_lettered_jobs: 0,
    rate_limit_active: false,
  },
  terminal_failure: null,
  as_of: at,
  cursor: 100,
};

const principal: Principal = {
  user_id: "operator-1",
  organization_id: "org-1",
  organization_role: "org:operator",
  organization_permissions: [PERMISSIONS.consoleRead],
};

describe("campaign completion reports", () => {
  it("labels a completed but uncalibrated outcome as inconclusive", () => {
    expect(campaignSecurityConclusion(operations)).toEqual(expect.objectContaining({
      label: "INCONCLUSIVE",
      tone: "queued",
    }));
    expect(campaignSecurityConclusion(operations).detail)
      .toContain("campaign completed operationally");
  });

  it("shows the latest terminal run even when no vulnerability report exists", async () => {
    const client = {
      read: vi.fn(async (path: string) => {
        if (path === RESOURCE_PATHS.campaigns) {
          return { state: "ready" as const, data: [campaign] };
        }
        if (path === RESOURCE_PATHS.campaignOperations(campaign.run_id)) {
          return { state: "ready" as const, data: operations };
        }
        if (path === RESOURCE_PATHS.campaignAgentActivity(campaign.run_id)) {
          return { state: "empty" as const, data: null };
        }
        if (path === RESOURCE_PATHS.reports) {
          return { state: "empty" as const, data: null };
        }
        return { state: "empty" as const, data: null };
      }),
      command: vi.fn(),
    } as unknown as ApiClient;

    const view = render(
      <ReportsScreen
        client={client}
        principal={principal}
        entityId={null}
        getToken={async () => null}
      />,
    );

    expect(await screen.findByRole("heading", {
      name: "Campaign completion report",
      exact: true,
    })).not.toBeNull();
    expect(screen.getAllByText("INCONCLUSIVE").length).toBeGreaterThan(0);
    expect(screen.getByText(/campaign completed operationally/)).not.toBeNull();
    expect(screen.getByText("40")).not.toBeNull();
    expect(screen.getByText("101")).not.toBeNull();
    expect(screen.getByText(
      "No confirmed exploit produced a vulnerability report.",
    )).not.toBeNull();
    await waitFor(() => expect(client.read).toHaveBeenCalledWith(
      RESOURCE_PATHS.campaignAgentActivity(campaign.run_id),
      expect.any(AbortSignal),
    ));
    view.unmount();
  });
});
