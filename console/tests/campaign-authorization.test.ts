import { describe, expect, it } from "vitest";

import {
  buildCampaignAuthorizationPayload,
  exactWorkloadCaps,
} from "../src/campaignAuthorization";
import type { CampaignTemplateReadModel } from "../src/types";

const template = (
  overrides: Partial<CampaignTemplateReadModel> = {},
): CampaignTemplateReadModel => ({
  target_id: "target-1",
  target_version: "1.0.0",
  surface_id: "chat",
  surface_version: "1.0.0",
  corpus_id: "reviewed-corpus",
  corpus_hash: "c".repeat(64),
  case_count: 14,
  tool_sources: [],
  execution_profile: "live",
  maximum_caps: {
    budget_usd: 2,
    max_attempts_per_run: 14,
    target_requests_per_second: 0.5,
    run_timeout_seconds: 600,
    logical_case_limit: 14,
    physical_request_limit: 51,
    target_retries_per_turn: 2,
  },
  hosted_run: {
    configuration_set_sha256: "a".repeat(64),
    generation_policy_sha256: "b".repeat(64),
    session_generation: "reviewed-generation",
    provider_model_call_limit: 56,
    provider_model_spend_limit_usd: "5",
    provider_max_retries: 1,
    provider_max_concurrency: 1,
    provider_timeout_seconds: 180,
  },
  ...overrides,
});

describe("exact campaign workload authorization", () => {
  it("copies the complete server-bound workload limits into the command payload", () => {
    const payload = buildCampaignAuthorizationPayload({
      template: template(),
      selection: {
        budget_usd: 1,
        max_attempts_per_run: 14,
        target_requests_per_second: 0.25,
        run_timeout_seconds: 300,
      },
      runNonce: " reviewed-run-nonce-0001 ",
    });

    expect(payload).not.toBeNull();
    expect(payload?.caps).toEqual({
      budget_usd: 1,
      max_attempts_per_run: 14,
      target_requests_per_second: 0.25,
      run_timeout_seconds: 300,
      logical_case_limit: 14,
      physical_request_limit: 51,
      target_retries_per_turn: 2,
    });
    expect(payload?.run_nonce).toBe("reviewed-run-nonce-0001");
    expect(payload?.corpus_id).toBe("reviewed-corpus");
    expect(payload?.corpus_hash).toBe("c".repeat(64));
  });

  it.each([
    ["logical case limit", "logical_case_limit"],
    ["physical request limit", "physical_request_limit"],
    ["retry limit", "target_retries_per_turn"],
  ] as const)("fails closed when the server omits the %s", (_label, field) => {
    const selected = template();
    selected.maximum_caps = {
      ...selected.maximum_caps,
      [field]: null,
    };

    expect(exactWorkloadCaps(selected)).toBeNull();
    expect(buildCampaignAuthorizationPayload({
      template: selected,
      selection: {
        budget_usd: 1,
        max_attempts_per_run: 14,
        target_requests_per_second: 0.25,
        run_timeout_seconds: 300,
      },
      runNonce: "reviewed-run-nonce-0001",
    })).toBeNull();
  });

  it("rejects target ceilings that are not coherently bound to the selected corpus", () => {
    const wrongLogicalCount = template({
      maximum_caps: {
        ...template().maximum_caps,
        logical_case_limit: 15,
      },
    });
    const partialRetryEnvelope = template({
      maximum_caps: {
        ...template().maximum_caps,
        physical_request_limit: 50,
      },
    });

    expect(exactWorkloadCaps(wrongLogicalCount)).toBeNull();
    expect(exactWorkloadCaps(partialRetryEnvelope)).toBeNull();
  });
});
