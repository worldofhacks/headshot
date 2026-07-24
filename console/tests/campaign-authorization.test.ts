import { describe, expect, it } from "vitest";

import {
  AUTHORIZATION_EXECUTION_MARGIN_SECONDS,
  MAX_AUTHORIZATION_EXPIRY_SECONDS,
  authorizationExpirySeconds,
  buildCampaignAuthorizationPayload,
  campaignAuthorizationBlocker,
  exactWorkloadCaps,
} from "../src/campaignAuthorization";
import type {
  CampaignCapSelection,
} from "../src/campaignAuthorization";
import type { CampaignTemplateReadModel } from "../src/types";

const selection = (
  caseCount: number,
  overrides: Partial<CampaignCapSelection> = {},
): CampaignCapSelection => ({
  budget_usd: 1,
  max_attempts_per_run: caseCount,
  target_requests_per_second: 0.25,
  run_timeout_seconds: 900,
  ...overrides,
});

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
    max_attempts_per_run: 40,
    target_requests_per_second: 0.5,
    run_timeout_seconds: 3_300,
    logical_case_limit: 40,
    physical_request_limit: 120,
    target_retries_per_turn: 2,
  },
  workload_caps: {
    logical_case_limit: 14,
    physical_request_limit: 17,
    target_retries_per_turn: 0,
  },
  target_policy: {
    exact_host: "target.example.test",
    allowlisted_hosts: ["target.example.test"],
    synthetic_data_only: true,
    synthetic_data_attestation_ref: "attestation://headshot/synthetic-v1",
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
  it.each([
    { caseCount: 9, physicalCount: 12 },
    { caseCount: 14, physicalCount: 17 },
  ])(
    "authorizes the exact $caseCount-case workload beneath a 40-case target ceiling",
    ({ caseCount, physicalCount }) => {
      const selectedTemplate = template({
        case_count: caseCount,
        workload_caps: {
          logical_case_limit: caseCount,
          physical_request_limit: physicalCount,
          target_retries_per_turn: 0,
        },
      });
      const selectedCaps = selection(caseCount);
      const payload = buildCampaignAuthorizationPayload({
        template: selectedTemplate,
        selection: selectedCaps,
        runNonce: " reviewed-run-nonce-0001 ",
      });

      expect(payload).not.toBeNull();
      expect(payload?.caps).toEqual({
        budget_usd: 1,
        max_attempts_per_run: caseCount,
        target_requests_per_second: 0.25,
        run_timeout_seconds: 900,
        logical_case_limit: caseCount,
        physical_request_limit: physicalCount,
        target_retries_per_turn: 0,
      });
      expect(payload?.run_nonce).toBe("reviewed-run-nonce-0001");
      expect(payload?.corpus_id).toBe("reviewed-corpus");
      expect(payload?.corpus_hash).toBe("c".repeat(64));
      expect(payload?.expires_in_seconds).toBeGreaterThan(
        selectedCaps.run_timeout_seconds + AUTHORIZATION_EXECUTION_MARGIN_SECONDS,
      );
      expect(payload?.expires_in_seconds).toBeLessThanOrEqual(
        MAX_AUTHORIZATION_EXPIRY_SECONDS,
      );
    },
  );

  it("rejects the 100-case workload beneath a 40-case target ceiling", () => {
    const selectedTemplate = template({
      case_count: 100,
      workload_caps: {
        logical_case_limit: 100,
        physical_request_limit: 121,
        target_retries_per_turn: 0,
      },
    });

    expect(campaignAuthorizationBlocker({
      template: selectedTemplate,
      selection: selection(100),
      runNonce: "reviewed-run-nonce-0001",
    })).toMatch(/fit every server-supplied target ceiling/i);
    expect(buildCampaignAuthorizationPayload({
      template: selectedTemplate,
      selection: selection(100),
      runNonce: "reviewed-run-nonce-0001",
    })).toBeNull();
  });

  it("derives a bounded expiry strictly beyond timeout plus execution margin", () => {
    expect(authorizationExpirySeconds(900)).toBe(1_201);
    expect(authorizationExpirySeconds(900.75)).toBe(1_201);
    expect(authorizationExpirySeconds(3_299.9)).toBe(3_600);
    expect(authorizationExpirySeconds(3_300)).toBeNull();
  });

  it("never treats target ceilings as workload data", () => {
    const selected = template({ workload_caps: null });

    expect(exactWorkloadCaps(selected)).toBeNull();
    expect(campaignAuthorizationBlocker({
      template: selected,
      selection: selection(14),
      runNonce: "reviewed-run-nonce-0001",
    })).toMatch(/server-derived workload/i);
    expect(buildCampaignAuthorizationPayload({
      template: selected,
      selection: selection(14),
      runNonce: "reviewed-run-nonce-0001",
    })).toBeNull();
  });

  it.each([
    {
      name: "corpus identity",
      selected: template({ corpus_hash: "not-a-sha256" }),
      caps: selection(14),
      expected: /validated immutable corpus/i,
    },
    {
      name: "target and allowlist",
      selected: template({ target_policy: null }),
      caps: selection(14),
      expected: /target host.*allowlist/i,
    },
    {
      name: "synthetic-data assertion",
      selected: template({
        target_policy: {
          exact_host: "target.example.test",
          allowlisted_hosts: ["target.example.test"],
          synthetic_data_only: false,
          synthetic_data_attestation_ref: "",
        },
      } as unknown as Partial<CampaignTemplateReadModel>),
      caps: selection(14),
      expected: /synthetic-data-only assertion/i,
    },
    {
      name: "budget authorization",
      selected: template(),
      caps: selection(14, { budget_usd: 3 }),
      expected: /requested budget/i,
    },
    {
      name: "rate authorization",
      selected: template(),
      caps: selection(14, { target_requests_per_second: 1 }),
      expected: /requested target rate/i,
    },
    {
      name: "exact attempt abort limit",
      selected: template(),
      caps: selection(14, { max_attempts_per_run: 15 }),
      expected: /maximum-attempt abort limit/i,
    },
    {
      name: "timeout authorization",
      selected: template(),
      caps: selection(14, { run_timeout_seconds: 3_301 }),
      expected: /requested timeout/i,
    },
    {
      name: "expiry headroom",
      selected: template(),
      caps: selection(14, { run_timeout_seconds: 3_300 }),
      expected: /execution margin/i,
    },
    {
      name: "hosted binding",
      selected: template({ hosted_run: null }),
      caps: selection(14),
      expected: /server-owned four-role/i,
    },
  ])("fails closed with an explicit $name blocker", ({ selected, caps, expected }) => {
    const blocker = campaignAuthorizationBlocker({
      template: selected,
      selection: caps,
      runNonce: "reviewed-run-nonce-0001",
    });
    expect(blocker).toMatch(expected);
    expect(buildCampaignAuthorizationPayload({
      template: selected,
      selection: caps,
      runNonce: "reviewed-run-nonce-0001",
    })).toBeNull();
  });

  it("reports missing template data without producing optimistic payload state", () => {
    expect(campaignAuthorizationBlocker({
      template: null,
      selection: selection(14),
      runNonce: "reviewed-run-nonce-0001",
    })).toMatch(/immutable corpus and campaign template/i);
  });
});
