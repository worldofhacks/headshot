import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import { ApiClientError } from "../src/api/client";
import { failureMessage } from "../src/components/CommandButton";
import { decodeTargets } from "../src/api/read-models";
import { TargetManagement } from "../src/screens/ConsoleScreens";
import type { Principal, TargetReadModel } from "../src/types";

/**
 * A scan authorization request must carry the three exact execution caps.
 *
 * The panel used to send only the four editable ceiling caps. That scope is accepted at request
 * time and approves normally, then the control plane refuses the first physical work unit because
 * the authorized scope has no durable `physical_request_limit` or `target_retries_per_turn`. The
 * operator saw a bare 403 at launch with nothing naming the missing caps.
 *
 * The suite batches were never affected — they spread `...batch.maximum_caps`, which already
 * carries the exact three.
 */

const at = "2026-07-27T00:00:00Z";

// The target's ceiling. The exact three are null here — that is exactly why the console cannot
// simply spread maximum_caps the way the suite batches do, and must derive them from the corpus.
const caps = {
  budget_usd: 5,
  max_attempts_per_run: 14,
  target_requests_per_second: 0.5,
  run_timeout_seconds: 7200,
  logical_case_limit: null,
  physical_request_limit: null,
  target_retries_per_turn: null,
};

const hostedRun = {
  configuration_set_sha256: "a".repeat(64),
  generation_policy_sha256: "b".repeat(64),
  session_generation: "copilot-api",
  provider_model_call_limit: 68,
  provider_model_spend_limit_usd: "5",
  provider_max_retries: 1,
  provider_max_concurrency: 1,
  provider_timeout_seconds: 180,
};

// 14 cases spanning 17 turns — the real headshot-full-scan-v1 shape.
const template = {
  target_id: "clinical-copilot-week1",
  target_version: "1.0.1",
  surface_id: "week1-chat",
  surface_version: "1.0.1",
  corpus_id: "headshot-full-scan-v1",
  corpus_hash: "c".repeat(64),
  case_count: 14,
  physical_request_count: 17,
  tool_sources: [],
  execution_profile: "live" as const,
  maximum_caps: caps,
  hosted_run: hostedRun,
};

const target = {
  target_id: "clinical-copilot-week1",
  version: "1.0.1",
  content_hash: "d".repeat(64),
  name: "Clinical Co-Pilot",
  adapter_kind: "openemr",
  environment: "staging",
  base_url: "https://target.invalid",
  auth_mode: "session",
  credential_configured: true,
  synthetic_data_only: true,
  safety_caps: caps,
  lifecycle: "ready",
  allowed_lifecycle_transitions: ["disabled"],
  surfaces: [{
    surface_id: "week1-chat",
    version: "1.0.1",
    target_version: "1.0.1",
    content_hash: "e".repeat(64),
    kind: "chat",
    protocol: "https",
    method: "POST",
    relative_path: "api/chat",
    trust_boundary: "external-target",
    authentication_required: true,
    risk: "high",
    owasp_mappings: [],
    oracle_refs: [],
    enabled: true,
    created_at: at,
  }],
  campaign_template: template,
  created_at: at,
} as unknown as TargetReadModel;

const operator = {
  user_id: "user_Operator",
  organization_id: "org_Headshot",
  organization_permissions: [
    "org:console:read",
    "org:campaign:launch",
    "org:targets:manage",
  ],
} as unknown as Principal;

// Auto-cleanup is not configured here, so a second render would leave the first panel mounted
// and `getAllByRole` would return the already-clicked button from the previous test.
afterEach(cleanup);

const requestAuthorization = async (): Promise<Record<string, unknown>> => {
  const command = vi.fn().mockResolvedValue({
    acknowledgement_id: "ack-1",
    status: "accepted",
  });
  const client = { read: vi.fn(), command } as unknown as ApiClient;

  render(
    <TargetManagement
      client={client}
      principal={operator}
      selected={target}
      refresh={vi.fn()}
    />,
  );

  const button = screen.getAllByRole("button")
    .find((candidate) => /request/i.test(candidate.textContent ?? ""));
  expect(button, "the panel must offer an authorization-request control").toBeTruthy();
  fireEvent.click(button!);

  expect(command).toHaveBeenCalledTimes(1);
  return command.mock.calls[0][1] as Record<string, unknown>;
};

describe("scan authorization scope", () => {
  it("sends the three exact execution caps alongside the four editable ceilings", async () => {
    const payload = await requestAuthorization();
    const sent = payload.caps as Record<string, number>;

    // The regression: these three were absent, and their absence only surfaced as a 403.
    expect(sent.logical_case_limit).toBe(14);
    expect(sent.physical_request_limit).toBe(17);
    expect(sent.target_retries_per_turn).toBe(0);
  });

  it("derives the exact caps from the template rather than the operator-editable fields", async () => {
    const payload = await requestAuthorization();
    const sent = payload.caps as Record<string, number>;

    // physical_request_limit is Sigma(turns) = 17, NOT the case count and NOT the attempt cap.
    expect(sent.physical_request_limit).toBe(template.physical_request_count);
    expect(sent.physical_request_limit).not.toBe(sent.max_attempts_per_run);
    expect(sent.logical_case_limit).toBe(template.case_count);
  });

  it("keeps the four editable ceiling caps exactly as before", async () => {
    const payload = await requestAuthorization();
    const sent = payload.caps as Record<string, number>;

    expect(sent.budget_usd).toBe(5);
    expect(sent.max_attempts_per_run).toBe(14);
    expect(sent.target_requests_per_second).toBe(0.5);
    expect(sent.run_timeout_seconds).toBe(7200);
  });

  it("sends target_retries_per_turn as 0 and not as an omitted field", async () => {
    // A retried turn replays a live attack against the target. Zero is a value, not an absence,
    // and `0` must survive both the payload build and JSON serialisation.
    const payload = await requestAuthorization();
    const sent = payload.caps as Record<string, number>;

    expect(Object.keys(sent)).toContain("target_retries_per_turn");
    expect(JSON.parse(JSON.stringify(sent)).target_retries_per_turn).toBe(0);
  });
});

describe("campaign template contract", () => {
  it("rejects a template that does not publish its physical request count", () => {
    const { physical_request_count: _omitted, ...legacy } = template;

    expect(() => decodeTargets([{ ...target, campaign_template: legacy }]))
      .toThrow();
    expect(decodeTargets([{ ...target, campaign_template: template }]))
      .toEqual([{ ...target, campaign_template: template }]);
  });

  it("rejects a non-positive physical request count", () => {
    expect(() => decodeTargets([{
      ...target,
      campaign_template: { ...template, physical_request_count: 0 },
    }])).toThrow();
  });
});

describe("403 detail names the refused action", () => {
  it("names the command instead of always reporting a denied launch", () => {
    const denied = new ApiClientError("Access denied", "forbidden", 403);

    expect(failureMessage(denied, "Request campaign authorization"))
      .toContain('"Request campaign authorization"');
    expect(failureMessage(denied, "Request campaign authorization"))
      .not.toContain("denied this launch");
  });

  it("still reports a launch denial when the launch button is the one refused", () => {
    const denied = new ApiClientError("Access denied", "forbidden", 403);

    expect(failureMessage(denied, "Launch campaign")).toContain('"Launch campaign"');
  });

  it("falls back to a neutral subject when no action is supplied", () => {
    const denied = new ApiClientError("Access denied", "forbidden", 403);

    expect(failureMessage(denied)).toContain("this action");
  });

  it("leaves non-403 failures unchanged", () => {
    expect(failureMessage(new ApiClientError("Expired", "unauthenticated", 401)))
      .toBe("Authentication expired. Sign in again before retrying.");
    expect(failureMessage(new Error("network")))
      .toBe("The command was not acknowledged. No state change was assumed.");
  });
});
