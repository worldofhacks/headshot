import { renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { createApiClient } from "../src/api/client";
import {
  decodeApprovals,
  decodeAttempts,
  decodeAuditHistory,
  decodeCampaigns,
  decodeComponents,
  decodeConfiguration,
  decodeCosts,
  decodeCoverage,
  decodeEvidence,
  decodeFinding,
  decodeFindings,
  decodePrincipal,
  decodeResilience,
  decodeTargets,
  decodeTraces,
} from "../src/api/read-models";
import { useResource } from "../src/hooks/useResource";

const at = "2026-07-21T00:00:00Z";
const caps = {
  budget_usd: 1,
  max_attempts_per_run: 2,
  target_requests_per_second: 0.5,
  run_timeout_seconds: 60,
};
const scope = {
  target_id: "target-1",
  target_version: "1.0.0",
  surface_id: "surface-1",
  surface_version: "1.0.0",
  adapter_kind: "openemr",
  environment: "staging",
  exact_host: "target.invalid",
  auth_mode: "bearer",
  explicit_no_auth: false,
  auth_posture: "bearer",
  protocol: "https",
  method: "POST",
  relative_path: "api",
  endpoint: "https://target.invalid/api",
  corpus_hash: "corpus-1",
  caps,
  run_nonce: "nonce-1",
};
const finding = {
  finding_id: "finding-1",
  state: "confirmed",
  severity: "high",
  category: "prompt_injection",
  target_version: "1.0.0",
  publication_status: "pending",
  evidence_integrity: "verified",
  history: [{ decision: "confirmed", actor_user_id: "user-1", rationale: "evidence", created_at: at }],
};

const validResources: Array<[string, (value: unknown) => unknown, unknown]> = [
  [
    "principal",
    decodePrincipal,
    { user_id: "user-1", session_id: "session-1", organization_id: "org-1", organization_role: "org:operator", organization_permissions: ["org:console:read"] },
  ],
  [
    "campaigns",
    decodeCampaigns,
    [{ ...scope, run_id: "run-1", authorization_request_id: "request-1", state: "queued", scope_hash: "scope-1", launcher_user_id: "user-1", attempt_count: 0, created_at: at }],
  ],
  [
    "attempts",
    decodeAttempts,
    [{ attempt_id: "attempt-1", ordinal: 0, case_id: "case-1", content_hash: null, executed_at: null, trace_id: null, verdict: null, confidence: null, created_at: at }],
  ],
  [
    "evidence",
    decodeEvidence,
    { attempt_id: "attempt-1", campaign_run_id: "run-1", target_id: "target-1", target_version: "1.0.0", surface_id: "surface-1", surface_version: "1.0.0", attack_attempt: {}, request_transcript: {}, response_transcript: "response", policy_decision_id: "policy-1", executed_at: at, trace_id: null, content_hash: "content-1", verdict: null, confidence: null },
  ],
  [
    "findings",
    decodeFindings,
    [finding],
  ],
  [
    "finding detail and history",
    decodeFinding,
    finding,
  ],
  [
    "approvals",
    decodeApprovals,
    [{ ...scope, request_id: "request-1", status: "pending", decision: null, scope_hash: "scope-1", launcher_user_id: "user-1", approver_user_id: null, decided_at: null, created_at: at, expires_at: "2026-07-21T00:15:00Z" }],
  ],
  [
    "coverage",
    decodeCoverage,
    [{ target_version: "1.0.0", verified_attempt_count: 1, covered: true, as_of: at }],
  ],
  [
    "resilience",
    decodeResilience,
    [{ regression_id: "regression-1", version: "1.0.0", status: "passed", recorded_at: at }],
  ],
  [
    "traces",
    decodeTraces,
    [{ trace_id: "trace-1", operation: "runner.attempt", status: "ok", started_at: at, duration_ms: 12.5 }],
  ],
  [
    "costs",
    decodeCosts,
    [{ accounting_id: "accounting-1", campaign_id: "run-1", provider: "provider", measured_cost: 0.25, currency: "USD", recorded_at: at }],
  ],
  [
    "targets and surfaces",
    decodeTargets,
    [{ target_id: "target-1", name: "Registered target", version: "1.0.0", content_hash: "target-hash", lifecycle: "ready", environment: "staging", adapter_kind: "openemr", base_url: "https://target.invalid", auth_mode: "bearer", credential_configured: true, synthetic_data_only: true, safety_caps: caps, allowed_lifecycle_transitions: ["disabled"], created_at: at, surfaces: [{ surface_id: "surface-1", version: "1.0.0", target_version: "1.0.0", content_hash: "surface-hash", kind: "chat", protocol: "https", method: "POST", relative_path: "api", trust_boundary: "external-target", authentication_required: true, risk: "high", owasp_mappings: [], oracle_refs: [], enabled: true, created_at: at }] }],
  ],
  [
    "configuration",
    decodeConfiguration,
    { snapshot_id: "snapshot-1", version: 1, status: "published", configuration: {}, published_at: at, published_by: "user-1" },
  ],
  [
    "components",
    decodeComponents,
    [{ component_id: "runner-1", name: "runner", kind: "runner", availability: "ready", heartbeat_at: at }],
  ],
  [
    "audit history",
    decodeAuditHistory,
    [{ cursor: 1, event_type: "target.created", aggregate_type: "target", aggregate_id: "target-1", actor_user_id: "user-1", payload: {}, created_at: at }],
  ],
];

describe("v1 read-model decoders", () => {
  it.each(validResources)("accepts the explicit %s contract", (_name, decode, value) => {
    expect(decode(value)).toEqual(value);
  });

  it.each(validResources)("rejects malformed ready %s data", (_name, decode, value) => {
    const malformed = Array.isArray(value) ? [{ unexpected: true }] : { unexpected: true };
    expect(() => decode(malformed)).toThrow("Invalid");
  });

  it("fails a malformed ready envelope closed without exposing its payload", async () => {
    const client = createApiClient({
      origin: "https://headshot.test",
      getToken: async () => "fixture-session",
      fetchImpl: vi.fn<typeof fetch>().mockResolvedValue(
        new Response(JSON.stringify({ state: "ready", data: [{ run_id: 42 }] })),
      ),
    });

    const { result } = renderHook(() =>
      useResource(client, "campaigns", decodeCampaigns),
    );

    await waitFor(() => expect(result.current.result.state).toBe("error"));
    expect(result.current.result).toEqual({
      state: "error",
      data: null,
      reason_code: "invalid_response_contract",
    });
  });

  it("preserves an unavailable envelope without invoking its data decoder", async () => {
    const decode = vi.fn(decodeCampaigns);
    const client = createApiClient({
      origin: "https://headshot.test",
      getToken: async () => "fixture-session",
      fetchImpl: vi.fn<typeof fetch>().mockResolvedValue(
        new Response(JSON.stringify({ state: "unavailable", data: null, reason_code: "repository_missing" })),
      ),
    });

    const { result } = renderHook(() => useResource(client, "campaigns", decode));

    await waitFor(() => expect(result.current.result.state).toBe("unavailable"));
    expect(result.current.result.reason_code).toBe("repository_missing");
    expect(decode).not.toHaveBeenCalled();
  });
});
