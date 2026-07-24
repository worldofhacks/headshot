import { describe, expect, it } from "vitest";

import { duration, percentile, summarizeTraces } from "../src/screens/ObservabilityScreens";
import type { TraceReadModel } from "../src/types";

const trace = (overrides: Partial<TraceReadModel> = {}): TraceReadModel => ({
  request_id: "request-1",
  execution_id: null,
  parent_execution_id: null,
  trace_id: "trace-1",
  campaign_id: "campaign-1",
  attempt_id: "attempt-1",
  operation: "target.http",
  provider: "openemr",
  agent_role: null,
  execution_mode: null,
  returned_model: null,
  upstream_provider: null,
  provider_request_id: null,
  configuration_set_sha256: null,
  role_configuration_sha256: null,
  generation_policy_sha256: null,
  physical_attempts: null,
  method: "POST",
  destination_host: "target.invalid",
  relative_path: "chat",
  status: "succeeded",
  status_code: 200,
  error_code: null,
  started_at: "2026-07-22T00:00:00Z",
  finished_at: "2026-07-22T00:00:00.100Z",
  duration_ms: 100,
  request_bytes: 100,
  response_bytes: 200,
  measured_cost: 0.01,
  accounting_status: "measured",
  currency: "USD",
  input_tokens: null,
  output_tokens: null,
  reasoning_tokens: null,
  judge_calibration_id: null,
  judge_calibration_state: null,
  oracle_agreement: null,
  decision_authority: null,
  p50_duration_ms: null,
  p95_duration_ms: null,
  langfuse_status: "exported",
  langfuse_verified_at: "2026-07-22T00:00:01Z",
  request_preview: '{"turns":["synthetic"]}',
  response_preview: '{"answer":"safe"}',
  request_sha256: "a".repeat(64),
  response_sha256: "b".repeat(64),
  inspection_flags: [],
  inspection_owasp_mappings: [],
  ...overrides,
});

describe("observability metrics", () => {
  it("uses nearest-rank percentiles and readable durations", () => {
    expect(percentile([10, 20, 30, 40], 0.95)).toBe(40);
    expect(percentile([], 0.95)).toBe(0);
    expect(duration(950)).toBe("950 ms");
    expect(duration(2_500)).toBe("2.50 s");
  });

  it("summarizes physical request rows without double-counting campaign traces", () => {
    const summary = summarizeTraces([
      trace(),
      trace({ request_id: "request-2", trace_id: "trace-2", duration_ms: 300, status: "failed", response_bytes: null, measured_cost: 0.02, langfuse_status: "queued", langfuse_verified_at: null }),
      trace({ request_id: null, trace_id: "campaign-trace", operation: "campaign.run", duration_ms: 9_999, measured_cost: 9 }),
    ]);

    expect(summary).toEqual({
      requestCount: 2,
      averageLatencyMs: 200,
      p95LatencyMs: 300,
      totalCost: 0.03,
      totalBytes: 400,
      successRate: 0.5,
      langfuseCoverage: 0.5,
    });
  });
});
