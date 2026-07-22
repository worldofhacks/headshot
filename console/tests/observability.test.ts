import { describe, expect, it } from "vitest";

import { duration, percentile, summarizeTraces } from "../src/screens/ObservabilityScreens";
import type { TraceReadModel } from "../src/types";

const trace = (overrides: Partial<TraceReadModel> = {}): TraceReadModel => ({
  request_id: "request-1",
  trace_id: "trace-1",
  campaign_id: "campaign-1",
  attempt_id: "attempt-1",
  operation: "target.http",
  provider: "openemr",
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
  currency: "USD",
  langfuse_status: "exported",
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
      trace({ request_id: "request-2", trace_id: "trace-2", duration_ms: 300, status: "failed", response_bytes: null, measured_cost: 0.02, langfuse_status: "error" }),
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
