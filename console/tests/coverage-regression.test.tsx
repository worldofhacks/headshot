import {
  cleanup,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import { CoverageRegressionScreen } from "../src/screens/CoverageRegressionScreen";

afterEach(cleanup);

const at = "2026-07-24T12:00:00Z";

describe("Coverage & Regression", () => {
  it("merges the independently projected coverage and regression ledgers", async () => {
    const read = vi.fn(async (path: string) => {
      if (path === "coverage") {
        return {
          state: "ready" as const,
          data: [{
            target_version: "openemr@2.0.0",
            verified_attempt_count: 8,
            total_case_count: 10,
            category_count: 3,
            execution_profile: "live",
            evidence_provenance: "live_target",
            classifications: ["boundary", "invariant", "regression"],
            owasp_web: ["A01:2021"],
            owasp_llm: ["LLM01:2025", "LLM06:2025"],
            verdict_counts: {
              NO_EXPLOIT_OBSERVED: 7,
              EXPLOIT_CONFIRMED: 1,
            },
            covered: false,
            as_of: at,
          }],
        };
      }
      if (path === "resilience") {
        return {
          state: "ready" as const,
          data: [
            {
              regression_id: "regression-prompt-injection",
              version: "2.0.0",
              status: "NO_EXPLOIT_OBSERVED",
              recorded_at: at,
            },
            {
              regression_id: "regression-data-exfiltration",
              version: "2.0.0",
              status: "EXPLOIT_CONFIRMED",
              recorded_at: "2026-07-24T11:00:00Z",
            },
          ],
        };
      }
      throw new Error(`Unexpected read path: ${path}`);
    });
    const client = {
      read,
      command: vi.fn(),
    } as unknown as ApiClient;

    render(<CoverageRegressionScreen client={client} />);

    expect(await screen.findByRole("heading", {
      name: "Coverage & Regression",
      level: 1,
    })).toBeTruthy();
    expect(await screen.findByLabelText("Coverage summary")).toBeTruthy();
    expect(await screen.findByLabelText("Regression summary")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Taxonomy coverage" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Regression timeline" })).toBeTruthy();
    expect(screen.getAllByText("regression-prompt-injection")).toHaveLength(2);
    expect(screen.queryByRole("heading", { name: "Resilience", level: 1 })).toBeNull();
    await waitFor(() => {
      expect(read).toHaveBeenCalledWith("coverage", expect.any(AbortSignal));
      expect(read).toHaveBeenCalledWith("resilience", expect.any(AbortSignal));
    });
  });

  it("keeps regression evidence visible when coverage is unavailable", async () => {
    const client = {
      read: vi.fn(async (path: string) => path === "coverage"
        ? {
            state: "unavailable" as const,
            data: null,
            reason_code: "coverage_projection_unavailable",
          }
        : {
            state: "ready" as const,
            data: [{
              regression_id: "regression-tool-boundary",
              version: "2.0.0",
              status: "NO_EXPLOIT_OBSERVED",
              recorded_at: at,
            }],
          }),
      command: vi.fn(),
    } as unknown as ApiClient;

    render(<CoverageRegressionScreen client={client} />);

    expect(await screen.findByText("coverage_projection_unavailable")).toBeTruthy();
    expect(await screen.findByLabelText("Regression summary")).toBeTruthy();
    expect(screen.getAllByText("regression-tool-boundary")).toHaveLength(2);
  });
});
