import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { RunFailurePanel } from "../src/components/RunFailurePanel";

describe("run failure panel", () => {
  it("leads with the typed cause and retry authority", () => {
    render(
      <RunFailurePanel
        failure={{
          stage: "judge",
          error_code: "invalid_structured_output",
          attempt_id: "attempt-12-long-identity",
          execution_id: "execution-12-long-identity",
          agent_role: "judge",
          provider: "google",
          model: "gemini-2.5-pro",
          retryable: true,
          retries_remaining: 1,
          occurred_at: "2026-07-26T22:00:00Z",
          operator_summary: "Judge returned schema-invalid structured output.",
        }}
      />,
    );

    expect(screen.getByRole("alert", { name: "Run failure" })).not.toBeNull();
    expect(screen.getByText("Judge returned schema-invalid structured output.")).not.toBeNull();
    expect(screen.getByText("invalid_structured_output")).not.toBeNull();
    expect(screen.getByText("Retryable · 1 remaining")).not.toBeNull();
    expect(screen.getByText("judge · google · gemini-2.5-pro")).not.toBeNull();
  });
});
