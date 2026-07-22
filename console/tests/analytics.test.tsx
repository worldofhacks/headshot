import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  DistributionBars,
  EvidenceGrid,
  MetricStrip,
  money,
  percent,
  shortId,
  TagMatrix,
} from "../src/components/Analytics";

describe("shared analytical presentation", () => {
  it("formats only supplied authoritative values", () => {
    expect(money(0.225)).toBe("$0.2250");
    expect(percent(8 / 9)).toBe("89%");
    expect(shortId("browser-campaign-alpha")).toBe("browser-…lpha");
    expect(shortId(null)).toBe("—");
  });

  it("renders summaries, distributions, evidence and mapped tags accessibly", () => {
    render(
      <>
        <MetricStrip label="Authoritative summary" values={[
          { label: "Attempts", value: "9", note: "live target" },
          { label: "Coverage", value: "100%", note: "verified" },
        ]} />
        <DistributionBars rows={[
          { label: "Passed", value: 8, tone: "success" },
          { label: "Failed", value: 1, tone: "failure" },
        ]} />
        <EvidenceGrid values={[{ label: "Evidence bound", value: "9/9", tone: "success" }]} />
        <TagMatrix groups={[{ label: "OWASP LLM", values: ["LLM01:2025"] }]} />
      </>,
    );

    expect(screen.getByRole("region", { name: "Authoritative summary" })).toBeTruthy();
    expect(screen.getByText("live target")).toBeTruthy();
    expect(screen.getByText("Passed")).toBeTruthy();
    expect(screen.getByText("Evidence bound")).toBeTruthy();
    expect(screen.getByText("LLM01:2025")).toBeTruthy();
  });
});
