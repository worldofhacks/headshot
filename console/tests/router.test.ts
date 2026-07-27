import { describe, expect, it } from "vitest";

import {
  parseConsoleRoute,
  PRIMARY_NAVIGATION_SCREENS,
  routePath,
  workspaceRoute,
} from "../src/router";

describe("frozen direct routes", () => {
  it.each([
    ["/runs", { screen: "runs", entityId: null }],
    ["/runs/campaign-id", { screen: "runs", entityId: "campaign-id" }],
    ["/live", { screen: "live", entityId: null }],
    ["/live/attempt-id", { screen: "live", entityId: "attempt-id" }],
    ["/findings/finding-id", { screen: "findings", entityId: "finding-id" }],
    ["/approvals/approval-id", { screen: "approvals", entityId: "approval-id" }],
    ["/reports/report-id", { screen: "reports", entityId: "report-id" }],
    ["/coverage", { screen: "coverage", entityId: null }],
    ["/resilience", { screen: "resilience", entityId: null }],
    ["/observability", { screen: "observability", entityId: null }],
    ["/observability/campaign-id", { screen: "observability", entityId: "campaign-id" }],
    ["/traces", { screen: "traces", entityId: null }],
    ["/traces/campaign-id", { screen: "traces", entityId: "campaign-id" }],
    ["/costs", { screen: "costs", entityId: null }],
    ["/costs/campaign-id", { screen: "costs", entityId: "campaign-id" }],
    ["/targets", { screen: "targets", entityId: null }],
    ["/targets/campaign-id", { screen: "targets", entityId: "campaign-id" }],
    ["/config", { screen: "config", entityId: null }],
    ["/system", { screen: "system", entityId: null }],
  ])("parses %s", (path, expected) => {
    expect(parseConsoleRoute(path)).toEqual(expected);
  });

  it("encodes entity identifiers and defaults unknown routes to Runs", () => {
    expect(routePath({ screen: "findings", entityId: "finding / one" })).toBe(
      "/findings/finding%20%2F%20one",
    );
    expect(parseConsoleRoute("/costs/campaign%20%2F%20one")).toEqual({
      screen: "costs",
      entityId: "campaign / one",
    });
    expect(parseConsoleRoute("/not-a-screen")).toEqual({ screen: "runs", entityId: null });
    expect(parseConsoleRoute("/coverage/regression-id")).toEqual({
      screen: "runs",
      entityId: null,
    });
  });

  it("consolidates aliases into exactly six primary workspaces", () => {
    expect(PRIMARY_NAVIGATION_SCREENS).toEqual([
      "runs",
      "findings",
      "coverage",
      "approvals",
      "observability",
      "system",
    ]);
    expect(workspaceRoute("live")).toEqual({ screen: "runs", view: "operations" });
    expect(workspaceRoute("targets")).toEqual({ screen: "runs", view: "targets" });
    expect(workspaceRoute("reports")).toEqual({ screen: "findings", view: "reports" });
    expect(workspaceRoute("resilience")).toEqual({ screen: "coverage", view: "coverage" });
    expect(workspaceRoute("costs")).toEqual({ screen: "observability", view: "costs" });
    expect(workspaceRoute("tooling")).toEqual({ screen: "system", view: "tools" });
    expect(workspaceRoute("config")).toEqual({ screen: "system", view: "configuration" });
  });
});
