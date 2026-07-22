import { describe, expect, it } from "vitest";

import { parseConsoleRoute, routePath } from "../src/router";

describe("frozen direct routes", () => {
  it.each([
    ["/live", { screen: "live", entityId: null }],
    ["/live/attempt-id", { screen: "live", entityId: "attempt-id" }],
    ["/findings/finding-id", { screen: "findings", entityId: "finding-id" }],
    ["/approvals/approval-id", { screen: "approvals", entityId: "approval-id" }],
    ["/coverage", { screen: "coverage", entityId: null }],
    ["/resilience", { screen: "resilience", entityId: null }],
    ["/traces", { screen: "traces", entityId: null }],
    ["/costs", { screen: "costs", entityId: null }],
    ["/targets", { screen: "targets", entityId: null }],
    ["/config", { screen: "config", entityId: null }],
  ])("parses %s", (path, expected) => {
    expect(parseConsoleRoute(path)).toEqual(expected);
  });

  it("encodes entity identifiers and defaults unknown routes to Live", () => {
    expect(routePath({ screen: "findings", entityId: "finding / one" })).toBe(
      "/findings/finding%20%2F%20one",
    );
    expect(parseConsoleRoute("/not-a-screen")).toEqual({ screen: "live", entityId: null });
  });
});
