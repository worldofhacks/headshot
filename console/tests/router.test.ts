import { describe, expect, it } from "vitest";

import { parseConsoleRoute, routePath } from "../src/router";

describe("canonical console routes", () => {
  it.each([
    ["/live", { screen: "live", entityId: null }],
    ["/coverage", { screen: "coverage", entityId: null }],
    ["/agents", { screen: "agents", entityId: null }],
    ["/tooling", { screen: "tooling", entityId: null }],
    ["/traces", { screen: "traces", entityId: null }],
    ["/costs", { screen: "costs", entityId: null }],
    ["/targets", { screen: "targets", entityId: null }],
    ["/config", { screen: "config", entityId: null }],
  ])("spec(T-F18a:AC-3) preserves the canonical collection route %s", (path, expected) => {
    expect(parseConsoleRoute(path)).toEqual(expected);
  });

  it.each([
    ["/resilience", { screen: "coverage", entityId: null }],
    ["/resilience/", { screen: "coverage", entityId: null }],
  ])("spec(T-F18a:AC-2) resolves the retired compatibility route %s to Coverage", (path, expected) => {
    expect(parseConsoleRoute(path)).toEqual(expected);
  });

  it.each([
    ["/not-a-screen", "unknown screen"],
    ["/findings/%E0%A4%A", "malformed entity escape"],
    ["/live/attempt-id/extra", "extra path segment"],
    ["/resilience/extra", "extra segment on the compatibility route"],
    ["/coverage/case-id", "entity on a collection-only screen"],
    ["/agents/agent-id", "entity on an unsupported screen"],
  ])("spec(T-F18a:AC-3) defaults a %s to canonical Live", (path) => {
    expect(parseConsoleRoute(path)).toEqual({ screen: "live", entityId: null });
  });

  it.each([
    ["live", "attempt / one"],
    ["findings", "finding://external.example/患者?next=/config#evidence"],
    ["approvals", "//external.example/approval α"],
  ] as const)(
    "spec(T-F18a:AC-4) round-trips an encoded %s identity without changing origin",
    (screen, entityId) => {
      const path = routePath({ screen, entityId });
      const url = new URL(path, "https://console.example.test/live");

      expect(url.origin).toBe("https://console.example.test");
      expect(url.pathname.startsWith(`/${screen}/`)).toBe(true);
      expect(parseConsoleRoute(url.pathname)).toEqual({ screen, entityId });
    },
  );

  it.each([".", ".."])(
    "spec(T-F18a:AC-4) rejects the path-traversal entity identity %s",
    (entityId) => {
      expect(() => routePath({ screen: "findings", entityId })).toThrow();
    },
  );

  it.each([
    "/live/%2e%2e",
    "/findings/%2E%2E",
    "/approvals/%2e",
  ])("spec(T-F18a:AC-4) does not accept a percent-encoded dot segment at %s", (path) => {
    expect(parseConsoleRoute(path)).toEqual({ screen: "live", entityId: null });
  });
});
