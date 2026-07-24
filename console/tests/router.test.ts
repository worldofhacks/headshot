import { describe, expect, it } from "vitest";

import { parseConsoleRoute, routePath } from "../src/router";

const hostileOpaqueIdentityVectors = [
  {
    screen: "live",
    entityId: "//external.example/records",
    pathname: "/live/%2F%2Fexternal.example%2Frecords",
  },
  {
    screen: "findings",
    entityId: "https://external.example/steal?next=/config",
    pathname:
      "/findings/https%3A%2F%2Fexternal.example%2Fsteal%3Fnext%3D%2Fconfig",
  },
  {
    screen: "approvals",
    entityId: "../config",
    pathname: "/approvals/..%2Fconfig",
  },
] as const;

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
    ["/live/attempt-id/extra", "extra path segment"],
    ["/resilience/extra", "extra segment on the compatibility route"],
    ["/coverage/case-id", "entity on a collection-only screen"],
    ["/agents/agent-id", "entity on an unsupported screen"],
    ["/tooling/tool-id", "entity on Tooling"],
    ["/traces/trace-id", "entity on Traces"],
    ["/costs/cost-id", "entity on Costs"],
    ["/targets/target-id", "entity on Targets"],
    ["/config/config-id", "entity on Configuration"],
  ])("spec(T-F18a:AC-3) defaults a %s to canonical Live", (path) => {
    expect(parseConsoleRoute(path)).toEqual({ screen: "live", entityId: null });
  });

  it.each([
    ["/live/%E0%A4%A", "malformed Live entity"],
    ["/findings/%E0%A4%A", "malformed Findings entity"],
    ["/approvals/%E0%A4%A", "malformed Approval entity"],
  ])("spec(T-F18a:AC-3) rejects a %s", (path) => {
    expect(parseConsoleRoute(path)).toEqual({ screen: "live", entityId: null });
  });

  it.each([
    ["/live/attempt%20one%2F%E6%82%A3%E8%80%85", { screen: "live", entityId: "attempt one/患者" }],
    ["/findings/finding%3F%23one%2F%CE%B1", { screen: "findings", entityId: "finding?#one/α" }],
    ["/approvals/approval%3A%252F%2F%CE%B2", { screen: "approvals", entityId: "approval:%2F/β" }],
  ])("spec(T-F18a:AC-4) preserves the fixed encoded bookmark %s", (pathname, expected) => {
    expect(parseConsoleRoute(pathname)).toEqual(expected);
  });

  it.each([
    [
      { screen: "live", entityId: "attempt one/患者" } as const,
      "/live/attempt%20one%2F%E6%82%A3%E8%80%85",
    ],
    [
      { screen: "findings", entityId: "finding?#one/α" } as const,
      "/findings/finding%3F%23one%2F%CE%B1",
    ],
    [
      { screen: "approvals", entityId: "approval:%2F/β" } as const,
      "/approvals/approval%3A%252F%2F%CE%B2",
    ],
  ])("spec(T-F18a:AC-4) emits the exact encoded route %s", (route, pathname) => {
    expect(routePath(route)).toBe(pathname);
    const url = new URL(pathname, "https://console.example.test/live");
    expect(url.origin).toBe("https://console.example.test");
  });

  it.each(hostileOpaqueIdentityVectors)(
    "spec(T-F18a:AC-4) parses hostile-prefix bookmark $pathname as an opaque identity",
    ({ screen, entityId, pathname }) => {
      expect(parseConsoleRoute(pathname)).toEqual({ screen, entityId });
    },
  );

  it.each(hostileOpaqueIdentityVectors)(
    "spec(T-F18a:AC-4) contains hostile-prefix $entityId beneath its canonical screen path",
    ({ screen, entityId, pathname }) => {
      const emittedPath = routePath({ screen, entityId });
      const resolved = new URL(emittedPath, "https://console.example.test/live");

      expect(emittedPath).toBe(pathname);
      expect(resolved.origin).toBe("https://console.example.test");
      expect(resolved.pathname).toBe(pathname);
      expect(resolved.pathname.startsWith(`/${screen}/`)).toBe(true);
    },
  );

  it("spec(T-F18a:AC-2) keeps Resilience inbound-only", () => {
    expect(() =>
      routePath({
        screen: "resilience",
        entityId: null,
      } as unknown as Parameters<typeof routePath>[0]),
    ).toThrow();
  });

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
