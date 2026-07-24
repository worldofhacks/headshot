import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { createElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "../src/App";
import { decodeResourceEnvelope } from "../src/api/contracts";

vi.mock("@clerk/react", () => ({
  SignIn: () => null,
  TaskChooseOrganization: () => null,
  TaskResetPassword: () => null,
  TaskSetupMFA: () => null,
  UserButton: () => null,
  useAuth: () => ({
    actor: null,
    getToken: async () => "test-session-token",
    isLoaded: true,
    isSignedIn: true,
    orgId: "org-headshot",
  }),
  useClerk: () => ({ status: "loaded" }),
}));

vi.mock("../src/api/client", () => ({
  createApiClient: () => ({ read: vi.fn() }),
}));

vi.mock("../src/hooks/useResource", () => ({
  useResource: (_client: unknown, path: string) => {
    if (path === "principal") {
      return {
        result: {
          state: "ready",
          data: {
            user_id: "operator-1",
            session_id: "session-1",
            organization_id: "org-headshot",
            organization_role: "org:operator",
            organization_permissions: ["org:console:read"],
          },
        },
        refresh: () => undefined,
      };
    }
    if (path === "campaigns" || path === "approvals") {
      return { result: { state: "ready", data: [] }, refresh: () => undefined };
    }
    return { result: { state: "unavailable", data: null }, refresh: () => undefined };
  },
}));

vi.mock("../src/screens/ConsoleScreens", async () => {
  const { createElement: element } = await import("react");
  const heading = (title: string, entityId: string | null = null) =>
    element("h1", { "data-entity-id": entityId }, title);
  return {
    ApprovalsScreen: ({ entityId }: { entityId: string | null }) =>
      heading("Approvals", entityId),
    ConfigurationScreen: () => heading("Configuration"),
    FindingsScreen: ({ entityId }: { entityId: string | null }) =>
      heading("Findings", entityId),
    LiveScreen: ({ entityId }: { entityId: string | null }) =>
      heading("Live operations", entityId),
    SimpleResourceScreen: ({ resource }: { resource: string }) =>
      heading(resource === "coverage" ? "Coverage" : resource),
    TargetsScreen: () => heading("Targets"),
  };
});

vi.mock("../src/screens/AgentToolScreens", async () => {
  const { createElement: element } = await import("react");
  return {
    AgentsScreen: () => element("h1", null, "Agents"),
    ToolingScreen: () => element("h1", null, "Tooling"),
  };
});

describe("resource envelopes", () => {
  it.each(["ready", "empty", "unavailable", "stale", "degraded", "error"])(
    "accepts the backend %s state",
    (state) => {
      expect(decodeResourceEnvelope({ state, data: null }).state).toBe(state);
    },
  );

  it("rejects unknown states instead of treating them as ready", () => {
    expect(() => decodeResourceEnvelope({ state: "nominal", data: {} })).toThrow(
      "Invalid resource envelope",
    );
  });
});

const canonicalDesktopLabels = [
  "Live",
  "Findings",
  "Approvals",
  "Coverage & Regression",
  "Agents",
  "Tooling",
  "Traces",
  "Costs",
  "Targets",
  "Configuration",
];

function labelsAppearInOrder(container: HTMLElement, labels: string[]): void {
  const text = container.textContent ?? "";
  let priorIndex = -1;
  for (const label of labels) {
    const index = text.indexOf(label);
    expect(index).toBeGreaterThan(priorIndex);
    priorIndex = index;
  }
}

beforeEach(() => {
  window.history.replaceState(null, "", "/live");
});

afterEach(() => {
  cleanup();
});

describe("canonical console navigation contract", () => {
  it("spec(T-F18a:AC-1) exposes the canonical desktop labels once and in order", () => {
    render(createElement(App));
    const desktop = document.querySelector<HTMLElement>(".sidebar nav");

    expect(desktop).not.toBeNull();
    labelsAppearInOrder(desktop!, canonicalDesktopLabels);
    expect(
      within(desktop!).getAllByText("Coverage & Regression", {
        exact: true,
      }),
    ).toHaveLength(1);
    expect(within(desktop!).queryByText("Resilience", { exact: true })).toBeNull();
  });

  it("spec(T-F18a:AC-1) targets /coverage from the canonical desktop item", () => {
    render(createElement(App));
    const desktop = document.querySelector<HTMLElement>(".sidebar nav");
    expect(desktop).not.toBeNull();
    const coverage = within(desktop!).getByText("Coverage & Regression", {
      exact: true,
    });

    fireEvent.click(coverage);

    expect(window.location.pathname).toBe("/coverage");
  });

  it("spec(T-F18a:AC-1) exposes the same retired-page contract in mobile More", () => {
    render(createElement(App));
    const mobile = document.querySelector<HTMLElement>(".mobile-nav");
    expect(mobile).not.toBeNull();

    fireEvent.click(within(mobile!).getByText("More", { exact: true }));

    labelsAppearInOrder(mobile!, [
      "Live",
      "Findings",
      "Approvals",
      "Targets",
      "More",
      "Coverage & Regression",
      "Agents",
      "Tooling",
      "Traces",
      "Costs",
      "Configuration",
    ]);
    expect(
      within(mobile!).getAllByText("Coverage & Regression", {
        exact: true,
      }),
    ).toHaveLength(1);
    expect(within(mobile!).queryByText("Resilience", { exact: true })).toBeNull();
    const coverage = within(mobile!).getByText("Coverage & Regression", { exact: true });

    fireEvent.click(coverage);

    expect(window.location.pathname).toBe("/coverage");
  });
});

describe("replace-normalized browser route contract", () => {
  it.each([
    ["/resilience", "bare"],
    ["/resilience?return=%2Ffindings", "query-only"],
    ["/resilience#latest%20regression", "hash-only"],
    ["/resilience?window=90d#version%20two", "combined query/hash"],
  ])("spec(T-F18a:AC-2) replaces the %s compatibility URL once", (path) => {
    window.history.replaceState(null, "", "/live");
    window.history.pushState(null, "", path);
    const historyLength = window.history.length;
    const replace = vi.spyOn(window.history, "replaceState");
    const push = vi.spyOn(window.history, "pushState");

    render(createElement(App));

    expect(replace.mock.calls.map((call) => call[2])).toEqual(["/coverage"]);
    expect(push).not.toHaveBeenCalled();
    expect(window.location.pathname).toBe("/coverage");
    expect(window.location.search).toBe("");
    expect(window.location.hash).toBe("");
    expect(window.history.length).toBe(historyLength);
    expect(screen.getByRole("heading", { name: "Coverage", exact: true })).not.toBeNull();

    act(() => window.dispatchEvent(new PopStateEvent("popstate")));
    expect(replace.mock.calls.map((call) => call[2])).toEqual(["/coverage"]);
  });

  it.each([
    ["/unknown?next=/findings#fragment", "unknown screen"],
    ["/live/%E0%A4%A?next=/findings#fragment", "malformed Live entity"],
    ["/findings/%E0%A4%A?next=/findings#fragment", "malformed escape"],
    ["/approvals/%E0%A4%A?next=/findings#fragment", "malformed Approval entity"],
    ["/live/attempt-1/extra?next=/findings#fragment", "extra segment"],
    ["/resilience/extra?next=/findings#fragment", "compatibility-route prefix"],
    ["/coverage/case-1?next=/findings#fragment", "unsupported entity"],
    ["/agents/agent-1?next=/findings#fragment", "Agents entity"],
    ["/tooling/tool-1?next=/findings#fragment", "Tooling entity"],
    ["/traces/trace-1?next=/findings#fragment", "Traces entity"],
    ["/costs/cost-1?next=/findings#fragment", "Costs entity"],
    ["/targets/target-1?next=/findings#fragment", "Targets entity"],
    ["/config/config-1?next=/findings#fragment", "Configuration entity"],
  ])("spec(T-F18a:AC-3) replaces a %s URL with canonical Live", (path) => {
    window.history.replaceState(null, "", path);
    const historyLength = window.history.length;
    const replace = vi.spyOn(window.history, "replaceState");
    const push = vi.spyOn(window.history, "pushState");

    render(createElement(App));

    expect(replace.mock.calls.map((call) => call[2])).toEqual(["/live"]);
    expect(push).not.toHaveBeenCalled();
    expect(`${window.location.pathname}${window.location.search}${window.location.hash}`).toBe(
      "/live",
    );
    expect(window.history.length).toBe(historyLength);
    expect(
      screen.getByRole("heading", { name: "Live operations", exact: true }),
    ).not.toBeNull();
  });
});

describe("encoded entity production path", () => {
  it.each([
    ["/live/attempt%20one%2F%E6%82%A3%E8%80%85", "Live operations", "attempt one/患者"],
    ["/findings/finding%3F%23one%2F%CE%B1", "Findings", "finding?#one/α"],
    ["/approvals/approval%3A%252F%2F%CE%B2", "Approvals", "approval:%2F/β"],
  ])(
    "spec(T-F18a:AC-4) routes fixed bookmark %s without rewriting its identity",
    (pathname, heading, entityId) => {
      window.history.replaceState(null, "", pathname);
      const replace = vi.spyOn(window.history, "replaceState");

      render(createElement(App));

      expect(replace).not.toHaveBeenCalled();
      expect(window.location.pathname).toBe(pathname);
      expect(
        screen.getByRole("heading", { name: heading, exact: true }).getAttribute(
          "data-entity-id",
        ),
      ).toBe(entityId);
    },
  );
});
