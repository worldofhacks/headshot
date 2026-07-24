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
  const heading = (title: string) => element("h1", null, title);
  return {
    ApprovalsScreen: () => heading("Approvals"),
    ConfigurationScreen: () => heading("Configuration"),
    FindingsScreen: () => heading("Findings"),
    LiveScreen: () => heading("Live operations"),
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

beforeEach(() => {
  window.history.replaceState(null, "", "/live");
});

afterEach(() => {
  cleanup();
});

describe("canonical console navigation contract", () => {
  it("spec(T-F18a:AC-1) exposes the canonical desktop labels once and in order", () => {
    render(createElement(App));
    const desktop = screen.getAllByRole("navigation")[0];
    const labels = within(desktop)
      .getAllByRole("button")
      .map((button) => button.textContent?.trim());

    expect(labels).toEqual(canonicalDesktopLabels);
    expect(
      within(desktop).getAllByRole("button", {
        name: "Coverage & Regression",
        exact: true,
      }),
    ).toHaveLength(1);
    expect(within(desktop).queryByRole("button", { name: "Resilience" })).toBeNull();
  });

  it("spec(T-F18a:AC-1) gives the desktop route list an accessible navigation name", () => {
    render(createElement(App));

    expect(
      screen.getByRole("navigation", { name: "Primary navigation" }),
    ).not.toBeNull();
  });

  it("spec(T-F18a:AC-1) targets /coverage from the canonical desktop item", () => {
    render(createElement(App));
    const desktop = screen.getAllByRole("navigation")[0];
    const coverage = within(desktop).getByRole("button", {
      name: "Coverage & Regression",
      exact: true,
    });

    fireEvent.click(coverage);

    expect(window.location.pathname).toBe("/coverage");
    expect(coverage.getAttribute("aria-current")).toBe("page");
  });

  it("spec(T-F18a:AC-1) exposes the same retired-page contract in mobile More", () => {
    render(createElement(App));
    const mobile = screen.getByRole("navigation", { name: "Mobile navigation" });

    fireEvent.click(within(mobile).getByRole("button", { name: "More", exact: true }));

    expect(
      within(mobile)
        .getAllByRole("button")
        .map((button) => button.textContent?.trim()),
    ).toEqual([
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
      within(mobile).getAllByRole("button", {
        name: "Coverage & Regression",
        exact: true,
      }),
    ).toHaveLength(1);
    expect(within(mobile).queryByRole("button", { name: "Resilience" })).toBeNull();
  });

  it("spec(T-F18a:AC-1) marks the selected mobile route for assistive technology", () => {
    render(createElement(App));
    const mobile = screen.getByRole("navigation", { name: "Mobile navigation" });
    fireEvent.click(within(mobile).getByRole("button", { name: "More", exact: true }));
    const coverage = within(mobile).getByRole("button", {
      name: "Coverage & Regression",
      exact: true,
    });

    fireEvent.click(coverage);

    expect(window.location.pathname).toBe("/coverage");
    expect(coverage.getAttribute("aria-current")).toBe("page");
  });
});

describe("replace-normalized browser route contract", () => {
  it("spec(T-F18a:AC-2) replaces a resilience query/hash with canonical Coverage once", () => {
    window.history.replaceState(null, "", "/live");
    window.history.pushState(null, "", "/resilience?window=30d#latest-regression");
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
    ["/findings/%E0%A4%A?next=/findings#fragment", "malformed escape"],
    ["/live/attempt-1/extra?next=/findings#fragment", "extra segment"],
    ["/resilience/extra?next=/findings#fragment", "compatibility-route prefix"],
    ["/coverage/case-1?next=/findings#fragment", "unsupported entity"],
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
