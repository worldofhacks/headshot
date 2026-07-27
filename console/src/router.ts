export type ScreenName =
  | "runs"
  | "live"
  | "findings"
  | "approvals"
  | "reports"
  | "coverage"
  | "resilience"
  | "observability"
  | "agents"
  | "tooling"
  | "traces"
  | "costs"
  | "targets"
  | "system"
  | "config";

export type PrimaryScreen =
  | "runs"
  | "findings"
  | "coverage"
  | "approvals"
  | "observability"
  | "system";

export type WorkspaceRoute =
  | { screen: "runs"; view: "operations" | "targets" }
  | { screen: "findings"; view: "findings" | "reports" }
  | { screen: "coverage"; view: "coverage" }
  | { screen: "approvals"; view: "approvals" }
  | { screen: "observability"; view: "traces" | "costs" }
  | { screen: "system"; view: "agents" | "tools" | "configuration" };

export const PRIMARY_NAVIGATION_SCREENS: readonly PrimaryScreen[] = [
  "runs",
  "findings",
  "coverage",
  "approvals",
  "observability",
  "system",
] as const;

export interface ConsoleRoute {
  screen: ScreenName;
  entityId: string | null;
}

export function isCampaignScopedScreen(screen: ScreenName): boolean {
  return screen === "runs"
    || screen === "targets"
    || screen === "observability"
    || screen === "traces"
    || screen === "costs";
}

const screens = new Set<ScreenName>([
  "runs",
  "live",
  "findings",
  "approvals",
  "reports",
  "coverage",
  "resilience",
  "observability",
  "agents",
  "tooling",
  "traces",
  "costs",
  "targets",
  "system",
  "config",
]);

export function workspaceRoute(screen: ScreenName): WorkspaceRoute {
  switch (screen) {
    case "runs":
    case "live":
      return { screen: "runs", view: "operations" };
    case "targets":
      return { screen: "runs", view: "targets" };
    case "findings":
      return { screen: "findings", view: "findings" };
    case "reports":
      return { screen: "findings", view: "reports" };
    case "coverage":
    case "resilience":
      return { screen: "coverage", view: "coverage" };
    case "approvals":
      return { screen: "approvals", view: "approvals" };
    case "observability":
    case "traces":
      return { screen: "observability", view: "traces" };
    case "costs":
      return { screen: "observability", view: "costs" };
    case "system":
    case "agents":
      return { screen: "system", view: "agents" };
    case "tooling":
      return { screen: "system", view: "tools" };
    case "config":
      return { screen: "system", view: "configuration" };
  }
}

function safeDecode(value: string | undefined): string | null {
  if (!value) return null;
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

export function parseConsoleRoute(pathname: string): ConsoleRoute {
  const [screenPart, entityPart, extra] = pathname.replace(/^\/+|\/+$/g, "").split("/");
  if (!screens.has(screenPart as ScreenName) || extra !== undefined) {
    return { screen: "runs", entityId: null };
  }
  const screen = screenPart as ScreenName;
  const supportsEntity = screen === "runs"
    || screen === "live"
    || screen === "findings"
    || screen === "approvals"
    || screen === "reports"
    || isCampaignScopedScreen(screen);
  if (entityPart && !supportsEntity) return { screen: "runs", entityId: null };
  return { screen, entityId: supportsEntity ? safeDecode(entityPart) : null };
}

export function routePath(route: ConsoleRoute): string {
  const base = `/${route.screen}`;
  return route.entityId === null ? base : `${base}/${encodeURIComponent(route.entityId)}`;
}

export function navigateTo(route: ConsoleRoute, replace = false): void {
  const path = routePath(route);
  if (replace) window.history.replaceState(null, "", path);
  else window.history.pushState(null, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}
