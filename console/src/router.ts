export type ScreenName =
  | "live"
  | "findings"
  | "approvals"
  | "coverage"
  | "resilience"
  | "traces"
  | "costs"
  | "targets"
  | "config";

export interface ConsoleRoute {
  screen: ScreenName;
  entityId: string | null;
}

const screens = new Set<ScreenName>([
  "live",
  "findings",
  "approvals",
  "coverage",
  "resilience",
  "traces",
  "costs",
  "targets",
  "config",
]);

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
    return { screen: "live", entityId: null };
  }
  const screen = screenPart as ScreenName;
  const supportsEntity = screen === "live" || screen === "findings" || screen === "approvals";
  if (entityPart && !supportsEntity) return { screen: "live", entityId: null };
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
