import {
  SignIn,
  TaskChooseOrganization,
  TaskResetPassword,
  TaskSetupMFA,
  UserButton,
  useAuth,
  useClerk,
} from "@clerk/react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { createApiClient } from "./api/client";
import type { Principal } from "./api/contracts";
import { RESOURCE_PATHS } from "./api/paths";
import { decodePrincipal } from "./api/read-models";
import { useResource } from "./hooks/useResource";
import { parseConsoleRoute, routePath, type ConsoleRoute, type ScreenName } from "./router";
import {
  ApprovalsScreen,
  ConfigurationScreen,
  FindingsScreen,
  LiveScreen,
  SimpleResourceScreen,
  TargetsScreen,
} from "./screens/ConsoleScreens";

const navigation: Array<{ screen: ScreenName; label: string }> = [
  { screen: "live", label: "Live" },
  { screen: "findings", label: "Findings" },
  { screen: "approvals", label: "Approvals" },
  { screen: "coverage", label: "Coverage" },
  { screen: "resilience", label: "Resilience" },
  { screen: "traces", label: "Traces" },
  { screen: "costs", label: "Costs" },
  { screen: "targets", label: "Targets" },
  { screen: "config", label: "Configuration" },
];

const mobilePrimaryNavigation = navigation.filter((item) =>
  (["live", "findings", "approvals", "targets"] as ScreenName[]).includes(item.screen),
);
const mobileMoreNavigation = navigation.filter(
  (item) => !mobilePrimaryNavigation.some((primary) => primary.screen === item.screen),
);

function SecurityState({ state, detail }: { state: string; detail: string }) {
  return (
    <main className="security-shell">
      <div className="security-card">
        <div className="brand-mark" aria-hidden="true">H</div>
        <p className="eyebrow">HEADSHOT ACCESS BOUNDARY</p>
        <h1>{state}</h1>
        <p>{detail}</p>
      </div>
    </main>
  );
}

function SessionTaskRoute({ path }: { path: string }) {
  return (
    <main className="security-shell">
      {path === "/session-tasks/choose-organization" && (
        <TaskChooseOrganization redirectUrlComplete="/live" />
      )}
      {path === "/session-tasks/setup-mfa" && <TaskSetupMFA redirectUrlComplete="/live" />}
      {path === "/session-tasks/reset-password" && (
        <TaskResetPassword redirectUrlComplete="/live" />
      )}
    </main>
  );
}

function useBrowserRoute(): [ConsoleRoute, (route: ConsoleRoute) => void] {
  const [route, setRoute] = useState(() => parseConsoleRoute(window.location.pathname));
  useEffect(() => {
    const update = () => setRoute(parseConsoleRoute(window.location.pathname));
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, []);
  const navigate = useCallback((next: ConsoleRoute) => {
    const path = routePath(next);
    if (path !== window.location.pathname) window.history.pushState(null, "", path);
    setRoute(next);
  }, []);
  return [route, navigate];
}

function ConsoleShell({
  principal,
  client,
  getToken,
}: {
  principal: Principal;
  client: ReturnType<typeof createApiClient>;
  getToken: () => Promise<string | null>;
}) {
  const [route, navigate] = useBrowserRoute();
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [mobileMore, setMobileMore] = useState(false);
  const go = (next: ConsoleRoute) => {
    setMobileMore(false);
    navigate(next);
  };
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);
  const common = { client, principal, entityId: route.entityId, getToken };

  let screen: React.ReactNode;
  switch (route.screen) {
    case "live":
      screen = <LiveScreen {...common} />;
      break;
    case "findings":
      screen = <FindingsScreen {...common} />;
      break;
    case "approvals":
      screen = <ApprovalsScreen {...common} />;
      break;
    case "coverage":
    case "resilience":
    case "traces":
    case "costs":
      screen = <SimpleResourceScreen client={client} resource={route.screen} />;
      break;
    case "targets":
      screen = <TargetsScreen {...common} />;
      break;
    case "config":
      screen = <ConfigurationScreen {...common} />;
      break;
  }

  return (
    <div className="console-shell">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="wordmark"><span className="brand-mark small">H</span><span>HEADSHOT</span></div>
        <nav>
          {navigation.map((item) => (
            <button
              type="button"
              key={item.screen}
              className={route.screen === item.screen ? "nav-item active" : "nav-item"}
              aria-current={route.screen === item.screen ? "page" : undefined}
              onClick={() => go({ screen: item.screen, entityId: null })}
            >
              {item.label}
            </button>
          ))}
        </nav>
        <div className="identity-block">
          <span className="eyebrow">VERIFIED BY BACKEND</span>
          <strong className="mono">{principal.user_id}</strong>
          <span className="mono">{principal.organization_id}</span>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div>
            <span className="topbar-title">Operator Console</span>
            <span className="topbar-context">{principal.organization_permissions.length} server-verified capabilities</span>
          </div>
          <div className="topbar-actions">
            <button
              type="button"
              className="icon-button"
              onClick={() => setTheme((value) => value === "dark" ? "light" : "dark")}
              aria-label={`Use ${theme === "dark" ? "light" : "dark"} theme`}
            >
              {theme === "dark" ? "☼" : "◐"}
            </button>
            <UserButton />
          </div>
        </header>
        <main className="screen">{screen}</main>
        <nav className="mobile-nav" aria-label="Mobile navigation">
          {mobilePrimaryNavigation.map((item) => (
            <button
              type="button"
              key={item.screen}
              className={route.screen === item.screen ? "active" : undefined}
              onClick={() => go({ screen: item.screen, entityId: null })}
            >
              {item.label}
            </button>
          ))}
          <button
            type="button"
            className={mobileMoreNavigation.some((item) => item.screen === route.screen) ? "active" : undefined}
            aria-expanded={mobileMore}
            onClick={() => setMobileMore((value) => !value)}
          >
            More
          </button>
          {mobileMore && (
            <div className="mobile-more-menu">
              {mobileMoreNavigation.map((item) => (
                <button
                  type="button"
                  key={item.screen}
                  className={route.screen === item.screen ? "active" : undefined}
                  onClick={() => go({ screen: item.screen, entityId: null })}
                >
                  {item.label}
                </button>
              ))}
            </div>
          )}
        </nav>
      </div>
    </div>
  );
}

function ProtectedConsole({ getToken }: { getToken: () => Promise<string | null> }) {
  const client = useMemo(() => createApiClient({ getToken }), [getToken]);
  const principal = useResource<Principal>(client, RESOURCE_PATHS.principal, decodePrincipal);
  if (principal.result.state === "loading") {
    return <SecurityState state="Verifying organization access" detail="Protected data remains closed until FastAPI verifies the session." />;
  }
  if (principal.result.state !== "ready" || principal.result.data === null) {
    return (
      <SecurityState
        state="Platform access denied"
        detail="The server did not return a ready organization principal. Access remains closed."
      />
    );
  }
  return <ConsoleShell principal={principal.result.data} client={client} getToken={getToken} />;
}

export function App() {
  const clerk = useClerk();
  const auth = useAuth({ treatPendingAsSignedOut: true });
  const path = window.location.pathname;
  const getToken = useCallback(() => auth.getToken(), [auth.getToken]);

  if (clerk.status === "loading" || !auth.isLoaded) {
    return <SecurityState state="Loading identity provider" detail="Protected data remains unavailable while Clerk initializes." />;
  }
  if (clerk.status === "error") {
    return <SecurityState state="Authentication unavailable" detail="Clerk failed to initialize. Access remains closed." />;
  }
  if (clerk.status === "degraded") {
    return <SecurityState state="Authentication degraded" detail="Identity verification is degraded. Access remains closed." />;
  }
  if (path.startsWith("/session-tasks/")) return <SessionTaskRoute path={path} />;
  if (!auth.isSignedIn || path === "/sign-in" || path.startsWith("/sign-in/")) {
    if (!auth.isSignedIn && path !== "/sign-in" && !path.startsWith("/sign-in/")) {
      window.history.replaceState(null, "", "/sign-in");
    }
    return (
      <main className="security-shell">
        <div className="sign-in-frame">
          <p className="eyebrow">INVITATION-ONLY ACCESS</p>
          <SignIn
            routing="path"
            path="/sign-in"
            withSignUp={false}
            forceRedirectUrl="/live"
            fallbackRedirectUrl="/live"
          />
        </div>
      </main>
    );
  }
  if (auth.actor !== null) {
    return <SecurityState state="Impersonation denied" detail="Impersonated sessions cannot access the operator console." />;
  }
  if (!auth.orgId) {
    return (
      <main className="security-shell">
        <div className="sign-in-frame">
          <p className="eyebrow">ORGANIZATION REQUIRED</p>
          <TaskChooseOrganization redirectUrlComplete="/live" />
        </div>
      </main>
    );
  }
  return <ProtectedConsole getToken={getToken} />;
}
