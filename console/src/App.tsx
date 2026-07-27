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
import {
  decodeApprovals,
  decodeBirdseye,
  decodeCampaigns,
  decodePrincipal,
} from "./api/read-models";
import {
  LIVE_RESOURCE_POLL_INTERVAL_MS,
  useResource,
} from "./hooks/useResource";
import { shortId } from "./components/Analytics";
import { FreshnessBadge } from "./components/FreshnessBadge";
import { LiveDataProvider } from "./live/LiveDataProvider";
import {
  isCampaignScopedScreen,
  parseConsoleRoute,
  routePath,
  workspaceRoute,
  type ConsoleRoute,
  type PrimaryScreen,
} from "./router";
import { ApprovalsScreen } from "./screens/ConsoleScreens";
import { CoverageRegressionScreen } from "./screens/CoverageRegressionScreen";
import {
  FindingsWorkspace,
  ObservabilityWorkspace,
  RunsWorkspace,
  SystemWorkspace,
} from "./screens/Workspaces";
import type {
  ApprovalReadModel,
  BirdseyeSnapshotReadModel,
  CampaignReadModel,
} from "./types";

const navigation: Array<{ screen: PrimaryScreen; label: string; icon: string }> = [
  { screen: "runs", label: "Runs", icon: "M3 12h3.5l2.5 7 4.5-14 2.5 7H21" },
  { screen: "findings", label: "Findings", icon: "M12 3l7 2.5v5.5c0 4.3-3 7.4-7 8.5-4-1.1-7-4.2-7-8.5V5.5L12 3z M9 12l2 2 4-4" },
  { screen: "coverage", label: "Coverage", icon: "M4 4h7v7H4z M13 4h7v7h-7z M4 13h7v7H4z M13 13h7v7h-7z" },
  { screen: "approvals", label: "Approvals", icon: "M4 6.5A2.5 2.5 0 0 1 6.5 4h11A2.5 2.5 0 0 1 20 6.5v11a2.5 2.5 0 0 1-2.5 2.5h-11A2.5 2.5 0 0 1 4 17.5z M8.5 12l2.5 2.5 5-5" },
  { screen: "observability", label: "Observability", icon: "M4 6h11 M4 12h15 M4 18h8" },
  { screen: "system", label: "System", icon: "M6 4v5 M6 13v7 M12 4v3 M12 11v9 M18 4v9 M18 17v3 M3 11h6 M9 7h6 M15 13h6" },
];

function LineIcon({ path, size = 17 }: { path: string; size?: number }) {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <path d={path} />
    </svg>
  );
}

function HeadshotMark() {
  return (
    <svg width="26" height="26" viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <rect x="6" y="5.4" width="6" height="9" rx="2.6" fill="currentColor" />
      <rect x="6" y="17.6" width="6" height="9" rx="2.6" fill="currentColor" />
      <rect x="20" y="5.4" width="6" height="9" rx="2.6" fill="currentColor" />
      <rect x="20" y="17.6" width="6" height="9" rx="2.6" fill="currentColor" />
      <rect x="11" y="14.6" width="10" height="2.8" rx="1.4" fill="currentColor" opacity=".5" />
      <circle cx="16" cy="16" r="2.5" fill="var(--phos)" />
      <path d="M3 8.5V4.8A1.8 1.8 0 0 1 4.8 3H8.5 M23.5 3h3.7A1.8 1.8 0 0 1 29 4.8V8.5 M29 23.5v3.7a1.8 1.8 0 0 1-1.8 1.8H23.5 M8.5 29H4.8A1.8 1.8 0 0 1 3 27.2V23.5" stroke="currentColor" strokeWidth="1.3" opacity=".34" strokeLinecap="round" />
    </svg>
  );
}

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
        <TaskChooseOrganization redirectUrlComplete="/runs" />
      )}
      {path === "/session-tasks/setup-mfa" && <TaskSetupMFA redirectUrlComplete="/runs" />}
      {path === "/session-tasks/reset-password" && (
        <TaskResetPassword redirectUrlComplete="/runs" />
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
  const scopeKey = `${route.screen}:${route.entityId ?? ""}`;

  return (
    <LiveDataProvider getToken={getToken} scopeKey={scopeKey}>
      <ConsoleShellContent
        principal={principal}
        client={client}
        getToken={getToken}
        route={route}
        navigate={navigate}
      />
    </LiveDataProvider>
  );
}

function ConsoleShellContent({
  principal,
  client,
  getToken,
  route,
  navigate,
}: {
  principal: Principal;
  client: ReturnType<typeof createApiClient>;
  getToken: () => Promise<string | null>;
  route: ConsoleRoute;
  navigate: (route: ConsoleRoute) => void;
}) {
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [selectedCampaignId, setSelectedCampaignId] = useState<string | null>(
    isCampaignScopedScreen(route.screen) ? route.entityId : null,
  );
  const campaigns = useResource<CampaignReadModel[]>(
    client,
    RESOURCE_PATHS.campaigns,
    decodeCampaigns,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  const approvals = useResource<ApprovalReadModel[]>(
    client,
    RESOURCE_PATHS.approvals,
    decodeApprovals,
  );
  const birdseye = useResource<BirdseyeSnapshotReadModel>(
    client,
    RESOURCE_PATHS.birdseye,
    decodeBirdseye,
  );
  const campaignData = campaigns.result.data ?? [];
  const routedCampaignId = isCampaignScopedScreen(route.screen) ? route.entityId : null;
  const explicitCampaignId = routedCampaignId
    ?? (route.screen === "live" ? selectedCampaignId : null);
  const selectedCampaign = explicitCampaignId === null
    ? [...campaignData]
      .sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))
      .find((campaign) => campaign.state === "running" || campaign.state === "queued")
      ?? [...campaignData].sort(
        (left, right) => Date.parse(right.created_at) - Date.parse(left.created_at),
      )[0]
      ?? null
    : campaignData.find((campaign) => campaign.run_id === explicitCampaignId) ?? null;
  const activeCampaignId = explicitCampaignId ?? selectedCampaign?.run_id ?? null;
  const pendingApprovals = approvals.result.data?.filter((approval) => approval.status === "pending").length ?? 0;
  const systemState = birdseye.result.data?.instrumentation.system_state ?? birdseye.result.state;
  const serverStatus = birdseye.result.data
    ? `${systemState} · ${new Intl.DateTimeFormat("en-US", {
        hour: "numeric",
        minute: "2-digit",
        second: "2-digit",
      }).format(new Date(birdseye.result.data.as_of))}`
    : systemState;
  const go = (next: ConsoleRoute) => {
    navigate(next);
  };
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);
  const common = { client, principal, entityId: route.entityId, getToken };
  const workspace = workspaceRoute(route.screen);

  let screen: React.ReactNode;
  switch (workspace.screen) {
    case "runs":
      screen = (
        <RunsWorkspace
          {...common}
          entityId={workspace.view === "targets" ? null : route.entityId}
          view={workspace.view}
          campaignId={activeCampaignId}
          expandedAttemptId={route.screen === "live" ? route.entityId : null}
          onCampaignSelect={(campaignId) => {
            setSelectedCampaignId(campaignId);
            go({ screen: "runs", entityId: campaignId });
          }}
          onCampaignResolved={setSelectedCampaignId}
          onViewChange={(view) => go({
            screen: view === "operations" ? "runs" : "targets",
            entityId: null,
          })}
        />
      );
      break;
    case "findings":
      screen = (
        <FindingsWorkspace
          {...common}
          view={workspace.view}
          onViewChange={(view) => go({
            screen: view === "findings" ? "findings" : "reports",
            entityId: null,
          })}
        />
      );
      break;
    case "approvals":
      screen = <ApprovalsScreen {...common} />;
      break;
    case "coverage":
      screen = <CoverageRegressionScreen client={client} />;
      break;
    case "observability":
      screen = (
        <ObservabilityWorkspace
          client={client}
          campaignId={activeCampaignId}
          view={workspace.view}
          onViewChange={(view) => go({
            screen: view === "traces" ? "observability" : "costs",
            entityId: activeCampaignId,
          })}
        />
      );
      break;
    case "system":
      screen = (
        <SystemWorkspace
          {...common}
          entityId={null}
          view={workspace.view}
          onViewChange={(view) => go({
            screen: view === "agents"
              ? "system"
              : view === "tools"
                ? "tooling"
                : "config",
            entityId: null,
          })}
        />
      );
      break;
  }

  return (
    <div className="console-shell" data-theme={theme} data-density="compact">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="wordmark">
          <span className="wordmark-glyph"><HeadshotMark /></span>
          <span className="wordmark-copy"><strong>Headshot</strong><small>Adversarial eval</small></span>
        </div>
        <nav>
          {navigation.map((item) => (
            <button
              type="button"
              key={item.screen}
              className={workspace.screen === item.screen ? "nav-item active" : "nav-item"}
              aria-current={workspace.screen === item.screen ? "page" : undefined}
              onClick={() => go({
                screen: item.screen,
                entityId: null,
              })}
            >
              <LineIcon path={item.icon} />
              <span>{item.label}</span>
              {item.screen === "approvals" && pendingApprovals > 0 && (
                <span className="nav-badge mono" aria-label={`${pendingApprovals} pending`}>{pendingApprovals}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="identity-block">
          <UserButton />
          <span className="identity-copy">
            <strong>{(principal.organization_role ?? "member").replace("org:", "")}</strong>
            <span className="mono">{shortId(principal.user_id)}</span>
          </span>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div className="campaign-context">
            <span className="campaign-chip">
              <span className={`status-dot ${selectedCampaign?.state === "running" ? "live" : "idle"}`} />
              <span className="mono campaign-run">
                {selectedCampaign
                  ? shortId(selectedCampaign.run_id)
                  : activeCampaignId
                    ? shortId(activeCampaignId)
                    : "No selected run"}
              </span>
              {selectedCampaign && <><span className="campaign-sep">·</span><span className="mono campaign-version">{selectedCampaign.target_version}</span></>}
            </span>
            <span className={`campaign-state ${selectedCampaign?.state === "running" ? "live" : "idle"}`}>
              <span className="status-dot" />
              {selectedCampaign?.state ?? (activeCampaignId ? "Unavailable" : "ready")}
            </span>
          </div>
          <div className="topbar-actions">
            <FreshnessBadge serverStatus={serverStatus} systemState={systemState} />
            <button
              type="button"
              className="icon-button approval-shortcut"
              onClick={() => go({ screen: "approvals", entityId: null })}
              aria-label={`${pendingApprovals} pending approvals`}
            >
              <LineIcon path="M6.5 9a5.5 5.5 0 0 1 11 0c0 5.5 2.5 6 2.5 7.5H4C4 15 6.5 14.5 6.5 9z M10 20a2 2 0 0 0 4 0" size={16} />
              {pendingApprovals > 0 && <span className="topbar-badge mono">{pendingApprovals}</span>}
            </button>
            <button
              type="button"
              className="icon-button"
              onClick={() => setTheme((value) => value === "dark" ? "light" : "dark")}
              aria-label={`Use ${theme === "dark" ? "light" : "dark"} theme`}
            >
              <LineIcon path={theme === "dark" ? "M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z" : "M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10z M12 2v2 M12 20v2 M4 12H2 M22 12h-2 M5.6 5.6L4.2 4.2 M19.8 19.8l-1.4-1.4 M18.4 5.6l1.4-1.4 M4.2 19.8l-1.4 1.4"} size={15} />
            </button>
          </div>
        </header>
        <main className="screen">{screen}</main>
        <nav className="mobile-nav" aria-label="Mobile navigation">
          {navigation.map((item) => (
            <button
              type="button"
              key={item.screen}
              className={workspace.screen === item.screen ? "active" : undefined}
              onClick={() => go({
                screen: item.screen,
                entityId: null,
              })}
            >
              {item.label}
            </button>
          ))}
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
            forceRedirectUrl="/runs"
            fallbackRedirectUrl="/runs"
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
          <TaskChooseOrganization redirectUrlComplete="/runs" />
        </div>
      </main>
    );
  }
  return <ProtectedConsole getToken={getToken} />;
}
