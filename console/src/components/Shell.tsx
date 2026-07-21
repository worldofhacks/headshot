/*
 * Shell — the composition root. Faithful port of the root wrapper + desktop/mobile
 * split (Headshot Console.dc.html lines 107-108, 3401 `isDesktop`, and the per-screen
 * <sc-if> switch in <main>).
 *
 *   isDesktop = !(bp==='sm' || surface==='mobile')   (core() line 861)
 *   Desktop  → grid [shellCols] = sidebar + main(TopBar + routed screen)
 *   Mobile   → <Mobile app={app}/>  (phone frame / full-viewport handled inside)
 *
 * The routed screen is chosen from app.state.screen. <Overlays/> is ALWAYS rendered
 * last so palette / abort / decision / role-menu / catalog / drawers layer above.
 */
import type { ScreenProps, Screen } from "../types";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { Live } from "../screens/Live";
import { Findings } from "../screens/Findings";
import { Approvals } from "../screens/Approvals";
import { Coverage } from "../screens/Coverage";
import { Resilience } from "../screens/Resilience";
import { Traces } from "../screens/Traces";
import { Costs } from "../screens/Costs";
import { Targets } from "../screens/Targets";
import { Configuration } from "../screens/Configuration";
import { Mobile } from "../screens/Mobile";
import { Overlays } from "../overlays/Overlays";

function routeScreen(screen: Screen, app: ScreenProps["app"]) {
  switch (screen) {
    case "live": return <Live app={app} />;
    case "findings": return <Findings app={app} />;
    case "approvals": return <Approvals app={app} />;
    case "coverage": return <Coverage app={app} />;
    case "resilience": return <Resilience app={app} />;
    case "traces": return <Traces app={app} />;
    case "costs": return <Costs app={app} />;
    case "targets": return <Targets app={app} />;
    case "config": return <Configuration app={app} />;
    default: return <Live app={app} />;
  }
}

export function Shell({ app }: ScreenProps) {
  const vm = app.core();
  const isDesktop = vm.isDesktop as boolean;
  const screenLabel = ((app.nav as any[]).find((n) => n.id === app.state.screen) || {}).label || "Console";

  if (!isDesktop) {
    return (
      <>
        <Mobile app={app} />
        <Overlays app={app} />
      </>
    );
  }

  return (
    <>
      <div style={{ display: "grid", gridTemplateColumns: vm.shellCols as string, height: "100dvh", overflow: "hidden" }}>
        <Sidebar app={app} />
        <div style={{ display: "flex", flexDirection: "column", minWidth: 0, minHeight: 0 }}>
          <TopBar app={app} />
          <main aria-label={screenLabel} style={{ flex: 1, minHeight: 0, overflow: "hidden", display: "flex", flexDirection: "column" }}>
            {routeScreen(app.state.screen, app)}
          </main>
        </div>
      </div>
      <Overlays app={app} />
    </>
  );
}
