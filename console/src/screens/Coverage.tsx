/*
 * Coverage.tsx — faithful 1:1 port of the prototype COVERAGE screen
 * (Headshot Console.dc.html lines 1032–1082).
 *
 * OWASP LLM + Web coverage matrix over app.coverageVM(): each category row carries a
 * non-color state label (tested/partial/untested/na), case count, hit-rate bar, last
 * version, and evidence-quality dots. In Integration scenario, fabricated live rollups
 * are dropped and an honest "No live projection" empty-state renders instead — never a
 * "safe"-reading blank. Colors are the prototype's CSS vars; no restyling.
 */
import type { ScreenProps } from "../types";

export function Coverage({ app }: ScreenProps) {
  const integ = app.state.scenario === "integration";
  const setDemo = () => app.setState({ scenario: "demo" });
  const vm = app.coverageVM();
  const covRows: any[] = vm.covRows;

  return (
    <>
      {/* ===== COVERAGE ===== */}
      {integ && (
        <div style={{ flex: 1, minHeight: 0, overflowY: "auto", display: "flex", alignItems: "center", justifyContent: "center", padding: "48px 24px" }}>
          <div style={{ maxWidth: "540px", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center", gap: "13px" }}>
            <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="var(--tx3)" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z" opacity=".45"></path>
              <path d="M8.5 12h7"></path>
            </svg>
            <div style={{ fontSize: "var(--fs-2xl)", fontWeight: 600, color: "var(--tx)", letterSpacing: "-.01em" }}>No live projection</div>
            <div style={{ fontSize: "var(--fs-base)", color: "var(--tx2)", lineHeight: 1.55 }}>Coverage is computed inside the platform (coverage_view.sql) but has no console-facing read model. Category rollups render here once a projection exists.</div>
            <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "4px 11px", border: "1px solid var(--bd)", borderRadius: "var(--r-pill)", color: "var(--tx2)", fontSize: "var(--fs-2xs)" }}>INTERNAL ONLY → projection PROPOSED</span>
            <button onClick={setDemo} style={{ marginTop: "4px", height: "32px", padding: "0 15px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "transparent", color: "var(--tx2)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>View demo scenario</button>
          </div>
        </div>
      )}
      {!integ && (
        <div style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
          <div style={{ maxWidth: "1120px", margin: "0 auto", padding: "20px 24px" }}>
            <div style={{ display: "flex", alignItems: "flex-end", gap: "12px", marginBottom: "14px" }}>
              <span style={{ fontSize: "var(--fs-3xl)", fontWeight: 600 }}>Coverage</span>
              <span style={{ fontSize: "var(--fs-base)", color: "var(--tx2)", paddingBottom: "2px" }}>OWASP taxonomy · Atlas Support Agent <span className="mono" style={{ color: "var(--tx3)" }}>v1.4.2</span></span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "18px", marginBottom: "16px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "7px" }}><span style={{ width: "9px", height: "9px", borderRadius: "2px", background: "var(--v-clear)" }}></span><span className="mono" style={{ fontSize: "var(--fs-lg)", fontWeight: 600 }}>{vm.covTested}</span><span className="lab">tested</span></div>
              <div style={{ display: "flex", alignItems: "center", gap: "7px" }}><span style={{ width: "9px", height: "9px", borderRadius: "2px", background: "var(--tz-data)" }}></span><span className="mono" style={{ fontSize: "var(--fs-lg)", fontWeight: 600 }}>{vm.covPartial}</span><span className="lab">partial</span></div>
              <div style={{ display: "flex", alignItems: "center", gap: "7px" }}><span style={{ width: "9px", height: "9px", borderRadius: "2px", border: "1.5px solid var(--warn)" }}></span><span className="mono" style={{ fontSize: "var(--fs-lg)", fontWeight: 600, color: "var(--warn)" }}>{vm.covUntested}</span><span className="lab">untested</span></div>
              <div style={{ flex: 1 }}></div>
              <span style={{ display: "inline-flex", alignItems: "center", gap: "7px", fontSize: "var(--fs-sm)", color: "var(--warn)" }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3l9.5 17H2.5z M12 9.5v5 M12 17.5h.01"></path></svg>Untested categories drive the Orchestrator’s next priority</span>
            </div>
            <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", overflow: "hidden" }}>
              <div style={{ display: "grid", gridTemplateColumns: "96px 1fr 108px 62px 132px 82px 66px", gap: "8px", padding: "9px 14px", background: "var(--bg-head)", borderBottom: "1px solid var(--sep)" }}>
                <span className="lab">OWASP</span><span className="lab">Category</span><span className="lab">Coverage</span><span className="lab" style={{ textAlign: "right" }}>Cases</span><span className="lab">Recent exploit</span><span className="lab">Last ver</span><span className="lab">Evidence</span>
              </div>
              {covRows.map((c: any, i: number) => (
                <div key={i} style={{ display: "grid", gridTemplateColumns: "96px 1fr 108px 62px 132px 82px 66px", gap: "8px", padding: "10px 14px", alignItems: "center", background: c.rowBg, borderBottom: "1px solid var(--sep)" }}>
                  <span className="mono" style={{ fontSize: "var(--fs-2xs)", padding: "2px 6px", borderRadius: "var(--r-xs)", background: "var(--bg-inset)", color: "var(--tx2)", justifySelf: "start" }}>{c.tag}</span>
                  <span style={{ fontSize: "var(--fs-base)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{c.name}</span>
                  <span style={{ justifySelf: "start", display: "inline-flex", alignItems: "center", gap: "5px", padding: "2px 9px", borderRadius: "var(--r-xs)", fontSize: "var(--fs-xs)", fontWeight: 600, color: c.stColor, background: c.stBg, border: "1px solid " + c.stColor }}>{c.stLabel}</span>
                  <span className="mono" style={{ fontSize: "var(--fs-sm)", textAlign: "right", color: "var(--tx2)" }}>{c.cases}</span>
                  <span style={{ display: "flex", alignItems: "center", gap: "7px" }}>
                    <span style={{ flex: 1, height: "4px", borderRadius: "2px", background: "var(--bg-inset)", overflow: "hidden" }}><span style={{ display: "block", height: "100%", width: c.rateW, background: "var(--v-conf)" }}></span></span>
                    <span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", width: "30px", textAlign: "right" }}>{c.rate}</span>
                  </span>
                  <span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)" }}>{c.ver}</span>
                  <span style={{ display: "flex", gap: "3px" }}><span style={{ width: "6px", height: "6px", borderRadius: "50%", background: c.ev1c }}></span><span style={{ width: "6px", height: "6px", borderRadius: "50%", background: c.ev2c }}></span><span style={{ width: "6px", height: "6px", borderRadius: "50%", background: c.ev3c }}></span></span>
                </div>
              ))}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "10px", fontSize: "var(--fs-xs)", color: "var(--tx3)" }}><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M4 6h16 M4 12h16 M4 18h10"></path></svg>This table is the accessible alternative to the heat view — keyboard-navigable, with non-color state labels and evidence-quality dots.</div>
          </div>
        </div>
      )}
    </>
  );
}
