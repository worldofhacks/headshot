/*
 * Traces.tsx — trace waterfall of spans + span detail.
 * Faithful 1:1 translation of "Headshot Console.dc.html" template lines 1142–1216.
 * Data shape from tracesVM() (line 3212): trHeader / trSpans / trTicks / trSel.
 * Scenario gate: integration state drops the fabricated live trace and shows an honest
 * "No live projection" empty-state; demo state shows the waterfall.
 */
import type { ScreenProps } from "../types";

export function Traces({ app }: ScreenProps) {
  const integ = app.state.scenario === "integration";
  const { trHeader, trSpans, trTicks, trSel } = app.tracesVM();

  if (integ) {
    return (
      <div style={{ flex: 1, minHeight: 0, overflowY: "auto", display: "flex", alignItems: "center", justifyContent: "center", padding: "48px 24px" }}>
        <div style={{ maxWidth: "540px", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center", gap: "13px" }}>
          <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="var(--tx3)" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z" opacity=".45"></path>
            <path d="M8.5 12h7"></path>
          </svg>
          <div style={{ fontSize: "var(--fs-2xl)", fontWeight: 600, color: "var(--tx)", letterSpacing: "-.01em" }}>No live projection</div>
          <div style={{ fontSize: "var(--fs-base)", color: "var(--tx2)", lineHeight: 1.55 }}>Span and trace data exist in the internal tracing layer. The Langfuse integration and a console trace read model are not implemented.</div>
          <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "4px 11px", border: "1px solid var(--bd)", borderRadius: "var(--r-pill)", color: "var(--tx2)", fontSize: "var(--fs-2xs)" }}>tracing INTERNAL ONLY · Langfuse PROPOSED</span>
          <button onClick={() => app.setDemo()} style={{ marginTop: "4px", height: "32px", padding: "0 15px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "transparent", color: "var(--tx2)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>View demo scenario</button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ flex: 1, minHeight: 0, overflowX: "hidden", overflowY: "hidden" }}>
      <div style={{ height: "100%", minWidth: 0, display: "flex", flexDirection: "column" }}>
        <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "12px", padding: "13px 18px", borderBottom: "1px solid var(--bd)" }}>
          <span style={{ fontSize: "var(--fs-xl)", fontWeight: 600 }}>Agent trace</span>
          <span className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--brand)" }}>{trHeader.run}</span>
          <span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>{trHeader.attempt}</span>
          <span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)" }}>{trHeader.trace}</span>
          <div style={{ flex: 1 }}></div>
          <span className="lab">Total</span><span className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>{trHeader.total}</span>
        </div>
        <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "1.5fr 1fr" }}>
          <section aria-label="Trace waterfall" style={{ minHeight: 0, display: "flex", flexDirection: "column", borderRight: "1px solid var(--bd)" }}>
            <div style={{ display: "flex", padding: "6px 16px 6px 176px", borderBottom: "1px solid var(--sep)", position: "relative", height: "26px" }}>
              {trTicks.map((k: any, i: number) => (
                <span key={i} className="mono" style={{ position: "absolute", fontSize: "var(--fs-2xs)", color: "var(--tx3)", left: `calc(176px + ${k.left})` }}>{k.label}</span>
              ))}
            </div>
            <div style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
              {trSpans.map((s: any) => (
                <button key={s.id} onClick={s.onClick} style={{ width: "100%", display: "flex", alignItems: "center", gap: 0, height: "36px", padding: "0 16px 0 0", textAlign: "left", background: s.rowBg, position: "relative", borderBottom: "1px solid var(--sep)" }}>
                  <span style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: "2px", background: s.rowLine }}></span>
                  <span style={{ width: "176px", flex: "0 0 auto", paddingLeft: "16px", display: "flex", flexDirection: "column", lineHeight: 1.1, overflow: "hidden" }}>
                    <span style={{ fontSize: "var(--fs-sm)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{s.label}</span>
                    <span className="lab" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{s.agent}</span>
                  </span>
                  <span style={{ flex: 1, position: "relative", height: "100%" }}>
                    <span style={{ position: "absolute", top: "50%", transform: "translateY(-50%)", height: "12px", left: s.left, width: s.width, background: s.zoneColor, borderRadius: "3px", minWidth: "3px" }}></span>
                  </span>
                  <span className="mono" style={{ width: "52px", flex: "0 0 auto", textAlign: "right", fontSize: "var(--fs-2xs)", color: "var(--tx2)" }}>{s.dur}</span>
                  <span style={{ width: "9px", height: "9px", borderRadius: "50%", background: s.statusColor, marginLeft: "10px", flex: "0 0 auto" }}></span>
                </button>
              ))}
            </div>
          </section>
          <section aria-label="Span detail" style={{ minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg-panel)" }}>
            <div style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "16px 18px", display: "flex", flexDirection: "column", gap: "14px" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "9px", marginBottom: "8px" }}>
                  <span style={{ width: "3px", height: "20px", borderRadius: "2px", background: trSel.zoneColor }}></span>
                  <span style={{ fontSize: "var(--fs-xl)", fontWeight: 600 }}>{trSel.label}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span className="lab" style={{ padding: "2px 8px", borderRadius: "var(--r-xs)", color: trSel.zoneColor, border: `1px solid ${trSel.zoneColor}` }}>{trSel.zoneLabel}</span>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-xs)", color: trSel.statusColor }}><span style={{ width: "6px", height: "6px", borderRadius: "50%", background: trSel.statusColor }}></span>{trSel.statusLabel}</span>
                </div>
              </div>
              <p style={{ margin: 0, fontSize: "var(--fs-base)", lineHeight: 1.55, color: "var(--tx)" }}>{trSel.desc}</p>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "9px" }}>
                <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Agent</span><div style={{ fontSize: "var(--fs-sm)", marginTop: "3px" }}>{trSel.agent}</div></div>
                <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Model / tool</span><div className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", marginTop: "3px" }}>{trSel.model}</div></div>
                <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Start → end</span><div className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", marginTop: "3px" }}>{trSel.start} → {trSel.end}</div></div>
                <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Duration</span><div className="mono" style={{ fontSize: "var(--fs-sm)", fontWeight: 600, marginTop: "3px" }}>{trSel.dur}</div></div>
                <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Tokens</span><div className="mono" style={{ fontSize: "var(--fs-sm)", marginTop: "3px" }}>{trSel.tokens}</div></div>
                <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Cost</span><div className="mono" style={{ fontSize: "var(--fs-sm)", marginTop: "3px" }}>{trSel.cost}</div></div>
              </div>
              <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Correlation ID</span><div className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", marginTop: "3px" }}>{trHeader.trace} · {trSel.corr}</div></div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
