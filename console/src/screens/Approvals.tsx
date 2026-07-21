/*
 * Approvals.tsx — faithful 1:1 port of the prototype APPROVALS screen
 * (Headshot Console.dc.html template lines 923–1031).
 *
 * Data comes from app.core() (apprCount/hasAppr/aEmpty/goLive) + app.apprVM()
 * (aList/aCurrent). The queue-vs-detail two-pane layout, the two-person-rule
 * courtesy-disable, and the sticky action bar are preserved verbatim. Decisions
 * are routed through the decision sheet overlay (each action's onClick =
 * app.openDecision(k), wired in the VM). Icons that arrive as pre-rendered VM
 * fields (kindIconEl / vIconEl) are React elements from app.svgEl(...) — rendered
 * directly. Colors are always CSS vars; every semantic channel keeps icon+shape+label.
 */
import type { ScreenProps } from "../types";

export function Approvals({ app }: ScreenProps) {
  const core = app.core();
  const vm = app.apprVM();

  const apprCount = core.apprCount as number;
  const aEmpty = vm.aEmpty as boolean;
  const hasAppr = core.hasAppr as boolean;
  const goLive = core.goLive as () => void;
  const aList = (vm.aList as any[]) || [];
  const aCurrent = (vm.aCurrent as any) || {};

  return (
    <div style={{ flex: 1, minHeight: 0, overflowX: "hidden", overflowY: "hidden" }}>
      <div style={{ height: "100%", minWidth: 0, display: "flex", flexDirection: "column" }}>
        <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "12px", padding: "12px 16px", borderBottom: "1px solid var(--bd)" }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: "9px" }}>
            <span style={{ fontSize: "var(--fs-2xl)", fontWeight: 600 }}>Approvals</span>
            <span className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx3)" }}>{apprCount} pending</span>
          </div>
          <div style={{ flex: 1 }}></div>
          <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "5px 10px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", color: "var(--tx2)" }}>
            <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M5 20a7 7 0 0 1 14 0"></path></svg>
            Two-person rule · approver ≠ launcher
          </span>
        </div>

        {aEmpty && (
          <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: "12px", textAlign: "center", padding: "40px" }}>
            <span style={{ width: "46px", height: "46px", borderRadius: "var(--r-xl)", background: "var(--phos-tint)", border: "1px solid var(--phos-line)", color: "var(--phos)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12.5l5 5 11-11"></path></svg>
            </span>
            <div style={{ fontSize: "var(--fs-xl)", fontWeight: 600 }}>Approval queue clear</div>
            <div style={{ fontSize: "var(--fs-base)", color: "var(--tx2)", maxWidth: "340px" }}>No decisions are waiting on a human. The campaign continues autonomously — new critical publications and indeterminate verdicts will appear here.</div>
            <button onClick={() => goLive()} style={{ marginTop: "4px", padding: "9px 15px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", fontSize: "var(--fs-base)", fontWeight: 500 }}>Back to Live</button>
          </div>
        )}

        {hasAppr && (
          <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "minmax(340px,1fr) 1.7fr" }}>
            {/* QUEUE LIST */}
            <section aria-label="Approval queue" style={{ minHeight: 0, display: "flex", flexDirection: "column", borderRight: "1px solid var(--bd)" }}>
              <div style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
                {aList.map((q: any) => (
                  <button key={q.id} onClick={() => q.onClick()} style={{ width: "100%", display: "flex", flexDirection: "column", gap: "7px", padding: "12px 15px 12px 16px", position: "relative", textAlign: "left", background: q.rowBg, borderBottom: "1px solid var(--sep)" }}>
                    <span style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: "2px", background: q.rowLine }}></span>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span style={{ width: "22px", height: "22px", borderRadius: "var(--r-sm)", background: "var(--bg-inset)", color: q.kindColor, display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}>{q.kindIconEl}</span>
                      <span style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: q.kindColor }}>{q.kindLabel}</span>
                      <div style={{ flex: 1 }}></div>
                      {q.escRaised && (<span className="lab" style={{ padding: "1px 6px", borderRadius: "var(--r-xs)", background: "var(--warn-t)", color: "var(--warn)", fontSize: "var(--fs-2xs)" }}>Escalated</span>)}
                      <span className="mono" style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "var(--fs-xs)", color: "var(--tx3)" }}>
                        <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M12 7.5v5l3 1.8"></path></svg>{q.sla}
                      </span>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span className="mono" style={{ fontSize: "var(--fs-sm)", fontWeight: 600 }}>{q.fid}</span>
                      <span style={{ width: "8px", height: "8px", borderRadius: "2px", background: q.sevColor }}></span>
                      <span style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{q.catShort}</span>
                      <div style={{ flex: 1 }}></div>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "2px 8px", borderRadius: "var(--r-xs)", fontSize: "var(--fs-2xs)", fontWeight: 600, color: q.vColor, background: q.vTint, border: "1px solid " + q.vBorder }}>{q.vIconEl}{q.vLabel}</span>
                    </div>
                  </button>
                ))}
              </div>
            </section>

            {/* DETAIL */}
            <section aria-label="Approval detail" style={{ minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg-panel)" }}>
              <div style={{ flex: "0 0 auto", padding: "15px 18px", borderBottom: "1px solid var(--sep)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px" }}>
                  <span style={{ width: "24px", height: "24px", borderRadius: "var(--r-sm)", background: "var(--bg-inset)", color: aCurrent.kindColor, display: "flex", alignItems: "center", justifyContent: "center" }}>{aCurrent.kindIconEl}</span>
                  <span className="lab" style={{ color: aCurrent.kindColor, fontSize: "var(--fs-2xs)" }}>{aCurrent.kindLabel}</span>
                  <div style={{ flex: 1 }}></div>
                  <span className="mono" style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-xs)", color: "var(--warn)" }}>
                    <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M12 7.5v5l3 1.8"></path></svg>SLA {aCurrent.sla}
                  </span>
                </div>
                <div style={{ fontSize: "var(--fs-md)", fontWeight: 600, color: "var(--tx)", marginBottom: "10px" }}>{aCurrent.requestText}</div>
                <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "11px" }}>
                  <span className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: "var(--brand)" }}>{aCurrent.fid}</span>
                  <span style={{ fontSize: "var(--fs-lg)", fontWeight: 600 }}>{aCurrent.title}</span>
                  <span style={{ width: "9px", height: "9px", borderRadius: "2px", background: aCurrent.sevColor }}></span>
                  <span style={{ fontSize: "var(--fs-sm)", fontWeight: 600, color: aCurrent.sevColor }}>{aCurrent.sevLabel}</span>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "3px 10px", borderRadius: "var(--r-sm)", fontSize: "var(--fs-sm)", fontWeight: 600, color: aCurrent.vColor, background: aCurrent.vTint, border: "1px solid " + aCurrent.vBorder }}>{aCurrent.vIconEl}{aCurrent.vLabel}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "4px 9px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>{aCurrent.target} <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{aCurrent.ver}</span></span>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "4px 9px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>Source: {aCurrent.confSource}</span>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "4px 9px", border: "1px solid " + aCurrent.integrityColor, borderRadius: "var(--r-xs)", fontSize: "var(--fs-xs)", fontWeight: 600, color: aCurrent.integrityColor }}>
                    <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M6.5 10V7.5a5.5 5.5 0 0 1 11 0V10 M5 10h14v9.5A1.5 1.5 0 0 1 17.5 21h-11A1.5 1.5 0 0 1 5 19.5z"></path></svg>{aCurrent.integrity}
                  </span>
                </div>
              </div>

              <div style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "16px 18px", display: "flex", flexDirection: "column", gap: "15px" }}>
                <div style={{ border: "1px solid var(--v-conf)", borderLeftWidth: "2.5px", borderRadius: "var(--r-sm)", padding: "11px 12px", background: "var(--v-conf-t)" }}><span className="lab" style={{ color: "var(--v-conf)" }}>Impact if approved unreviewed</span><p style={{ margin: "5px 0 0", fontSize: "var(--fs-base)", lineHeight: 1.5 }}>{aCurrent.impact}</p></div>

                <div>
                  <span className="lab">Consequences</span>
                  <div style={{ marginTop: "8px", display: "flex", flexDirection: "column", gap: "8px" }}>
                    {(aCurrent.acts || []).map((c: any, i: number) => (
                      <div key={i} style={{ display: "flex", gap: "10px", padding: "9px 11px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)" }}><span style={{ fontSize: "var(--fs-sm)", fontWeight: 600, color: "var(--tx)", whiteSpace: "nowrap", flex: "0 0 auto", width: "132px" }}>{c.label}</span><span style={{ fontSize: "var(--fs-sm)", lineHeight: 1.45, color: "var(--tx2)" }}>{c.cons}</span></div>
                    ))}
                  </div>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                  <div><span className="lab" style={{ color: "var(--v-clear)" }}>Expected</span><p style={{ margin: "5px 0 0", fontSize: "var(--fs-sm)", lineHeight: 1.45, color: "var(--tx2)" }}>{aCurrent.expected}</p></div>
                  <div><span className="lab" style={{ color: "var(--v-conf)" }}>Observed</span><p style={{ margin: "5px 0 0", fontSize: "var(--fs-sm)", lineHeight: 1.45, color: "var(--tx2)" }}>{aCurrent.observed}</p></div>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "10px", padding: "10px 12px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "var(--bg-inset)" }}>
                  <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--tx2)" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a9 9 0 1 0 9 9 M21 3v5h-5"></path></svg>
                  <span style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)" }}>Reproduction: <span className="mono" style={{ color: "var(--tx)" }}>{aCurrent.reproCount} step sequence</span> · deterministic replay on file</span>
                </div>
              </div>

              <div style={{ flex: "0 0 auto", borderTop: "1px solid var(--sep)", background: "var(--bg-head)", padding: "12px 18px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "9px" }}><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M5 20a7 7 0 0 1 14 0"></path></svg><span className="lab" style={{ color: "var(--tx3)" }}>Acting as A. Okafor · Approver — launcher was M. Reyes</span></div>
                {aCurrent.blocked && (<div style={{ display: "flex", alignItems: "flex-start", gap: "9px", padding: "10px 12px", marginBottom: "9px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-sm)", background: "var(--warn-t)" }}><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--warn)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto", marginTop: "1px" }}><path d="M6.5 10V7.5a5.5 5.5 0 0 1 11 0V10 M5 10h14v9.5A1.5 1.5 0 0 1 17.5 21h-11A1.5 1.5 0 0 1 5 19.5z"></path></svg><span style={{ fontSize: "var(--fs-sm)", lineHeight: 1.45, color: "var(--tx)" }}>{aCurrent.blockReason}</span></div>)}
                <div style={{ display: "flex", gap: "9px" }}>
                  {(aCurrent.acts || []).map((a: any, i: number) => (
                    <button key={i} onClick={() => a.onClick()} disabled={a.disabled} aria-disabled={a.disabled} style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", gap: "7px", padding: "11px", borderRadius: "var(--r-md)", fontSize: "var(--fs-base)", fontWeight: 600, background: a.bg, color: a.fg, border: "1px solid " + a.bd }}>{a.label}</button>
                  ))}
                </div>
              </div>
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
