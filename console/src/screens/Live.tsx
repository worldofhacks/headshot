import type { ScreenProps } from "../types";

/*
 * Live.tsx — the flagship screen (template lines 227–749). Two modes share one
 * campaign+selection state: BIRDSEYE (war-room) and ATTEMPT STREAM.
 *
 * Data comes from three VM builders on `app`, exactly as the prototype's renderVals()
 * merges them: core() (isLive/paused/camp/togglePause), liveVM() (instr/rows/sel/ev),
 * birdseyeVM() (bePipeline/beSheet/beAttention/beTimeline/scenario). Icons are React
 * elements produced by app.svgEl() — rendered directly (the *IconEl fields).
 *
 * Faithful 1:1 translation: inline styles → style objects with the SAME CSS vars/values,
 * {{ expr }} → {expr}, <sc-if> → {cond && (...)}, sc-for → arr.map, all aria/role/data
 * attributes preserved verbatim. FROZEN design — no restyle, no added features.
 */
export function Live({ app }: ScreenProps) {
  const c = app.core();
  const l = app.liveVM();
  const b = app.birdseyeVM();

  const isLive: boolean = c.isLive;
  if (!isLive) return null;

  // convenience aliases (merged VM namespace, mirroring renderVals())
  const instr = l.instr;
  const sel = l.sel;
  const ev = l.ev;
  const camp = c.camp;

  return (
    <div style={{ flex: 1, minHeight: 0, overflowX: "hidden", overflowY: "hidden" }}>
      <div style={{ height: "100%", minWidth: 0, display: "flex", flexDirection: "column" }}>

        {/* INSTRUMENTATION STRIP */}
        <div style={{ flex: "0 0 auto", display: "flex", alignItems: "stretch", background: "var(--bg-panel)", borderBottom: "1px solid var(--bd)", overflowX: "auto" }}>
          <div style={{ display: "flex", flexDirection: "column", gap: "5px", padding: "11px 16px", minWidth: "184px" }}>
            <span className="lab">Budget consumed</span>
            <div style={{ display: "flex", alignItems: "baseline", gap: "6px" }}>
              <span className="mono" style={{ fontSize: "var(--fs-xl)", fontWeight: 600, color: instr.budgetColor }}>{instr.used}</span>
              <span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)" }}>/ {instr.cap}</span>
            </div>
            <div style={{ height: "4px", borderRadius: "3px", background: "var(--bg-inset)", overflow: "hidden" }}>
              <div style={{ height: "100%", borderRadius: "3px", width: instr.budgetPct, background: instr.budgetColor }}></div>
            </div>
          </div>
          <div style={{ width: "1px", background: "var(--sep)" }}></div>
          <div style={{ display: "flex", flexDirection: "column", gap: "5px", padding: "11px 16px", minWidth: "132px" }}>
            <span className="lab">Burn rate</span>
            <span className="mono" style={{ fontSize: "var(--fs-xl)", fontWeight: 600 }}>{instr.burn}<span style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", fontWeight: 400 }}> /hr</span></span>
            <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--warn)" }}>cap ≈ {instr.proj}</span>
          </div>
          <div style={{ width: "1px", background: "var(--sep)" }}></div>
          <div style={{ display: "flex", flexDirection: "column", gap: "5px", padding: "11px 16px", minWidth: "96px" }}>
            <span className="lab">Queue depth</span>
            <span className="mono" style={{ fontSize: "var(--fs-xl)", fontWeight: 600 }}>{instr.queue}</span>
            <span className="lab" style={{ color: "var(--tx2)" }}>draining</span>
          </div>
          <div style={{ width: "1px", background: "var(--sep)" }}></div>
          <div style={{ display: "flex", flexDirection: "column", gap: "5px", padding: "11px 16px", minWidth: "110px" }}>
            <span className="lab">Rate limit</span>
            <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "var(--fs-base)", fontWeight: 500, color: "var(--v-clear)" }}><span style={{ width: "7px", height: "7px", borderRadius: "50%", background: "var(--phos)" }}></span>Nominal</span>
            <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{instr.rate}</span>
          </div>
          <div style={{ width: "1px", background: "var(--sep)" }}></div>
          <div style={{ display: "flex", flexDirection: "column", gap: "5px", padding: "11px 16px", minWidth: "150px" }}>
            <span className="lab">Findings this run</span>
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-base)", fontWeight: 600 }}><span style={{ width: "7px", height: "7px", borderRadius: "2px", background: "var(--v-conf)" }}></span>{instr.cf}</span>
              <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-base)", fontWeight: 600 }}><span style={{ width: "7px", height: "7px", borderRadius: "2px", background: "var(--v-likely)" }}></span>{instr.likely}</span>
              <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-base)", fontWeight: 600 }}><span style={{ width: "7px", height: "7px", borderRadius: "2px", background: "var(--v-indet)" }}></span>{instr.indet}</span>
            </div>
            <span className="lab" style={{ color: "var(--tx2)" }}>confirmed · likely · review</span>
          </div>
          <div style={{ width: "1px", background: "var(--sep)" }}></div>
          <div style={{ display: "flex", flexDirection: "column", gap: "5px", padding: "11px 16px", minWidth: "132px", flex: 1 }}>
            <span className="lab">System health</span>
            <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "var(--fs-base)", fontWeight: 500, color: b.sysHealthColor }}><span style={{ width: "7px", height: "7px", borderRadius: "50%", background: b.sysHealthColor }}></span>{b.sysHealthLabel}</span>
            <span className="lab" style={{ color: "var(--tx2)" }}>{b.sysHealthSub}</span>
          </div>
        </div>

        {/* MODE + SCENARIO TABS */}
        <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "9px", padding: "8px 14px", borderBottom: "1px solid var(--sep)" }}>
          <div style={{ display: "flex", border: "1px solid var(--bd)", borderRadius: "var(--r-md)", overflow: "hidden" }} role="tablist" aria-label="Live mode">
            <button role="tab" aria-selected={b.liveBirdseye} onClick={b.setBirdseye} style={{ display: "flex", alignItems: "center", gap: "6px", padding: "6px 13px", fontSize: "var(--fs-sm)", fontWeight: 600, background: b.beBg, color: b.beFg }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"></path></svg>Birdseye</button>
            <button role="tab" aria-selected={b.liveStream} onClick={b.setStream} style={{ padding: "6px 13px", fontSize: "var(--fs-sm)", fontWeight: 600, borderLeft: "1px solid var(--bd)", background: b.streamBg, color: b.streamFg }}>Attempt Stream</button>
          </div>
          <span className="lab" style={{ color: "var(--tx3)" }}>War room</span>
          <div style={{ flex: 1 }}></div>
          <div style={{ display: "flex", alignItems: "center", gap: "9px" }}>
            <div style={{ display: "flex", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", overflow: "hidden" }} role="tablist" aria-label="Data source">
              <button role="tab" aria-selected={b.scenDemo} onClick={b.setDemo} title="Synthetic demo scenario — animated walkthrough" style={{ padding: "5px 11px", fontSize: "var(--fs-2xs)", fontWeight: 600, background: b.scenDemoBg, color: b.scenDemoFg }}>Demo scenario</button>
              <button role="tab" aria-selected={b.scenInteg} onClick={b.setInteg} title="Integration readiness — what actually exists in the backend today" style={{ padding: "5px 11px", fontSize: "var(--fs-2xs)", fontWeight: 600, borderLeft: "1px solid var(--bd)", background: b.scenIntegBg, color: b.scenIntegFg }}>Integration state</button>
            </div>
            <span className="lab" style={{ color: b.scenarioTagColor, fontSize: "var(--fs-2xs)" }}>{b.scenarioTag}</span>
          </div>
        </div>

        {/* ============ BIRDSEYE ============ */}
        {b.liveBirdseye && (
          <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: b.beGridCols }}>
            <div style={{ minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", borderRight: "1px solid var(--bd)" }}>
              <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "11px", padding: "9px 14px", borderBottom: "1px solid var(--sep)" }}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "var(--fs-sm)", fontWeight: 600, color: b.sysHealthColor }}><span style={{ width: "7px", height: "7px", borderRadius: "50%", background: b.sysHealthColor }}></span>{b.sysHealthLabel}</span>
                <span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)" }}>{b.beLive}</span>
                <span style={{ width: "1px", height: "14px", background: "var(--sep)" }}></span>
                <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "var(--fs-sm)", color: b.activeColor }}><span style={{ width: "6px", height: "6px", borderRadius: "50%", background: b.activeColor }}></span>{b.activeLabel}</span>
                <div style={{ marginLeft: "auto", display: "flex", gap: "6px" }}>
                  <button onClick={b.fitView} title="Fit — clear selection, follow live" style={{ height: "28px", padding: "0 10px", display: "inline-flex", alignItems: "center", gap: "5px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "transparent", color: "var(--tx2)", fontSize: "var(--fs-xs)", fontWeight: 600 }}>{b.icFit}Fit</button>
                  <button onClick={b.toggleFollow} aria-pressed={b.beFollow} title="Follow the active attempt's path" style={{ height: "28px", padding: "0 10px", display: "inline-flex", alignItems: "center", gap: "5px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: b.followBg, color: b.followFg, fontSize: "var(--fs-xs)", fontWeight: 600 }}>{b.icFollow}Follow</button>
                  <button onClick={b.focusActive} title="Open the active attempt in the stream" style={{ height: "28px", padding: "0 10px", display: "inline-flex", alignItems: "center", gap: "5px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "transparent", color: "var(--tx2)", fontSize: "var(--fs-xs)", fontWeight: 600 }}>{b.icFocus}Focus active</button>
                </div>
              </div>
              <div style={{ flex: 1, minHeight: 0, overflowY: "auto", overflowX: "hidden", padding: "16px 16px 18px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}><span className="lab">Execution pipeline</span><span className="lab" style={{ color: "var(--tx3)", marginLeft: "auto" }}>Untrusted → enforced → evaluated · top to bottom</span></div>
                <div style={{ display: "flex", flexDirection: "column" }}>
                  {b.bePipeline.map((z: any, zi: number) => (
                    <div key={zi}>
                      {z.hasConn && (
                        <div style={{ display: "flex", alignItems: "center", gap: "9px", paddingLeft: "6px", minHeight: "32px" }}>
                          <span style={{ display: "flex", flexDirection: "column", alignItems: "center", width: "16px", flex: "0 0 auto", color: z.connColor }}><span style={{ width: "2px", height: "12px", background: z.connColor }}></span><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 5v13 M6 13l6 6 6-6"></path></svg></span>
                          {z.hasConnLabel && (<span className="mono" style={{ fontSize: "var(--fs-2xs)", color: z.connColor, border: "1px solid " + z.connColor, borderRadius: "var(--r-xs)", padding: "2px 7px" }}>{z.connLabel}</span>)}
                          {z.connHasAttempt && (<span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-2xs)", fontWeight: 600, color: "var(--phos)" }}><span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "var(--phos)" }}></span>{z.connAttempt}</span>)}
                        </div>
                      )}
                      <div style={{ borderTop: "1px solid " + z.bandBd, borderRight: "1px solid " + z.bandBd, borderBottom: "1px solid " + z.bandBd, borderLeft: "3px solid " + z.color, borderRadius: "var(--r-lg)", padding: "11px 12px", background: "var(--bg-app)", boxShadow: z.bandShadow }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "9px" }}><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: z.color, fontWeight: 600 }}>{z.idx}</span><span className="lab" style={{ color: "var(--tx2)" }}>{z.label}</span></div>
                        <div style={{ display: "grid", gridTemplateColumns: z.nodesCols, gap: "9px" }}>
                          {z.nodes.map((n: any, ni: number) => (
                            <button key={ni} onClick={n.onClick} aria-pressed={n.selected} aria-label={n.name} style={{ textAlign: "left", minWidth: 0, border: "1px solid " + n.cardBd, borderRadius: "var(--r-md)", padding: "10px 11px", background: n.cardBg, display: "flex", flexDirection: "column", gap: "6px" }}>
                              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}><span style={{ color: n.zoneColor, display: "flex", flex: "0 0 auto" }}>{n.typeIconEl}</span><span style={{ fontSize: "var(--fs-base)", fontWeight: 600, flex: 1, minWidth: 0, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{n.name}</span><span style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "var(--fs-2xs)", fontWeight: 600, color: n.stateColor, flex: "0 0 auto" }}>{n.stateIconEl}{n.stateLabel}</span></div>
                              <div style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", lineHeight: 1.4, overflow: "hidden", textOverflow: "ellipsis", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>{n.task}</div>
                              <div style={{ display: "flex", alignItems: "center", gap: "11px" }}><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{n.metricK} {n.metricV}</span>{n.cluster && (<span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{n.healthy}/{n.total} up</span>)}</div>
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                <div style={{ marginTop: "16px", borderTop: "1px dashed var(--bd)", paddingTop: "14px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "9px" }}><span className="lab">Shared infrastructure</span><span className="lab" style={{ color: "var(--tx3)", marginLeft: "auto" }}>Foundation · non-lifecycle</span></div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: "9px" }}>
                    {b.beInfra.map((n: any, ni: number) => (
                      <button key={ni} onClick={n.onClick} aria-pressed={n.selected} style={{ textAlign: "left", minWidth: 0, border: "1px solid " + n.cardBd, borderRadius: "var(--r-md)", padding: "10px 11px", background: n.cardBg, display: "flex", flexDirection: "column", gap: "5px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "7px" }}><span style={{ color: n.zoneColor, display: "flex", flex: "0 0 auto" }}>{n.typeIconEl}</span><span style={{ fontSize: "var(--fs-sm)", fontWeight: 600, flex: 1, minWidth: 0, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{n.name}</span><span style={{ display: "inline-flex", alignItems: "center", gap: "4px", color: n.stateColor, flex: "0 0 auto" }}>{n.stateIconEl}</span></div>
                        <div style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", lineHeight: 1.35 }}>{n.supports}</div>
                        <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{n.metricK} {n.metricV}</span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              <div style={{ flex: "0 0 auto", borderTop: "1px solid var(--bd)", display: "flex", flexDirection: "column" }}>
                <button onClick={b.toggleTL} aria-expanded={b.beTLOpen} style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "8px", padding: "8px 14px", background: "transparent", textAlign: "left" }}><span style={{ display: "flex", color: "var(--tx3)", transform: "rotate(" + b.tlChevron + ")" }}>{b.icChevron}</span><span className="lab">Activity timeline</span><span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "4px", color: b.tlLiveColor }}><span style={{ width: "5px", height: "5px", borderRadius: "50%", background: b.tlLiveColor }}></span>{b.tlLiveBadge}</span><span className="lab" style={{ marginLeft: "auto", color: "var(--tx3)" }}>{b.tlHint}</span></button>
                {b.beTLOpen && (
                  <div style={{ height: "154px", overflowY: "auto", borderTop: "1px solid var(--sep)", animation: "hs-in .18s var(--ease-out)" }}>
                    {b.beTimeline.map((e: any, ei: number) => (
                      <button key={ei} onClick={e.onClick} style={{ width: "100%", textAlign: "left", display: "flex", alignItems: "center", gap: "10px", padding: "7px 14px", borderBottom: "1px solid var(--sep)" }}><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", width: "52px", flex: "0 0 auto" }}>{e.t}</span><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", width: "46px", flex: "0 0 auto" }}>{e.actor}</span><span style={{ flex: 1, minWidth: 0, fontSize: "var(--fs-sm)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", display: "flex", alignItems: "center", gap: "6px" }}><span style={{ width: "6px", height: "6px", borderRadius: "50%", background: e.color, flex: "0 0 auto" }}></span>{e.action}</span><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--brand)", flex: "0 0 auto" }}>{e.id}</span></button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {b.beShowInspector && (
              <div style={{ minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg-panel)", animation: "hs-in .2s var(--ease-out)" }} data-overlay="0">
                <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "9px", padding: "11px 12px 11px 14px", borderBottom: "1px solid var(--sep)" }}>
                  <span style={{ color: b.beSheet.zoneColor, display: "flex", flex: "0 0 auto" }}>{b.beSheet.typeIconEl}</span>
                  <div style={{ flex: 1, minWidth: 0 }}><div style={{ fontSize: "var(--fs-md)", fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{b.beSheet.name}</div><div style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-2xs)", fontWeight: 600, color: b.beSheet.stateColor, marginTop: "2px" }}>{b.beSheet.stateIconEl}{b.beSheet.stateLabel}</div></div>
                  <button onClick={b.closeNode} aria-label="Close inspector" title="Close (Esc)" style={{ width: "28px", height: "28px", flex: "0 0 auto", display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "transparent", color: "var(--tx2)" }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M6 6l12 12 M18 6L6 18"></path></svg></button>
                </div>
                <div style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "14px", display: "flex", flexDirection: "column", gap: "15px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px" }}><span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-2xs)", fontWeight: 600, color: b.beSheet.zoneColor, border: "1px solid " + b.beSheet.zoneColor, borderRadius: "var(--r-xs)", padding: "2px 7px" }}>{b.beSheet.zoneLabel}</span>{b.beSheet.cluster && (<span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{b.beSheet.healthy}/{b.beSheet.total} instances up</span>)}</div>
                  <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", lineHeight: 1.5 }}>{b.beSheet.purpose}</div>
                  <div><span className="lab">Current task</span><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx)", marginTop: "5px", lineHeight: 1.45 }}>{b.beSheet.task}</div></div>
                  {b.beSheet.hasModel && (<div><span className="lab">Assigned model</span><div className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", marginTop: "5px", wordBreak: "break-all" }}>{b.beSheet.model}</div></div>)}
                  {b.beSheet.uncal && (<div style={{ display: "flex", alignItems: "flex-start", gap: "8px", padding: "9px 11px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-md)", background: "var(--warn-t)", fontSize: "var(--fs-xs)", color: "var(--tx)", lineHeight: 1.45 }}><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="var(--warn)" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto", marginTop: "1px" }}><path d="M12 3l9.5 17H2.5z M12 9.5v5 M12 17.5h.01"></path></svg>{b.beSheet.uncalLabel}</div>)}
                  <div>
                    <span className="lab">Identity &amp; endpoints</span>
                    <div style={{ marginTop: "6px", display: "flex", flexDirection: "column", gap: "4px" }}>
                      {(b.beSheet.ep || []).map((e: string, ei: number) => (<span key={ei} className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", wordBreak: "break-all" }}>{e}</span>))}
                    </div>
                    <div style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)", marginTop: "7px", lineHeight: 1.45 }}>{b.beSheet.cred}</div>
                  </div>
                  <div>
                    <span className="lab">Health</span>
                    <div style={{ marginTop: "7px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                      <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "8px 10px" }}><div className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Last heartbeat</div><div className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600, marginTop: "3px" }}>{b.beSheet.hb}</div></div>
                      <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "8px 10px" }}><div className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Success</div><div className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600, marginTop: "3px" }}>{b.beSheet.succ}</div></div>
                      <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "8px 10px" }}><div className="lab" style={{ fontSize: "var(--fs-2xs)" }}>p50</div><div className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600, marginTop: "3px" }}>{b.beSheet.p50}</div></div>
                      <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "8px 10px" }}><div className="lab" style={{ fontSize: "var(--fs-2xs)" }}>p95</div><div className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600, marginTop: "3px" }}>{b.beSheet.p95}</div></div>
                    </div>
                  </div>
                  {b.beSheet.cluster && (
                    <div><span className="lab">Instances</span><div style={{ marginTop: "7px", display: "flex", gap: "14px" }}><span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-xs)", color: "var(--tx2)" }}><span style={{ width: "7px", height: "7px", borderRadius: "50%", background: "var(--phos)" }}></span>{b.beSheet.working} working</span><span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-xs)", color: "var(--tx2)" }}><span style={{ width: "7px", height: "7px", borderRadius: "50%", background: "var(--tx3)" }}></span>{b.beSheet.idleN} idle</span>{b.beSheet.degradedN ? (<span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-xs)", color: "var(--warn)" }}><span style={{ width: "7px", height: "7px", borderRadius: "50%", background: "var(--warn)" }}></span>{b.beSheet.degradedN} degraded</span>) : null}</div></div>
                  )}
                  {b.beSheet.hasErrs && (
                    <div><span className="lab" style={{ color: "var(--warn)" }}>Recent errors</span><div style={{ marginTop: "6px", display: "flex", flexDirection: "column", gap: "5px" }}>{(b.beSheet.errs || []).map((er: string, eri: number) => (<span key={eri} style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", borderLeft: "2px solid var(--warn)", paddingLeft: "8px", lineHeight: 1.4 }}>{er}</span>))}</div></div>
                  )}
                  {b.beSheet.hasRel && (
                    <div>
                      <span className="lab">Related</span>
                      <div style={{ marginTop: "7px", display: "flex", flexWrap: "wrap", gap: "6px" }}>
                        {(b.beSheet.relAtt || []).map((r: any, ri: number) => (<button key={"a" + ri} onClick={r.onClick} className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--brand)", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", padding: "3px 8px", background: "transparent" }}>{r.id}</button>))}
                        {(b.beSheet.relFind || []).map((r: any, ri: number) => (<button key={"f" + ri} onClick={r.onClick} className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--v-conf)", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", padding: "3px 8px", background: "transparent" }}>{r.id}</button>))}
                        {(b.beSheet.relTr || []).map((r: any, ri: number) => (<button key={"t" + ri} onClick={r.onClick} className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx2)", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", padding: "3px 8px", background: "transparent" }}>{r.id}</button>))}
                      </div>
                    </div>
                  )}
                  <span className="lab" style={{ alignSelf: "flex-start", display: "inline-flex", alignItems: "center", gap: "5px", padding: "3px 8px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-xs)", color: "var(--warn)", background: "var(--warn-t)", fontSize: "var(--fs-2xs)" }}>{b.scenarioTag}</span>
                </div>
              </div>
            )}

            {b.beShowAttn && (
              <div style={{ minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg-panel)" }}>
                <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "8px", padding: "9px 10px 9px 14px", borderBottom: "1px solid var(--sep)" }}><span style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Attention</span><span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--warn)" }}>{b.beAttnCount}</span><button onClick={b.toggleAttnRail} aria-label="Collapse attention rail" title="Collapse" style={{ marginLeft: "auto", width: "26px", height: "26px", display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "transparent", color: "var(--tx3)" }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M9 6l6 6-6 6"></path></svg></button></div>
                <div style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "10px", display: "flex", flexDirection: "column", gap: "9px" }}>
                  {b.beAttention.map((a: any, ai: number) => (
                    <button key={ai} onClick={a.onClick} style={{ width: "100%", textAlign: "left", borderTop: "1px solid var(--bd)", borderRight: "1px solid var(--bd)", borderBottom: "1px solid var(--bd)", borderLeft: "2.5px solid " + a.color, borderRadius: "var(--r-md)", padding: "10px 11px", background: "var(--bg-app)" }}><div style={{ display: "flex", alignItems: "center", gap: "7px", marginBottom: "4px" }}><span style={{ color: a.color, display: "flex", flex: "0 0 auto" }}>{a.iconEl}</span><span style={{ fontSize: "var(--fs-sm)", fontWeight: 600, flex: 1, minWidth: 0 }}>{a.title}</span><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", flex: "0 0 auto" }}>{a.age}</span></div><div style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", lineHeight: 1.4 }}>{a.why}</div><div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "6px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)", color: "var(--v-clear)" }}>{a.cont}</span><span className="lab" style={{ marginLeft: "auto", color: "var(--brand)", fontSize: "var(--fs-2xs)" }}>{a.action} ›</span></div></button>
                  ))}
                  {b.beAttnHasMore && (<button onClick={b.toggleAttnAll} style={{ width: "100%", textAlign: "center", fontSize: "var(--fs-xs)", fontWeight: 600, color: "var(--brand)", border: "1px dashed var(--bd)", borderRadius: "var(--r-md)", padding: "8px", background: "transparent" }}>{b.attnMoreLabel}</button>)}
                </div>
              </div>
            )}

            {b.beShowStrip && (
              <button onClick={b.toggleAttnRail} aria-label="Expand attention rail" title="Show attention" style={{ minHeight: 0, display: "flex", flexDirection: "column", alignItems: "center", gap: "10px", padding: "12px 0", background: "var(--bg-panel)", color: "var(--tx2)" }}><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M15 6l-6 6 6 6"></path></svg><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--warn)", border: "1px solid var(--warn-line)", borderRadius: "var(--r-xs)", padding: "2px 5px" }}>{b.beAttnCount}</span><span className="lab" style={{ writingMode: "vertical-rl", transform: "rotate(180deg)", letterSpacing: "1.5px" }}>Attention</span></button>
            )}
          </div>
        )}

        {/* ============ STREAM ============ */}
        {b.liveStream && (
          <>
            {l.liveTwoPane && (
              <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "9px", padding: "7px 14px", borderBottom: "1px solid var(--sep)", background: "var(--bg-head)" }}>
                <span className="lab">Inspector</span>
                <div style={{ display: "flex", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", overflow: "hidden" }} role="tablist" aria-label="Inspector pane">
                  {l.liveMdOne && (<button role="tab" aria-selected={l.inspStream} onClick={l.setInspStream} style={{ padding: "5px 12px", fontSize: "var(--fs-sm)", fontWeight: 500, borderRight: "1px solid var(--bd)", background: l.inspStreamBg, color: l.inspStreamFg }}>Stream</button>)}
                  <button role="tab" aria-selected={l.inspAttempt} onClick={l.setInspAttempt} style={{ padding: "5px 12px", fontSize: "var(--fs-sm)", fontWeight: 500, background: l.inspAttemptBg, color: l.inspAttemptFg }}>Attempt</button>
                  <button role="tab" aria-selected={l.inspEvidence} onClick={l.setInspEvidence} style={{ padding: "5px 12px", fontSize: "var(--fs-sm)", fontWeight: 500, borderLeft: "1px solid var(--bd)", background: l.inspEvidenceBg, color: l.inspEvidenceFg }}>Evidence &amp; verdict</button>
                </div>
              </div>
            )}
            {/* 3 PANES */}
            <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: l.liveCols }}>

              {l.streamVisible && (
                /* PANE 1: STREAM */
                <section aria-label="Campaign stream" style={{ minHeight: 0, display: "flex", flexDirection: "column", borderRight: "1px solid var(--bd)" }}>
                  <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "9px", padding: "9px 14px", borderBottom: "1px solid var(--sep)" }}>
                    <span style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Campaign stream</span>
                    <span className="lab" style={{ color: "var(--tx2)" }}>{camp.scope}</span>
                    <div style={{ flex: 1 }}></div>
                    {c.paused && (
                      <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "3px 7px", borderRadius: "var(--r-xs)", background: "var(--warn-t)", color: "var(--warn)" }}><span style={{ width: "5px", height: "5px", borderRadius: "50%", background: "var(--warn)" }}></span>Visual paused</span>
                    )}
                    <button onClick={c.togglePause} title={c.pauseTitle} style={{ display: "flex", alignItems: "center", gap: "6px", padding: "4px 9px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>
                      {c.paused && (<><svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M7 5l12 7-12 7z"></path></svg>Resume</>)}
                      {c.notPaused && (<><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round"><path d="M8 5v14 M16 5v14"></path></svg>Pause</>)}
                    </button>
                  </div>

                  <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "8px", padding: "6px 14px", borderBottom: "1px solid var(--sep)", background: "var(--bg-head)" }}>
                    <span className="lab" style={{ width: "42px" }}>Seq</span>
                    <span className="lab" style={{ width: "52px" }}>Time</span>
                    <span className="lab" style={{ flex: 1 }}>Attack category</span>
                    <span className="lab" style={{ width: "46px" }}>Gen</span>
                    <span className="lab" style={{ width: "96px" }}>Stage / verdict</span>
                    <span className="lab" style={{ width: "52px", textAlign: "right" }}>Cost</span>
                    <span style={{ width: "12px" }}></span>
                  </div>

                  <div style={{ position: "relative", flex: 1, minHeight: 0 }}>
                    {l.showNew && (
                      <button onClick={l.flushNew} style={{ position: "absolute", top: "10px", left: "50%", transform: "translateX(-50%)", zIndex: 5, display: "flex", alignItems: "center", gap: "7px", padding: "6px 13px", borderRadius: "var(--r-xl)", background: "var(--brand)", color: "#fff", fontSize: "var(--fs-sm)", fontWeight: 600, boxShadow: "var(--shadow)", animation: "hs-in .18s var(--ease-out)" }}>
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 19V6 M6 11l6-6 6 6"></path></svg>{l.newCount} new events
                      </button>
                    )}
                    <div ref={l.streamRef} onScroll={l.onStreamScroll} role="list" style={{ position: "absolute", inset: 0, overflowY: "auto", padding: "4px 0" }}>
                      {l.rows.map((a: any, ai: number) => (
                        <button key={ai} role="listitem" onClick={a.select} style={{ width: "100%", display: "flex", alignItems: "center", gap: "8px", height: "var(--row-h)", padding: "0 14px", position: "relative", background: a.rowBg, textAlign: "left", fontSize: "var(--fs-row)", borderBottom: "1px solid transparent" }}>
                          <span style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: "2px", background: a.rowLine }}></span>
                          <span className="mono" style={{ width: "42px", color: "var(--tx3)", fontSize: "var(--fs-xs)" }}>{a.seqStr}</span>
                          <span className="mono" style={{ width: "52px", color: "var(--tx2)", fontSize: "var(--fs-xs)" }}>{a.t}</span>
                          <span style={{ flex: 1, minWidth: 0, display: "flex", alignItems: "center", gap: "7px" }}>
                            <span className="mono" style={{ fontSize: "var(--fs-2xs)", padding: "1px 4px", borderRadius: "3px", background: "var(--bg-inset)", color: "var(--tx3)", flex: "0 0 auto" }}>{a.owaspId}</span>
                            <span style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", color: "var(--tx)" }}>{a.catShort}</span>
                          </span>
                          <span className="mono" style={{ width: "46px", flex: "0 0 auto", fontSize: "var(--fs-2xs)", color: "var(--tx3)", whiteSpace: "nowrap" }}>{a.strat}</span>
                          <span style={{ width: "96px", display: "flex", alignItems: "center" }}>
                            {a.inProgress && (
                              <span style={{ display: "flex", flexDirection: "column", gap: "3px", width: "100%" }}>
                                <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--brand)" }}>{a.stageLabel}</span>
                                <span style={{ height: "3px", borderRadius: "2px", background: "var(--bg-inset)", overflow: "hidden" }}><span style={{ display: "block", height: "100%", width: a.prog, background: "var(--brand)" }}></span></span>
                              </span>
                            )}
                            {a.resolved && (
                              <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-xs)", fontWeight: 500, color: a.vColor }}><span style={{ width: "6px", height: "6px", borderRadius: a.vDotR, background: a.vColor, flex: "0 0 auto" }}></span>{a.vLabel}</span>
                            )}
                          </span>
                          <span className="mono" style={{ width: "52px", textAlign: "right", color: "var(--tx2)", fontSize: "var(--fs-xs)" }}>{a.cost}</span>
                          <span style={{ width: "12px", display: "flex", justifyContent: "center" }}>
                            {a.attHuman && (<span title="Human attention required" style={{ width: "8px", height: "8px", borderRadius: "50%", background: "var(--warn)", boxShadow: "0 0 0 3px var(--warn-t)" }}></span>)}
                            {a.attReview && (<span title="Flagged for review" style={{ width: "7px", height: "7px", borderRadius: "50%", border: "2px solid var(--v-indet)" }}></span>)}
                          </span>
                        </button>
                      ))}
                    </div>
                  </div>
                </section>
              )}

              {l.selVisible && (
                /* PANE 2: SELECTED ATTEMPT */
                <section aria-label="Selected attempt" style={{ minHeight: 0, display: "flex", flexDirection: "column", borderRight: "1px solid var(--bd)" }}>
                  <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "8px", padding: "9px 14px", borderBottom: "1px solid var(--sep)" }}>
                    <span style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Attempt</span>
                    <span className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--brand)" }}>{sel.id}</span>
                    <div style={{ flex: 1 }}></div>
                    <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{sel.strat}</span>
                  </div>
                  <div style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "14px" }}>
                    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

                      <div>
                        <span className="lab">Attack objective</span>
                        <p style={{ margin: "5px 0 0", fontSize: "var(--fs-base)", lineHeight: 1.5 }}>{sel.objective}</p>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "7px" }}>
                          <span className="mono" style={{ fontSize: "var(--fs-2xs)", padding: "2px 6px", borderRadius: "var(--r-xs)", background: "var(--bg-inset)", color: "var(--tx2)" }}>{sel.owaspF} {sel.owaspId}</span>
                          <span style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>{sel.owaspName}</span>
                        </div>
                      </div>

                      <div style={{ padding: "11px 12px", border: "1px solid var(--brand-line)", borderLeftWidth: "2.5px", borderRadius: "var(--r-sm)", background: "var(--brand-tint)" }}>
                        <span className="lab" style={{ color: "var(--brand)" }}>Why the orchestrator selected this</span>
                        <p style={{ margin: "5px 0 0", fontSize: "var(--fs-base)", lineHeight: 1.5, color: "var(--tx)" }}>{sel.rationale}</p>
                      </div>

                      {/* Quarantined input */}
                      <div>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                          <span className="lab" style={{ color: "var(--tz-quar)" }}>Quarantined input</span>
                          <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "4px", padding: "2px 6px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-xs)", color: "var(--warn)", background: "var(--warn-t)", fontSize: "var(--fs-2xs)" }}>Untrusted · Red Team</span>
                        </div>
                        <div style={{ border: "1px solid var(--warn-line)", borderRadius: "var(--r-sm)", overflow: "hidden", background: "repeating-linear-gradient(135deg,var(--warn-t),var(--warn-t) 9px,transparent 9px,transparent 18px)" }}>
                          {sel.quarHidden && (
                            <div style={{ padding: "18px 14px", display: "flex", flexDirection: "column", alignItems: "center", gap: "9px", textAlign: "center", background: "var(--bg-panel)" }}>
                              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="var(--warn)" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M4 4l16 16 M9.5 5.4A9.7 9.7 0 0 1 12 5c6.5 0 10 7 10 7a15 15 0 0 1-3.3 3.9 M6.4 6.4A15 15 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 3.1-.5"></path></svg>
                              <span style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", maxWidth: "230px" }}>Adversarial payload hidden. Content is rendered as escaped plain text and never interpreted.</span>
                              <button onClick={l.revealQuar} style={{ display: "flex", alignItems: "center", gap: "6px", padding: "6px 12px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-xs)", background: "var(--warn-t)", color: "var(--warn)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>
                                <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"></path></svg>Reveal payload
                              </button>
                            </div>
                          )}
                          {sel.quarRevealed && (
                            <div style={{ background: "var(--bg-inset)" }}>
                              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "5px 10px", borderBottom: "1px solid var(--warn-line)", background: "var(--warn-t)" }}>
                                <span className="lab" style={{ color: "var(--warn)", fontSize: "var(--fs-2xs)" }}>Quarantined content · escaped</span>
                                <div style={{ display: "flex", gap: "4px" }}>
                                  <button onClick={l.copyQuar} title="Copy (with warning)" style={{ display: "flex", alignItems: "center", gap: "4px", padding: "2px 6px", borderRadius: "var(--r-xs)", color: "var(--warn)", fontSize: "var(--fs-2xs)" }}><svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M9 9h10v10H9z M5 15V5h10"></path></svg>Copy</button>
                                  <button onClick={l.hideQuar} title="Hide" style={{ display: "flex", alignItems: "center", padding: "2px 5px", borderRadius: "var(--r-xs)", color: "var(--warn)", fontSize: "var(--fs-2xs)" }}><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M6 6l12 12 M18 6L6 18"></path></svg></button>
                                </div>
                              </div>
                              <pre className="mono" style={{ margin: 0, padding: "11px 12px", fontSize: "var(--fs-xs)", lineHeight: 1.55, color: "var(--tx)", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{sel.quarText}</pre>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Target exchange */}
                      <div>
                        <span className="lab" style={{ color: "var(--tz-ext)" }}>Target request</span>
                        <pre className="mono" style={{ margin: "5px 0 0", padding: "10px 11px", border: "1px solid var(--bd)", borderLeft: "2.5px solid var(--tz-ext)", borderRadius: "var(--r-sm)", background: "var(--bg-inset)", fontSize: "var(--fs-xs)", lineHeight: 1.5, whiteSpace: "pre-wrap", wordBreak: "break-word", color: "var(--tx2)" }}>{sel.req}</pre>
                      </div>
                      <div>
                        <span className="lab" style={{ color: "var(--tz-ext)" }}>Target response</span>
                        <pre className="mono" style={{ margin: "5px 0 0", padding: "10px 11px", border: "1px solid var(--bd)", borderLeft: "2.5px solid var(--tz-ext)", borderRadius: "var(--r-sm)", background: "var(--bg-inset)", fontSize: "var(--fs-xs)", lineHeight: 1.5, whiteSpace: "pre-wrap", wordBreak: "break-word", color: "var(--tx)" }}>{sel.resp}</pre>
                      </div>

                      {/* Mutation ancestry */}
                      <div>
                        <span className="lab">Mutation ancestry</span>
                        <div style={{ marginTop: "7px", display: "flex", flexDirection: "column", gap: 0 }}>
                          {sel.mutation.map((m: any, mi: number) => (
                            <div key={mi} style={{ display: "flex", gap: "10px", alignItems: "flex-start" }}>
                              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", flex: "0 0 auto" }}>
                                <span style={{ width: "9px", height: "9px", borderRadius: m.r, border: "1.5px solid " + m.c, background: m.fill }}></span>
                                <span style={{ width: "1.5px", flex: 1, minHeight: "14px", background: m.line }}></span>
                              </div>
                              <div style={{ paddingBottom: "10px" }}>
                                <span className="mono" style={{ fontSize: "var(--fs-xs)", color: m.c }}>{m.gen}</span>
                                <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "1px" }}>{m.desc}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Policy + timing */}
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                        <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "10px 11px" }}>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "7px" }}>
                            <span className="lab" style={{ color: "var(--tz-trust)" }}>Policy gateway</span>
                            <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "var(--fs-xs)", fontWeight: 600, color: "var(--v-clear)" }}><svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12.5l5 5 11-11"></path></svg>PASS</span>
                          </div>
                          <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                            {sel.policy.map((p: any, pi: number) => (
                              <div key={pi} style={{ display: "flex", justifyContent: "space-between", gap: "8px", fontSize: "var(--fs-xs)" }}><span style={{ color: "var(--tx3)" }}>{p.k}</span><span className="mono" style={{ color: "var(--tx2)", fontSize: "var(--fs-xs)" }}>{p.v}</span></div>
                            ))}
                          </div>
                        </div>
                        <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "10px 11px" }}>
                          <span className="lab">Execution timing</span>
                          <div style={{ display: "flex", flexDirection: "column", gap: "4px", marginTop: "7px" }}>
                            {sel.timing.map((t: any, ti: number) => (
                              <div key={ti} style={{ display: "flex", justifyContent: "space-between", gap: "8px", fontSize: "var(--fs-xs)" }}><span style={{ color: "var(--tx3)" }}>{t.k}</span><span className="mono" style={{ color: "var(--tx2)", fontSize: "var(--fs-xs)" }}>{t.v}</span></div>
                            ))}
                          </div>
                        </div>
                      </div>

                    </div>
                  </div>
                </section>
              )}

              {l.evVisible && (
                /* PANE 3: EVIDENCE & VERDICT */
                <section aria-label="Evidence and verdict" style={{ minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg-panel)" }}>
                  <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "8px", padding: "9px 14px", borderBottom: "1px solid var(--sep)" }}>
                    <span style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Evidence &amp; verdict</span>
                    <div style={{ flex: 1 }}></div>
                    <span className="lab" style={{ color: "var(--tx3)" }}>Independent judge</span>
                  </div>
                  <div style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "14px", display: "flex", flexDirection: "column", gap: "14px" }}>

                    {/* Verdict header */}
                    <div style={{ border: "1px solid " + ev.vBorder, borderRadius: "var(--r-md)", overflow: "hidden" }}>
                      <div style={{ padding: "13px 14px", background: ev.vTint, borderBottom: "1px solid " + ev.vBorder }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "9px" }}>
                          <span style={{ width: "30px", height: "30px", borderRadius: "var(--r-md)", background: ev.vTint, border: "1px solid " + ev.vBorder, display: "flex", alignItems: "center", justifyContent: "center", color: ev.vColor, flex: "0 0 auto" }}>
                            {ev.vIconEl}
                          </span>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ fontSize: "var(--fs-lg)", fontWeight: 600, color: ev.vColor, lineHeight: 1.15 }}>{ev.vLabel}</div>
                            <div className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", marginTop: "2px" }}>{ev.vKey}</div>
                          </div>
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "10px" }}>
                          <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-xs)", fontWeight: 500, color: ev.vColor }}><span style={{ width: "5px", height: "5px", borderRadius: "50%", background: ev.provColor }}></span>{ev.provLine}</span>
                        </div>
                      </div>
                    </div>

                    {/* Integrity */}
                    <div style={{ border: "1px solid " + ev.hashBorder, borderRadius: "var(--r-md)", padding: "11px 12px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "9px" }}>
                        <span style={{ color: ev.hashColor, display: "flex" }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M6.5 10V7.5a5.5 5.5 0 0 1 11 0V10 M5 10h14v9.5A1.5 1.5 0 0 1 17.5 21h-11A1.5 1.5 0 0 1 5 19.5z"></path></svg></span>
                        <span style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Evidence integrity</span>
                        <div style={{ flex: 1 }}></div>
                        <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "2px 8px", borderRadius: "var(--r-xs)", fontSize: "var(--fs-xs)", fontWeight: 600, color: ev.hashColor, background: ev.hashTint, border: "1px solid " + ev.hashBorder }}>{ev.hashLabel}</span>
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: "5px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: "10px", fontSize: "var(--fs-xs)" }}><span style={{ color: "var(--tx3)" }}>Content hash</span><span className="mono" style={{ color: "var(--tx2)", fontSize: "var(--fs-2xs)" }}>{ev.hash}</span></div>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: "10px", fontSize: "var(--fs-xs)" }}><span style={{ color: "var(--tx3)" }}>Recorder</span><span className="mono" style={{ color: "var(--tx2)", fontSize: "var(--fs-2xs)" }}>{ev.recorder}</span></div>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: "10px", fontSize: "var(--fs-xs)" }}><span style={{ color: "var(--tx3)" }}>Trace</span><span className="mono" style={{ color: "var(--tx2)", fontSize: "var(--fs-2xs)" }}>{ev.trace}</span></div>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: "10px", fontSize: "var(--fs-xs)" }}><span style={{ color: "var(--tx3)" }}>Schema</span><span className="mono" style={{ color: "var(--tx2)", fontSize: "var(--fs-2xs)" }}>{ev.schema}</span></div>
                      </div>
                    </div>

                    {/* Hash-mismatch block */}
                    {ev.hashMismatch && (
                      <div style={{ border: "1px solid var(--v-err)", borderRadius: "var(--r-md)", padding: "11px 12px", background: "var(--v-err-t)" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--v-err)" }}><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M8.5 3h7l5 5v7l-5 5h-7l-5-5V8z M12 8v5 M12 16.5h.01"></path></svg><span style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Verdict blocked — integrity failed</span></div>
                        <p style={{ margin: "7px 0 0", fontSize: "var(--fs-sm)", lineHeight: 1.5, color: "var(--tx2)" }}>Recomputed content hash does not match the stored hash. No judge verdict can be treated as authoritative until the evidence is re-recorded.</p>
                      </div>
                    )}

                    {/* Oracle evidence */}
                    {ev.hasOracle && (
                      <div style={{ border: "1px solid var(--phos-line)", borderRadius: "var(--r-md)", padding: "11px 12px", background: "var(--phos-tint)" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "7px" }}><span style={{ color: "var(--phos)", display: "flex" }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12.5l5 5 11-11"></path></svg></span><span style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Deterministic oracle</span><span className="lab" style={{ marginLeft: "auto", color: "var(--phos)", fontSize: "var(--fs-2xs)" }}>Precedence</span></div>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: "10px", fontSize: "var(--fs-xs)", marginBottom: "5px" }}><span style={{ color: "var(--tx3)" }}>Oracle</span><span className="mono" style={{ color: "var(--tx)", fontSize: "var(--fs-xs)" }}>{ev.oracleName}</span></div>
                        <p style={{ margin: 0, fontSize: "var(--fs-sm)", lineHeight: 1.5, color: "var(--tx)" }}>{ev.oracleDetail}</p>
                        <p style={{ margin: "7px 0 0", fontSize: "var(--fs-xs)", color: "var(--tx3)", fontStyle: "italic" }}>The LLM judge cannot downgrade a confirmed oracle hit.</p>
                      </div>
                    )}

                    {/* Judge evidence */}
                    {ev.hasJudge && (
                      <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "11px 12px", opacity: ev.judgeOpacity }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "9px" }}>
                          <span style={{ color: "var(--tz-gov)", display: "flex" }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3v3 M7 6h10l2 6H5z M6 12v6a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2v-6"></path></svg></span>
                          <span style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Judge assessment</span>
                          <span className="mono" style={{ marginLeft: "auto", fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{ev.judgeModel}</span>
                        </div>
                        {ev.judgeSuppressed && (
                          <p style={{ margin: 0, fontSize: "var(--fs-xs)", color: "var(--tx3)", fontStyle: "italic" }}>Not evaluated — deterministic oracle resolved the outcome.</p>
                        )}
                        {ev.judgeActive && (
                          <div>
                            <div style={{ display: "flex", alignItems: "baseline", gap: "8px", marginBottom: "7px" }}>
                              <span className="mono" style={{ fontSize: "var(--fs-4xl)", fontWeight: 600, color: ev.vColor }}>{ev.judgeScore}</span>
                              <span className="lab" style={{ color: "var(--tx3)" }}>confidence</span>
                              <span className="mono" style={{ marginLeft: "auto", fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>thr {ev.judgeThresh}</span>
                            </div>
                            <div style={{ position: "relative", height: "6px", borderRadius: "3px", background: "var(--bg-inset)", marginBottom: "9px" }}>
                              <div style={{ position: "absolute", top: 0, bottom: 0, left: 0, borderRadius: "3px", width: ev.judgeScorePct, background: ev.vColor }}></div>
                              <div style={{ position: "absolute", top: "-2px", bottom: "-2px", width: "2px", background: "var(--tx2)", left: ev.judgeThreshPct }}></div>
                            </div>
                            <div style={{ display: "flex", flexDirection: "column", gap: "5px", marginBottom: "9px" }}>
                              <div style={{ display: "flex", justifyContent: "space-between", gap: "8px", fontSize: "var(--fs-xs)" }}><span style={{ color: "var(--tx3)" }}>Rubric</span><span className="mono" style={{ color: "var(--tx2)", fontSize: "var(--fs-xs)" }}>{ev.judgeRubric}</span></div>
                              <div style={{ display: "flex", justifyContent: "space-between", gap: "8px", fontSize: "var(--fs-xs)" }}><span style={{ color: "var(--tx3)" }}>Calibration</span><span className="mono" style={{ color: ev.calibColor, fontSize: "var(--fs-xs)" }}>{ev.judgeCalib}</span></div>
                            </div>
                            <span className="lab">Evidence-grounded rationale</span>
                            <p style={{ margin: "5px 0 0", fontSize: "var(--fs-sm)", lineHeight: 1.5, color: "var(--tx2)" }}>{ev.judgeRationale}</p>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Error */}
                    {ev.hasError && (
                      <div style={{ border: "1px solid var(--v-err)", borderRadius: "var(--r-md)", padding: "11px 12px", background: "var(--v-err-t)" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}><span style={{ color: "var(--v-err)", display: "flex" }}><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M8.5 3h7l5 5v7l-5 5h-7l-5-5V8z M12 8v5 M12 16.5h.01"></path></svg></span><span style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: "var(--v-err)" }}>Evaluation error</span><span className="mono" style={{ marginLeft: "auto", fontSize: "var(--fs-2xs)", padding: "2px 6px", borderRadius: "var(--r-xs)", background: "var(--v-err-t)", border: "1px solid var(--v-err)", color: "var(--v-err)" }}>{ev.errCode}</span></div>
                        <div style={{ display: "flex", flexDirection: "column", gap: "7px" }}>
                          <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>What failed</span><p style={{ margin: "2px 0 0", fontSize: "var(--fs-sm)", lineHeight: 1.45, color: "var(--tx)" }}>{ev.errWhat}</p></div>
                          <div style={{ display: "flex", gap: "14px" }}>
                            <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Target executed</span><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "2px" }}>{ev.errExec}</div></div>
                            <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Retry</span><div className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", marginTop: "2px" }}>{ev.errRetry}</div></div>
                          </div>
                          <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Evidence trust</span><p style={{ margin: "2px 0 0", fontSize: "var(--fs-sm)", lineHeight: 1.45, color: "var(--tx)" }}>{ev.errTrust}</p></div>
                        </div>
                      </div>
                    )}

                    {/* Human review / provenance footer */}
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "9px" }}>
                      <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Reproductions</span><div className="mono" style={{ fontSize: "var(--fs-lg)", fontWeight: 600, marginTop: "3px" }}>{ev.reproCount}</div></div>
                      <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Human review</span><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx)", marginTop: "3px" }}>{ev.humanState}</div></div>
                    </div>

                    {ev.showAction && (
                      <button onClick={ev.action} style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "7px", width: "100%", padding: "9px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", fontSize: "var(--fs-base)", fontWeight: 600 }}>
                        {ev.actionIconEl}{ev.actionLabel}
                      </button>
                    )}

                  </div>
                </section>
              )}

            </div>
          </>
        )}
      </div>
    </div>
  );
}
