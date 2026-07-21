/*
 * Mobile.tsx — faithful 1:1 port of the prototype MOBILE surface
 * (Headshot Console.dc.html lines 1512–2042, plus the in-surface node bottom-sheet
 * at 2008–2029). The model catalog (2046–2093) and attack-surface / target editor /
 * new-target / auth-probe drawers live in src/overlays/Overlays.tsx and are rendered
 * by the Shell alongside <Mobile/>; this file owns the mobile shell chrome, the 5-tab
 * bottom nav, every mobile tab body, the drill-ins (Live/Findings/Approvals/Attempt/
 * Target/Agent), the More menu, and the birdseye per-node bottom sheet.
 *
 * Production posture: NO device frame. The prototype's phone-frame chrome (status bar,
 * radial backdrop, rounded bezel) is prototype-only (surface==='mobile' && bp!=='sm');
 * when the real viewport is mobile (bp==='sm') we fill the viewport with
 * env(safe-area-inset-*). `core().mOuter` / `mFrame` already encode both variants, so
 * we consume them verbatim — the full-viewport branch drops the bezel.
 *
 * All state/logic comes from app.core() + app.birdseyeVM() + app.liveVM() +
 * app.findingsVM() + app.apprVM() + app.targetsVM() + app.agentsVM() + app.tracesVM()
 * + app.coverageVM() + app.resilienceVM() + app.costsVM(). We never re-implement logic,
 * numbers, or handlers — every onClick binds the SAME app method desktop binds
 * (openMFinding / openMApproval / openMAttempt / openMTarget / openMAgent / mBack /
 * toggleMPhase / selectNode / closeNode / setMTab-equivalents). Integration state drops
 * fabricated live numbers via the same scenario gating as desktop (liveVM.instr, birdseye).
 *
 * Four-side border rule (task rule #3): anything that re-renders on the demo tick and needs
 * a colored accent side uses borderTop/Right/Bottom (neutral) + borderLeft/Top (accent) —
 * never `border` shorthand + a side shorthand in the same style object.
 */
import type { ScreenProps } from "../types";

/* Parse the prototype's inline `style="a:b;c:d"` string (from core().mOuter / mFrame) into
 * a React style object so we can consume those two values verbatim. */
function parseStyle(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  s.split(";").forEach((decl) => {
    const i = decl.indexOf(":");
    if (i < 0) return;
    const rawKey = decl.slice(0, i).trim();
    const val = decl.slice(i + 1).trim();
    if (!rawKey || !val) return;
    const key = rawKey.replace(/-([a-z])/g, (_m, c) => c.toUpperCase());
    out[key] = val;
  });
  return out;
}

/* ================= LIVE ================= */
function MobileLive({ app }: ScreenProps) {
  const core = app.core();
  const live = app.liveVM();
  const be = app.birdseyeVM();
  const instr: any = live.instr;
  const camp: any = core.camp;

  return (
    <div style={{ padding: "14px 14px 20px", display: "flex", flexDirection: "column", gap: "13px" }}>
      {/* Birdseye / Attempt Stream segmented control */}
      <div style={{ position: "relative", display: "flex", border: "1px solid var(--bd)", borderRadius: "var(--r-lg)", overflow: "hidden", background: "var(--bg-inset)", padding: "3px" }} role="tablist" aria-label="Live mode">
        <span aria-hidden="true" style={{ position: "absolute", top: "3px", bottom: "3px", left: "3px", width: "calc(50% - 3px)", borderRadius: "calc(var(--r-lg) - 3px)", background: "var(--bg-raise)", boxShadow: "0 1px 3px -1px rgba(0,0,0,.4),inset 0 0 0 1px var(--bd)", transform: "translateX(" + be.liveThumbX + ")", transition: "transform .24s var(--ease-out)", zIndex: 0 }}></span>
        <button role="tab" aria-selected={be.liveBirdseye} onClick={be.setBirdseye} style={{ position: "relative", zIndex: 1, flex: 1, minHeight: "42px", display: "flex", alignItems: "center", justifyContent: "center", gap: "6px", fontSize: "var(--fs-base)", fontWeight: 600, background: "transparent", color: be.beFg }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"></path></svg>Birdseye</button>
        <button role="tab" aria-selected={be.liveStream} onClick={be.setStream} style={{ position: "relative", zIndex: 1, flex: 1, minHeight: "42px", fontSize: "var(--fs-base)", fontWeight: 600, background: "transparent", color: be.streamFg }}>Attempt Stream</button>
      </div>

      {/* Campaign instrument */}
      <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-xl)", padding: "15px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}><span className="mono" style={{ fontSize: "var(--fs-sm)", fontWeight: 600, color: "var(--brand)" }}>RUN 042</span><span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-xs)", color: core.campColor, marginLeft: "auto" }}><span style={{ width: "6px", height: "6px", borderRadius: "50%", background: core.campColor }}></span>{camp.state}</span></div>
        <div style={{ fontSize: "var(--fs-xl)", fontWeight: 600, marginTop: "6px" }}>Atlas Support Agent <span className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx3)", fontWeight: 400 }}>v1.4.2</span></div>
        <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)" }}>Staging · indirect injection · cross-tenant</div>
        <div style={{ marginTop: "13px" }}><div style={{ display: "flex", justifyContent: "space-between", fontSize: "var(--fs-sm)", marginBottom: "5px" }}><span className="lab">Budget</span><span className="mono" style={{ color: instr.budgetColor }}>{instr.used} / {instr.cap} · {instr.budgetPct}</span></div><div style={{ height: "6px", borderRadius: "3px", background: "var(--bg-inset)", overflow: "hidden" }}><div style={{ height: "100%", width: instr.budgetPct, background: instr.budgetColor }}></div></div></div>
        <div style={{ display: "flex", gap: "16px", marginTop: "14px" }}>
          <div><div className="mono" style={{ fontSize: "var(--fs-2xl)", fontWeight: 600, color: "var(--v-conf)" }}>{instr.cf}</div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>confirmed</span></div>
          <div><div className="mono" style={{ fontSize: "var(--fs-2xl)", fontWeight: 600, color: "var(--v-likely)" }}>{instr.likely}</div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>likely</span></div>
          <div><div className="mono" style={{ fontSize: "var(--fs-2xl)", fontWeight: 600, color: "var(--v-indet)" }}>{instr.indet}</div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>review</span></div>
        </div>
      </div>

      {be.liveBirdseye && (
        <>
          {/* System health */}
          <div style={{ display: "flex", alignItems: "center", gap: "9px", padding: "11px 13px", border: "1px solid var(--bd)", borderRadius: "var(--r-xl)", background: "var(--bg-panel)" }}>
            <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: be.sysHealthColor, flex: "0 0 auto" }}></span>
            <span style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: be.sysHealthColor }}>{be.sysHealthLabel}</span>
            <span className="lab" style={{ marginLeft: "auto", color: "var(--tx2)", textAlign: "right" }}>{be.sysHealthSub}</span>
          </div>

          {/* Execution pipeline chips */}
          <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-xl)", padding: "12px 13px", background: "var(--bg-panel)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px" }}><span className="lab">Execution pipeline</span><span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-xs)", fontWeight: 600, color: be.beMActiveColor, marginLeft: "auto" }}><span style={{ width: "6px", height: "6px", borderRadius: "50%", background: be.beMActiveColor, flex: "0 0 auto" }}></span>{be.beMActive}</span></div>
            <div style={{ display: "flex", gap: "6px" }}>
              {(be.mPhaseChips as any[]).map((c: any) => (
                <div key={c.id} style={{ flex: 1, minWidth: 0, borderRight: "1px solid var(--bd)", borderBottom: "1px solid var(--bd)", borderLeft: "1px solid var(--bd)", borderTop: "2px solid " + c.zoneColor, borderRadius: "var(--r-md)", padding: "7px 5px 8px", display: "flex", flexDirection: "column", alignItems: "center", gap: "5px", textAlign: "center" }}>
                  <span style={{ fontSize: "var(--fs-2xs)", fontWeight: 600, color: "var(--tx2)", maxWidth: "100%", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{c.short}</span>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "var(--fs-2xs)", fontWeight: 600, color: c.stateColor, maxWidth: "100%" }}><span style={{ width: "5px", height: "5px", borderRadius: "50%", background: c.stateColor, flex: "0 0 auto" }}></span><span style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{c.stateLabel}</span></span>
                </div>
              ))}
            </div>
          </div>

          {/* Attention */}
          {be.beHasAttn && (
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "9px" }}><span className="lab">Attention</span><span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--warn)" }}>{be.beAttnCount}</span></div>
              <div style={{ display: "flex", flexDirection: "column", gap: "9px" }}>
                {(be.beMAttn as any[]).map((a: any, i: number) => (
                  <button key={i} onClick={a.onClick} style={{ width: "100%", textAlign: "left", minHeight: "44px", borderTop: "1px solid var(--bd)", borderRight: "1px solid var(--bd)", borderBottom: "1px solid var(--bd)", borderLeft: "2.5px solid " + a.color, borderRadius: "var(--r-lg)", padding: "11px 12px", background: "var(--bg-panel)" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}><span style={{ color: a.color, display: "flex", flex: "0 0 auto" }}>{a.iconEl}</span><span style={{ fontSize: "var(--fs-sm)", fontWeight: 600, flex: 1, minWidth: 0 }}>{a.title}</span><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", flex: "0 0 auto" }}>{a.age}</span></div>
                    <div style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", lineHeight: 1.45 }}>{a.why}</div>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "6px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)", color: "var(--v-clear)" }}>{a.cont}</span><span className="lab" style={{ marginLeft: "auto", color: "var(--brand)", fontSize: "var(--fs-2xs)" }}>{a.action} ›</span></div>
                  </button>
                ))}
                {be.beMAttnHasMore && (<button onClick={be.toggleAttnAll} style={{ width: "100%", minHeight: "44px", textAlign: "center", fontSize: "var(--fs-xs)", fontWeight: 600, color: "var(--brand)", border: "1px dashed var(--bd)", borderRadius: "var(--r-lg)", background: "transparent" }}>{be.beMAttnMoreLabel}</button>)}
              </div>
            </div>
          )}

          {/* Phase details accordion */}
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "11px" }}><span className="lab">Phase details</span><span className="lab" style={{ marginLeft: "auto", color: "var(--tx3)", fontSize: "var(--fs-2xs)" }}>Tap a phase to expand</span></div>
            <div style={{ display: "flex", flexDirection: "column", gap: "9px" }}>
              {(be.mPhases as any[]).map((p: any) => (
                <div key={p.id} style={{ borderTop: "1px solid var(--bd)", borderRight: "1px solid var(--bd)", borderBottom: "1px solid var(--bd)", borderLeft: "3px solid " + p.zoneColor, borderRadius: "var(--r-xl)", overflow: "hidden" }}>
                  <button onClick={p.onToggle} aria-expanded={p.open} style={{ width: "100%", minHeight: "56px", display: "flex", alignItems: "center", gap: "10px", padding: "12px 13px", textAlign: "left", background: "transparent" }}>
                    <span style={{ color: p.stateColor, display: "flex", flex: "0 0 auto" }}>{p.stateIconEl}</span>
                    <div style={{ flex: 1, minWidth: 0 }}><div style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>{p.label}</div><div style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{p.summary}</div></div>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-2xs)", fontWeight: 600, color: p.stateColor, flex: "0 0 auto" }}><span style={{ width: "6px", height: "6px", borderRadius: "50%", background: p.stateColor }}></span>{p.stateLabel}</span>
                    <span style={{ display: "flex", color: "var(--tx3)", transform: "rotate(" + p.chevronRot + ")", flex: "0 0 auto" }}><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M6 9l6 6 6-6"></path></svg></span>
                  </button>
                  {p.open && (
                    <div style={{ padding: "0 11px 11px", display: "flex", flexDirection: "column", gap: "8px" }}>
                      {(p.nodes as any[]).map((n: any) => (
                        <div key={n.id} onClick={n.onClick} role="button" tabIndex={0} style={{ cursor: "pointer", borderTop: "1px solid var(--bd)", borderRight: "1px solid var(--bd)", borderBottom: "1px solid var(--bd)", borderLeft: "2.5px solid " + n.zoneColor, borderRadius: "var(--r-lg)", padding: "10px 11px", display: "flex", flexDirection: "column", gap: "5px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}><span style={{ color: n.zoneColor, display: "flex", flex: "0 0 auto" }}>{n.typeIconEl}</span><span style={{ fontSize: "var(--fs-base)", fontWeight: 600, flex: 1, minWidth: 0, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{n.name}</span><span style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "var(--fs-2xs)", fontWeight: 600, color: n.stateColor, flex: "0 0 auto" }}>{n.stateIconEl}{n.stateLabel}</span></div>
                          <div style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", lineHeight: 1.4 }}>{n.task}</div>
                          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{n.metricK} {n.metricV}</span>{n.cluster && (<span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{n.healthy}/{n.total} up</span>)}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          <span className="lab" style={{ alignSelf: "flex-start", display: "inline-flex", alignItems: "center", gap: "5px", padding: "3px 8px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-xs)", color: "var(--warn)", background: "var(--warn-t)", fontSize: "var(--fs-2xs)" }}>{be.scenarioTag}</span>
        </>
      )}

      {be.liveStream && (
        <>
          <button onClick={core.goApprovals} style={{ width: "100%", textAlign: "left", border: "1px solid var(--warn-line)", borderRadius: "var(--r-xl)", padding: "13px 14px", background: "var(--warn-t)", display: "flex", alignItems: "center", gap: "11px" }}>
            <svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="var(--warn)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto" }}><path d="M6.5 9a5.5 5.5 0 0 1 11 0c0 5.5 2.5 6 2.5 7.5H4C4 15 6.5 14.5 6.5 9z M10 20a2 2 0 0 0 4 0"></path></svg>
            <div style={{ flex: 1 }}><div style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: "var(--warn)" }}>{core.apprCount} need human attention</div><div style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>Tap to review the approval queue</div></div>
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M9 6l6 6-6 6"></path></svg>
          </button>
          <div>
            <span className="lab">Recent events</span>
            <div style={{ marginTop: "8px", border: "1px solid var(--bd)", borderRadius: "var(--r-xl)", overflow: "hidden" }}>
              {(live.mRows as any[]).map((a: any) => (
                <button key={a.id} onClick={a.mSelect} aria-label="Inspect attempt" style={{ width: "100%", textAlign: "left", display: "flex", alignItems: "center", gap: "9px", minHeight: "44px", padding: "10px 13px", borderBottom: "1px solid var(--sep)" }}>
                  <span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)", width: "48px" }}>{a.t}</span>
                  <span style={{ flex: 1, minWidth: 0, fontSize: "var(--fs-sm)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{a.catShort}</span>
                  {a.inProgress && (<span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--brand)" }}>{a.stageLabel}</span>)}
                  {a.resolved && (<span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-xs)", color: a.vColor }}><span style={{ width: "6px", height: "6px", borderRadius: a.vDotR, background: a.vColor }}></span>{a.vLabel}</span>)}
                  <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto" }}><path d="M9 6l6 6-6 6"></path></svg>
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

/* ================= FINDINGS (list) ================= */
function MobileFindings({ app }: ScreenProps) {
  const vm = app.findingsVM();
  return (
    <div style={{ padding: "16px 14px" }}>
      <div style={{ fontSize: "var(--fs-3xl)", fontWeight: 600, marginBottom: "13px" }}>Findings</div>
      <div style={{ display: "flex", flexDirection: "column", gap: "11px" }}>
        {(vm.fList as any[]).map((f: any) => (
          <button key={f.id} onClick={f.mOnClick} style={{ width: "100%", textAlign: "left", border: "1px solid var(--bd)", borderRadius: "var(--r-xl)", padding: "14px", background: "var(--bg-panel)", display: "flex", flexDirection: "column", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "9px" }}><span style={{ width: "9px", height: "9px", borderRadius: "2px", background: f.sevColor }}></span><span className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>{f.id}</span><span style={{ fontSize: "var(--fs-xs)", color: f.sevColor, fontWeight: 600 }}>{f.sevLabel}</span><div style={{ flex: 1 }}></div><span style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "3px 9px", borderRadius: "var(--r-sm)", fontSize: "var(--fs-xs)", fontWeight: 600, color: f.vColor, background: f.vTint, border: "1px solid " + f.vBorder }}>{f.vIconEl}{f.vLabel}</span></div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "var(--fs-xs)", color: "var(--tx2)" }}><span className="mono" style={{ fontSize: "var(--fs-2xs)", padding: "1px 4px", borderRadius: "3px", background: "var(--bg-inset)", color: "var(--tx3)" }}>{f.owasp}</span><span>{f.catShort}</span><div style={{ flex: 1 }}></div><span style={{ color: f.statusColor }}>{f.status}</span><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{f.age}</span></div>
          </button>
        ))}
      </div>
    </div>
  );
}

/* ================= APPROVALS (list) ================= */
function MobileApprovals({ app }: ScreenProps) {
  const core = app.core();
  const vm = app.apprVM();
  return (
    <div style={{ padding: "16px 14px" }}>
      <div style={{ fontSize: "var(--fs-3xl)", fontWeight: 600 }}>Approvals</div>
      <div style={{ fontSize: "var(--fs-base)", color: "var(--tx2)", margin: "2px 0 15px" }}>{core.apprCount} decisions need a human</div>
      {vm.aEmpty && (<div style={{ padding: "40px 12px", textAlign: "center", color: "var(--tx2)" }}><div style={{ fontSize: "var(--fs-md)", fontWeight: 600, marginBottom: "4px" }}>Queue clear</div><div style={{ fontSize: "var(--fs-sm)" }}>The campaign continues autonomously.</div></div>)}
      <div style={{ display: "flex", flexDirection: "column", gap: "11px" }}>
        {(vm.aList as any[]).map((q: any) => (
          <button key={q.id} onClick={q.mOnClick} style={{ width: "100%", textAlign: "left", border: "1px solid var(--bd)", borderRadius: "var(--r-xl)", padding: "14px", background: "var(--bg-panel)", display: "flex", flexDirection: "column", gap: "11px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ width: "24px", height: "24px", borderRadius: "var(--r-md)", background: "var(--bg-inset)", color: q.kindColor, display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}>{q.kindIconEl}</span>
              <span style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: q.kindColor }}>{q.kindLabel}</span>
              <div style={{ flex: 1 }}></div>
              <span className="mono" style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "var(--fs-xs)", color: "var(--warn)" }}><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M12 7.5v5l3 1.8"></path></svg>{q.sla}</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "9px" }}>
              <span className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>{q.fid}</span>
              <span style={{ width: "9px", height: "9px", borderRadius: "2px", background: q.sevColor }}></span>
              <span style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)" }}>{q.catShort}</span>
              <div style={{ flex: 1 }}></div>
              <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "3px 9px", borderRadius: "var(--r-sm)", fontSize: "var(--fs-xs)", fontWeight: 600, color: q.vColor, background: q.vTint, border: "1px solid " + q.vBorder }}>{q.vIconEl}{q.vLabel}</span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

/* ================= APPROVAL drill-in ================= */
function MobileApproval({ app }: ScreenProps) {
  const core = app.core();
  const vm = app.apprVM();
  const a: any = vm.aCurrent;
  if (!a) return null;
  return (
    <div style={{ display: "flex", flexDirection: "column", minHeight: "100%" }}>
      <div style={{ padding: "10px 14px 14px", borderBottom: "1px solid var(--sep)" }}>
        <button onClick={core.mBack} style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "var(--fs-base)", color: "var(--tx2)", padding: "6px 4px" }}><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M15 6l-6 6 6 6"></path></svg>Queue</button>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", margin: "8px 0 9px" }}><span style={{ width: "22px", height: "22px", borderRadius: "var(--r-sm)", background: "var(--bg-inset)", color: a.kindColor, display: "flex", alignItems: "center", justifyContent: "center" }}>{a.kindIconEl}</span><span className="lab" style={{ color: a.kindColor }}>{a.kindLabel}</span><div style={{ flex: 1 }}></div><span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--warn)" }}>SLA {a.sla}</span></div>
        <div style={{ fontSize: "var(--fs-md)", fontWeight: 600, marginBottom: "10px" }}>{a.requestText}</div>
        <div style={{ display: "flex", alignItems: "center", gap: "9px", marginBottom: "11px" }}><span className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: "var(--brand)" }}>{a.fid}</span><span style={{ width: "9px", height: "9px", borderRadius: "2px", background: a.sevColor }}></span><span style={{ fontSize: "var(--fs-sm)", fontWeight: 600, color: a.sevColor }}>{a.sevLabel}</span><span style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "3px 9px", borderRadius: "var(--r-sm)", fontSize: "var(--fs-xs)", fontWeight: 600, color: a.vColor, background: a.vTint, border: "1px solid " + a.vBorder }}>{a.vIconEl}{a.vLabel}</span></div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}><span style={{ padding: "3px 8px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>{a.target} {a.ver}</span><span style={{ padding: "3px 8px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>{a.confSource}</span><span style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "3px 8px", border: "1px solid " + a.integrityColor, borderRadius: "var(--r-xs)", fontSize: "var(--fs-xs)", fontWeight: 600, color: a.integrityColor }}>{a.integrity}</span></div>
      </div>
      <div style={{ flex: 1, padding: "14px", display: "flex", flexDirection: "column", gap: "12px" }}>
        <div style={{ borderTop: "1px solid var(--v-conf)", borderRight: "1px solid var(--v-conf)", borderBottom: "1px solid var(--v-conf)", borderLeft: "2.5px solid var(--v-conf)", borderRadius: "var(--r-md)", padding: "11px 12px", background: "var(--v-conf-t)" }}><span className="lab" style={{ color: "var(--v-conf)" }}>Impact</span><p style={{ margin: "5px 0 0", fontSize: "var(--fs-sm)", lineHeight: 1.5 }}>{a.impact}</p></div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "9px" }}><div><span className="lab" style={{ color: "var(--v-clear)" }}>Expected</span><p style={{ margin: "4px 0 0", fontSize: "var(--fs-xs)", lineHeight: 1.45, color: "var(--tx2)" }}>{a.expected}</p></div><div><span className="lab" style={{ color: "var(--v-conf)" }}>Observed</span><p style={{ margin: "4px 0 0", fontSize: "var(--fs-xs)", lineHeight: 1.45, color: "var(--tx2)" }}>{a.observed}</p></div></div>
        <div style={{ display: "flex", alignItems: "center", gap: "9px", padding: "10px 12px", border: "1px solid var(--bd)", borderRadius: "var(--r-md)", background: "var(--bg-inset)", fontSize: "var(--fs-sm)", color: "var(--tx2)" }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--tx2)" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a9 9 0 1 0 9 9 M21 3v5h-5"></path></svg>{a.reproCount}-step reproduction on file</div>
      </div>
      <div style={{ position: "sticky", bottom: 0, borderTop: "1px solid var(--sep)", background: "var(--bg-head)", padding: "11px 14px", display: "flex", flexDirection: "column", gap: "9px" }}>
        <span className="lab" style={{ color: "var(--tx3)", display: "flex", alignItems: "center", gap: "6px" }}><svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M5 20a7 7 0 0 1 14 0"></path></svg>A. Okafor · approver — launcher was M. Reyes</span>
        {a.blocked && (<div style={{ display: "flex", alignItems: "flex-start", gap: "8px", padding: "9px 11px", marginBottom: "9px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-md)", background: "var(--warn-t)", fontSize: "var(--fs-xs)", lineHeight: 1.4, color: "var(--tx)" }}>{a.blockReason}</div>)}
        <div style={{ display: "flex", gap: "8px" }}>{(a.acts as any[]).map((ac: any, i: number) => (<button key={i} onClick={ac.onClick} disabled={ac.disabled} aria-disabled={ac.disabled} style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: "13px 8px", borderRadius: "var(--r-lg)", fontSize: "var(--fs-sm)", fontWeight: 600, background: ac.bg, color: ac.fg, border: "1px solid " + ac.bd }}>{ac.label}</button>))}</div>
      </div>
    </div>
  );
}

/* ================= ATTEMPT drill-in ================= */
function MobileAttempt({ app }: ScreenProps) {
  const core = app.core();
  const live = app.liveVM();
  const sel: any = live.sel;
  const ev: any = live.ev;
  return (
    <div style={{ padding: "10px 14px 24px" }}>
      <button onClick={core.mBack} style={{ display: "inline-flex", alignItems: "center", gap: "4px", minHeight: "44px", fontSize: "var(--fs-base)", color: "var(--tx2)", padding: "6px 4px" }}><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M15 6l-6 6 6 6"></path></svg>Live</button>
      <div style={{ display: "flex", alignItems: "center", gap: "9px", margin: "8px 0 12px" }}><span className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: "var(--brand)" }}>{sel.id}</span><div style={{ flex: 1 }}></div><span style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "3px 10px", borderRadius: "var(--r-sm)", fontSize: "var(--fs-sm)", fontWeight: 600, color: ev.vColor, background: ev.vTint, border: "1px solid " + ev.vBorder }}>{ev.vIconEl}{ev.vLabel}</span></div>
      <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
        <div><span className="lab">Attack objective</span><p style={{ margin: "5px 0 0", fontSize: "var(--fs-base)", lineHeight: 1.5 }}>{sel.objective}</p><div style={{ marginTop: "7px" }}><span className="mono" style={{ fontSize: "var(--fs-2xs)", padding: "2px 6px", borderRadius: "var(--r-xs)", background: "var(--bg-inset)", color: "var(--tx2)" }}>{sel.owaspF} {sel.owaspId}</span></div></div>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}><span className="lab" style={{ color: "var(--tz-quar)" }}>Quarantined input</span><span className="lab" style={{ padding: "2px 6px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-xs)", color: "var(--warn)", background: "var(--warn-t)", fontSize: "var(--fs-2xs)" }}>Untrusted</span></div>
          <div style={{ border: "1px solid var(--warn-line)", borderRadius: "var(--r-md)", overflow: "hidden" }}>
            {sel.quarHidden && (<div style={{ padding: "16px 14px", textAlign: "center", background: "var(--bg-panel)" }}><button onClick={live.revealQuar} style={{ minHeight: "44px", padding: "8px 14px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-md)", background: "var(--warn-t)", color: "var(--warn)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Reveal payload</button></div>)}
            {sel.quarRevealed && (<div style={{ background: "var(--bg-inset)" }}><div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "6px 10px", borderBottom: "1px solid var(--warn-line)", background: "var(--warn-t)" }}><span className="lab" style={{ color: "var(--warn)", fontSize: "var(--fs-2xs)" }}>Quarantined · escaped</span><button onClick={live.copyQuar} aria-label="Copy quarantined content with warning" style={{ minHeight: "32px", padding: "2px 8px", color: "var(--warn)", fontSize: "var(--fs-2xs)" }}>Copy</button></div><pre className="mono" style={{ margin: 0, padding: "11px 12px", fontSize: "var(--fs-xs)", lineHeight: 1.55, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{sel.quarText}</pre></div>)}
          </div>
        </div>
        <div><span className="lab" style={{ color: "var(--tz-ext)" }}>Target response</span><pre className="mono" style={{ margin: "5px 0 0", padding: "10px 11px", borderTop: "1px solid var(--bd)", borderRight: "1px solid var(--bd)", borderBottom: "1px solid var(--bd)", borderLeft: "2.5px solid var(--tz-ext)", borderRadius: "var(--r-sm)", background: "var(--bg-inset)", fontSize: "var(--fs-xs)", lineHeight: 1.5, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{sel.resp}</pre></div>
        <div style={{ border: "1px solid " + ev.hashBorder, borderRadius: "var(--r-md)", padding: "11px 12px" }}><div style={{ display: "flex", alignItems: "center", gap: "8px" }}><span style={{ color: ev.hashColor, display: "flex" }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M6.5 10V7.5a5.5 5.5 0 0 1 11 0V10 M5 10h14v9.5A1.5 1.5 0 0 1 17.5 21h-11A1.5 1.5 0 0 1 5 19.5z"></path></svg></span><span style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Evidence integrity</span><span style={{ marginLeft: "auto", fontSize: "var(--fs-xs)", fontWeight: 600, color: ev.hashColor }}>{ev.hashLabel}</span></div><div className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", marginTop: "5px", wordBreak: "break-all" }}>{ev.hash} · {ev.recorder}</div></div>
        {ev.hashMismatch && (<div style={{ border: "1px solid var(--v-err)", borderRadius: "var(--r-md)", padding: "11px 12px", background: "var(--v-err-t)" }}><div style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: "var(--v-err)" }}>Verdict blocked — integrity failed</div><p style={{ margin: "6px 0 0", fontSize: "var(--fs-sm)", lineHeight: 1.5, color: "var(--tx2)" }}>Recomputed hash does not match; no judge verdict is authoritative until re-recorded.</p></div>)}
        <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "11px 12px" }}><div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}><span style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Verdict</span><span style={{ marginLeft: "auto", fontSize: "var(--fs-xs)", color: ev.vColor }}>{ev.provLine}</span></div><p style={{ margin: 0, fontSize: "var(--fs-sm)", lineHeight: 1.5, color: "var(--tx2)" }}>{ev.judgeRationale}</p></div>
      </div>
    </div>
  );
}

/* ================= FINDING drill-in ================= */
function MobileFinding({ app }: ScreenProps) {
  const core = app.core();
  const vm = app.findingsVM();
  const fd: any = vm.fd;
  return (
    <div style={{ padding: "10px 14px 20px" }}>
      <button onClick={core.mBack} style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "var(--fs-base)", color: "var(--tx2)", padding: "6px 4px" }}><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M15 6l-6 6 6 6"></path></svg>Findings</button>
      <div style={{ display: "flex", alignItems: "center", gap: "9px", margin: "9px 0 8px" }}><span className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: "var(--brand)" }}>{fd.id}</span><span style={{ width: "9px", height: "9px", borderRadius: "2px", background: fd.sevColor }}></span><span style={{ fontSize: "var(--fs-sm)", fontWeight: 600, color: fd.sevColor }}>{fd.sevLabel}</span><div style={{ flex: 1 }}></div><span style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "3px 10px", borderRadius: "var(--r-sm)", fontSize: "var(--fs-sm)", fontWeight: 600, color: fd.vColor, background: fd.vTint, border: "1px solid " + fd.vBorder }}>{fd.vIconEl}{fd.vLabel}</span></div>
      <div style={{ fontSize: "var(--fs-2xl)", fontWeight: 600, marginBottom: "4px" }}>{fd.title}</div>
      <div style={{ display: "flex", alignItems: "center", gap: "7px", fontSize: "var(--fs-sm)", color: "var(--tx2)", marginBottom: "15px" }}><span style={{ width: "5px", height: "5px", borderRadius: "50%", background: fd.vColor }}></span>{fd.prov}</div>
      <div style={{ display: "flex", flexDirection: "column", gap: "13px" }}>
        <div><span className="lab">Summary</span><p style={{ margin: "5px 0 0", fontSize: "var(--fs-base)", lineHeight: 1.5 }}>{fd.summary}</p></div>
        <div style={{ borderTop: "1px solid var(--v-conf)", borderRight: "1px solid var(--v-conf)", borderBottom: "1px solid var(--v-conf)", borderLeft: "2.5px solid var(--v-conf)", borderRadius: "var(--r-md)", padding: "11px 12px", background: "var(--v-conf-t)" }}><span className="lab" style={{ color: "var(--v-conf)" }}>Impact</span><p style={{ margin: "5px 0 0", fontSize: "var(--fs-sm)", lineHeight: 1.5 }}>{fd.impact}</p></div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "9px" }}><div><span className="lab" style={{ color: "var(--v-clear)" }}>Expected</span><p style={{ margin: "4px 0 0", fontSize: "var(--fs-xs)", lineHeight: 1.45, color: "var(--tx2)" }}>{fd.expected}</p></div><div><span className="lab" style={{ color: "var(--v-conf)" }}>Observed</span><p style={{ margin: "4px 0 0", fontSize: "var(--fs-xs)", lineHeight: 1.45, color: "var(--tx2)" }}>{fd.observed}</p></div></div>
        <div style={{ display: "flex", alignItems: "center", gap: "9px", padding: "10px 12px", border: "1px solid " + fd.hashColor, borderRadius: "var(--r-md)" }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke={fd.hashColor} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M6.5 10V7.5a5.5 5.5 0 0 1 11 0V10 M5 10h14v9.5A1.5 1.5 0 0 1 17.5 21h-11A1.5 1.5 0 0 1 5 19.5z"></path></svg><span style={{ fontSize: "var(--fs-sm)", fontWeight: 600, color: fd.hashColor }}>Evidence {fd.hashLabel}</span><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", marginLeft: "auto" }}>judge {fd.judgeScore}</span></div>
      </div>
    </div>
  );
}

/* ================= TARGETS (list) ================= */
function MobileTargets({ app }: ScreenProps) {
  const vm = app.targetsVM();
  return (
    <div style={{ padding: "16px 14px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "3px" }}><span style={{ fontSize: "var(--fs-3xl)", fontWeight: 600 }}>Targets</span><button onClick={vm.newTargetStart} style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: "5px", minHeight: "36px", padding: "0 13px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", border: "1px solid var(--brand)", fontSize: "var(--fs-sm)", fontWeight: 600 }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 5v14 M5 12h14"></path></svg>New</button></div>
      <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginBottom: "12px" }}>Lifecycle &amp; attack-surface management · credential values never shown</div>
      <div style={{ display: "flex", gap: "6px", overflowX: "auto", paddingBottom: "4px", marginBottom: "12px" }}>
        {(vm.tFilters as any[]).map((f: any) => (<button key={f.id} onClick={f.onClick} style={{ minHeight: "34px", padding: "0 13px", borderRadius: "var(--r-pill)", border: "1px solid var(--bd)", fontSize: "var(--fs-2xs)", fontWeight: 600, whiteSpace: "nowrap", flex: "0 0 auto", background: f.bg, color: f.fg }}>{f.label}</button>))}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
        {(vm.tList as any[]).map((t: any) => (
          <button key={t.id} onClick={t.mOnClick} aria-label="Manage target" style={{ width: "100%", textAlign: "left", minHeight: "56px", border: "1px solid var(--bd)", borderRadius: "var(--r-xl)", padding: "13px 14px", background: "var(--bg-panel)", display: "flex", alignItems: "center", gap: "11px" }}>
            <span style={{ width: "9px", height: "9px", borderRadius: "50%", background: t.eligColor, flex: "0 0 auto" }}></span>
            <span style={{ flex: 1, minWidth: 0 }}><span style={{ display: "block", fontSize: "var(--fs-md)", fontWeight: 500 }}>{t.name}</span><span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)" }}>{t.env} · {t.ver}</span></span>
            <span className="lab" style={{ padding: "2px 9px", borderRadius: "var(--r-pill)", background: t.lifeBg, color: t.lifeColor, fontSize: "var(--fs-2xs)", flex: "0 0 auto" }}>{t.lifeLabel}</span>
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto" }}><path d="M9 6l6 6-6 6"></path></svg>
          </button>
        ))}
      </div>
    </div>
  );
}

/* ================= TARGET drill-in (six tabs) ================= */
function MobileTarget({ app }: ScreenProps) {
  const core = app.core();
  const vm = app.targetsVM();
  const t: any = vm.tDet;
  return (
    <div style={{ padding: "10px 14px 28px" }}>
      <button onClick={core.mBack} style={{ display: "inline-flex", alignItems: "center", gap: "4px", minHeight: "44px", fontSize: "var(--fs-base)", color: "var(--tx2)", padding: "6px 4px" }}><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M15 6l-6 6 6 6"></path></svg>Targets</button>
      <div style={{ display: "flex", alignItems: "center", gap: "9px", margin: "6px 0 4px" }}><span style={{ fontSize: "var(--fs-2xl)", fontWeight: 600, flex: 1, minWidth: 0 }}>{t.name}</span><span className="lab" style={{ padding: "2px 9px", borderRadius: "var(--r-pill)", background: t.lifeBg, color: t.lifeColor, fontSize: "var(--fs-2xs)", flex: "0 0 auto" }}>{t.lifeLabel}</span></div>
      <div className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)", marginBottom: "11px" }}>{t.env} · {t.ver} · {t.adapter}</div>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", padding: "9px 12px", border: "1px solid " + t.eligColor, borderRadius: "var(--r-md)", marginBottom: "13px" }}><span style={{ width: "8px", height: "8px", borderRadius: "50%", background: t.eligColor, flex: "0 0 auto" }}></span><span style={{ fontSize: "var(--fs-sm)", fontWeight: 600, color: t.eligColor, flex: 1, minWidth: 0 }}>{t.eligLabel}</span><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", flex: "0 0 auto" }}>{t.enabledCount}/{t.surfaceCount} on</span></div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginBottom: "14px" }}>
        {(t.actions as any[]).map((a: any, i: number) => (<button key={i} onClick={a.onClick} style={{ flex: 1, minWidth: "44%", minHeight: "42px", padding: "0 12px", borderRadius: "var(--r-sm)", fontSize: "var(--fs-sm)", fontWeight: 600, background: a.bg, color: a.fg, border: "1px solid " + a.bd }}>{a.label}</button>))}
      </div>
      <div role="tablist" aria-label="Target sections" style={{ display: "flex", gap: "6px", overflowX: "auto", paddingBottom: "5px", marginBottom: "15px" }}>
        {(t.tabs as any[]).map((tb: any) => (<button key={tb.id} role="tab" aria-selected={tb.active} onClick={tb.onClick} style={{ minHeight: "36px", padding: "0 13px", borderRadius: "var(--r-pill)", border: "1px solid var(--bd)", fontSize: "var(--fs-sm)", fontWeight: 600, whiteSpace: "nowrap", flex: "0 0 auto", background: tb.pillBg, color: tb.pillFg }}>{tb.label}</button>))}
      </div>

      {t.tabOverview && (
        <>
          {t.hasBlockers && (<div style={{ marginBottom: "14px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-md)", background: "var(--warn-t)", padding: "11px 13px" }}><span className="lab" style={{ color: "var(--warn)" }}>Readiness blockers</span><div style={{ display: "flex", flexDirection: "column", gap: "5px", marginTop: "7px" }}>{(t.blockers as any[]).map((b: string, i: number) => (<div key={i} style={{ display: "flex", alignItems: "flex-start", gap: "8px", fontSize: "var(--fs-sm)", color: "var(--tx)" }}><span style={{ color: "var(--warn)", flex: "0 0 auto" }}>•</span>{b}</div>))}</div></div>)}
          <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", overflow: "hidden", marginBottom: "14px" }}>
            {(t.fields as any[]).map((f: any, i: number) => (<div key={i} style={{ display: "flex", alignItems: "center", gap: "10px", justifyContent: "space-between", padding: "10px 13px", borderBottom: "1px solid var(--sep)" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)", flex: "0 0 auto" }}>{f.k}</span><span className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx)", textAlign: "right", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis" }}>{f.v}</span></div>))}
          </div>
          <span className="lab">Readiness checklist</span>
          <div style={{ marginTop: "8px", border: "1px solid var(--bd)", borderRadius: "var(--r-md)", overflow: "hidden" }}>
            {(t.checks as any[]).map((c: any, i: number) => (<div key={i} style={{ display: "flex", alignItems: "flex-start", gap: "10px", padding: "11px 13px", borderBottom: "1px solid var(--sep)" }}><span style={{ width: "18px", height: "18px", borderRadius: "var(--r-xs)", background: "var(--bg-inset)", color: c.color, display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto", marginTop: "1px" }}>{c.iconEl}</span><div style={{ flex: 1 }}><span style={{ fontSize: "var(--fs-base)", fontWeight: 500 }}>{c.label}</span><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "1px" }}>{c.detail}</div></div></div>))}
          </div>
        </>
      )}

      {t.tabSurfaces && (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "11px" }}><span className="lab">Attack surfaces</span><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{t.enabledCount}/{t.surfaceCount} · versioned</span><button onClick={t.newSurface} style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: "5px", minHeight: "36px", padding: "0 12px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd-2)", background: "transparent", color: "var(--tx)", fontSize: "var(--fs-xs)", fontWeight: 600 }}><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 5v14 M5 12h14"></path></svg>Add</button></div>
          {t.surfaceCount > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: "9px" }}>
              {(t.surfaces as any[]).map((s: any) => (
                <div key={s.id} style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-lg)", padding: "12px 13px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "9px", marginBottom: "8px" }}><button onClick={s.onEdit} style={{ flex: 1, minWidth: 0, textAlign: "left", background: "transparent" }}><span style={{ display: "block", fontSize: "var(--fs-base)", fontWeight: 600, color: "var(--brand)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{s.name}</span><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{s.locator} · {s.ver}</span></button><button onClick={s.onToggle} role="switch" aria-checked={s.enabled} aria-label="Toggle surface" style={{ display: "inline-flex", alignItems: "center", gap: "5px", minHeight: "34px", padding: "0 11px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", fontSize: "var(--fs-2xs)", fontWeight: 600, color: s.enabledColor, background: "transparent", flex: "0 0 auto" }}><span style={{ width: "7px", height: "7px", borderRadius: "50%", background: s.enabledColor }}></span>{s.enabledLabel}</button></div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}><span style={{ fontSize: "var(--fs-2xs)", color: "var(--tx2)", padding: "2px 7px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)" }}>{s.typeLabel}</span><span style={{ fontSize: "var(--fs-2xs)", fontWeight: 600, color: s.riskColor, padding: "2px 7px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)" }}>{s.risk}</span><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", padding: "2px 7px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)" }}>{s.ow} · {s.ol}</span></div>
                </div>
              ))}
            </div>
          )}
          {t.noSurfaces && (<div style={{ border: "1px dashed var(--bd)", borderRadius: "var(--r-md)", padding: "22px", textAlign: "center", fontSize: "var(--fs-sm)", color: "var(--tx3)" }}>No attack surfaces yet. Add one to describe an endpoint, tool, RAG index, memory, file, or action to evaluate.</div>)}
        </>
      )}

      {t.tabControls && (
        <>
          <span className="lab">Target-level limits</span>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "9px", margin: "9px 0 13px" }}>
            <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 13px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Budget</span><div className="mono" style={{ fontSize: "var(--fs-md)", color: "var(--tx)", marginTop: "4px" }}>{t.budget}</div></div>
            <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 13px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Rate limit</span><div className="mono" style={{ fontSize: "var(--fs-md)", color: "var(--tx)", marginTop: "4px" }}>{t.rate}</div></div>
            <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 13px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Attempt cap</span><div className="mono" style={{ fontSize: "var(--fs-md)", color: "var(--tx)", marginTop: "4px" }}>{t.attemptCap}</div></div>
            <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 13px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Timeout</span><div className="mono" style={{ fontSize: "var(--fs-md)", color: "var(--tx)", marginTop: "4px" }}>{t.timeout}</div></div>
          </div>
          <div style={{ display: "flex", alignItems: "flex-start", gap: "9px", padding: "11px 13px", border: "1px solid var(--bd)", borderRadius: "var(--r-md)", background: "var(--bg-inset)", fontSize: "var(--fs-xs)", color: "var(--tx2)", lineHeight: 1.5 }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto", marginTop: "1px" }}><path d="M6.5 10V7.5a5.5 5.5 0 0 1 11 0V10 M5 10h14v9.5A1.5 1.5 0 0 1 17.5 21h-11A1.5 1.5 0 0 1 5 19.5z"></path></svg>Enforced server-side by the Policy Gateway — no UI control can exceed these caps.</div>
        </>
      )}

      {t.tabCredentials && (
        <>
          <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "13px 14px", marginBottom: "11px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Credential binding</span><div className="mono" style={{ fontSize: "var(--fs-md)", color: "var(--tx)", marginTop: "4px" }}>{t.cred}</div><div style={{ display: "flex", alignItems: "flex-start", gap: "7px", marginTop: "8px", fontSize: "var(--fs-xs)", color: "var(--tx3)", lineHeight: 1.45 }}><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto", marginTop: "1px" }}><path d="M6.5 10V7.5a5.5 5.5 0 0 1 11 0V10 M5 10h14v9.5A1.5 1.5 0 0 1 17.5 21h-11A1.5 1.5 0 0 1 5 19.5z"></path></svg>Reference only — the secret value is never entered, returned, or stored in the browser.</div></div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "9px" }}>
            <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 13px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Synthetic attestation</span><div style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: t.synthColor, marginTop: "4px" }}>{t.synthLabel}</div><div className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", marginTop: "4px" }}>{t.fixture}</div></div>
            <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 13px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Canary / reference</span><div className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "4px" }}>{t.canary}</div></div>
          </div>
        </>
      )}

      {t.tabAuthorization && (
        <div style={{ display: "flex", flexDirection: "column", gap: "11px" }}>
          <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "13px 14px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "9px" }}><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--v-clear)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto" }}><path d="M4 12l5 5 11-11"></path></svg><span style={{ fontSize: "var(--fs-md)", fontWeight: 600, flex: 1 }}>Structural validation</span><span style={{ fontSize: "var(--fs-sm)", fontWeight: 600, color: t.structuralColor }}>{t.structuralLabel}</span></div>
            <p style={{ margin: "8px 0 10px", fontSize: "var(--fs-sm)", color: "var(--tx2)", lineHeight: 1.5 }}>Local checks only — schema, allowlist, credential-reference, synthetic-data. Does not contact the target.</p>
            <button onClick={t.runStructural} style={{ width: "100%", minHeight: "42px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd-2)", background: "transparent", color: "var(--tx)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Run structural validation</button>
          </div>
          <div style={{ border: "1px solid " + t.connColor, borderRadius: "var(--r-md)", padding: "13px 14px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "9px" }}><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke={t.connColor} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto" }}><path d="M5 12.5a7 7 0 0 1 14 0 M8.5 15a3.5 3.5 0 0 1 7 0 M12 18h.01"></path></svg><span style={{ fontSize: "var(--fs-md)", fontWeight: 600, flex: 1 }}>Connectivity / preflight</span><span style={{ fontSize: "var(--fs-sm)", fontWeight: 600, color: t.connColor }}>{t.connLabel}</span></div>
            <p style={{ margin: "8px 0 10px", fontSize: "var(--fs-sm)", color: "var(--tx2)", lineHeight: 1.5 }}><strong>Live probing.</strong> Requires an approver distinct from the launcher; every authorization is audited.</p>
            {t.canAuthorize && (<button onClick={t.openAuthProbe} style={{ width: "100%", minHeight: "44px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", border: "1px solid var(--brand)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Authorize live probe</button>)}
            {t.probeAuthd && (<span style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "var(--fs-sm)", color: "var(--phos)" }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12l5 5 11-11"></path></svg>Authorized · logged</span>)}
          </div>
          <div style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)" }}>Authorization owner · {t.owner}</div>
        </div>
      )}

      {t.tabHistory && (
        <>
          <span className="lab">Audit history</span>
          <div style={{ marginTop: "9px", borderLeft: "2px solid var(--bd)", paddingLeft: "14px", display: "flex", flexDirection: "column", gap: "13px" }}>
            {(t.audit as any[]).map((a: any, i: number) => (<div key={i} style={{ position: "relative" }}><span style={{ position: "absolute", left: "-19px", top: "4px", width: "8px", height: "8px", borderRadius: "50%", background: "var(--brand)", border: "2px solid var(--bg-app)" }}></span><div style={{ display: "flex", alignItems: "baseline", gap: "9px", flexWrap: "wrap" }}><span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)", flex: "0 0 auto" }}>{a.t}</span><span style={{ fontSize: "var(--fs-sm)", fontWeight: 600 }}>{a.who}</span></div><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", lineHeight: 1.45, marginTop: "2px" }}>{a.ev}</div></div>))}
          </div>
        </>
      )}
    </div>
  );
}

/* ================= CONFIGURATION (list) ================= */
function MobileConfig({ app }: ScreenProps) {
  const vm = app.agentsVM();
  return (
    <div style={{ padding: "16px 14px" }}>
      <div style={{ fontSize: "var(--fs-3xl)", fontWeight: 600, marginBottom: "3px" }}>Configuration</div>
      <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginBottom: "13px" }}>Model-backed agents · <span style={{ color: "var(--warn)" }}>simulated catalog</span></div>
      <span className="lab">Model-backed agents</span>
      <div style={{ display: "flex", flexDirection: "column", gap: "10px", margin: "9px 0 18px" }}>
        {(vm.agentList as any[]).map((a: any) => (
          <button key={a.id} onClick={a.mOnClick} aria-label="Configure agent" style={{ width: "100%", textAlign: "left", borderTop: "1px solid var(--bd)", borderRight: "1px solid var(--bd)", borderBottom: "1px solid var(--bd)", borderLeft: "3px solid " + a.zoneColor, borderRadius: "var(--r-xl)", padding: "13px 14px", background: "var(--bg-panel)", display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ flex: 1, minWidth: 0 }}><span style={{ display: "flex", alignItems: "center", gap: "8px" }}><span style={{ fontSize: "var(--fs-md)", fontWeight: 600 }}>{a.name}</span>{a.uncal && (<span className="lab" style={{ padding: "1px 7px", borderRadius: "var(--r-xs)", background: "var(--warn-t)", color: "var(--warn)", fontSize: "var(--fs-2xs)" }}>Uncalibrated</span>)}{a.dirty && (<span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "var(--brand)" }}></span>)}</span><span className="mono" style={{ display: "block", fontSize: "var(--fs-xs)", color: "var(--tx3)", marginTop: "4px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{a.model}</span></span>
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto" }}><path d="M9 6l6 6-6 6"></path></svg>
          </button>
        ))}
      </div>
      <span className="lab">Deterministic — no model</span>
      <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "9px" }}>
        {(vm.detComps as any[]).map((d: any, i: number) => (
          <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: "10px", border: "1px solid var(--bd)", borderRadius: "var(--r-lg)", padding: "11px 13px", opacity: 0.9 }}>
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto", marginTop: "2px" }}><path d="M6.5 10V7.5a5.5 5.5 0 0 1 11 0V10 M5 10h14v9.5A1.5 1.5 0 0 1 17.5 21h-11A1.5 1.5 0 0 1 5 19.5z"></path></svg>
            <span style={{ flex: 1, minWidth: 0 }}><span style={{ display: "block", fontSize: "var(--fs-sm)", fontWeight: 600, color: "var(--tx2)" }}>{d.name}</span><span style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", lineHeight: 1.4 }}>{d.why}</span></span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ================= AGENT drill-in ================= */
function MobileAgent({ app }: ScreenProps) {
  const core = app.core();
  const vm = app.agentsVM();
  const a: any = vm.aDet;
  return (
    <div style={{ padding: "10px 14px 28px" }}>
      <button onClick={core.mBack} style={{ display: "inline-flex", alignItems: "center", gap: "4px", minHeight: "44px", fontSize: "var(--fs-base)", color: "var(--tx2)", padding: "6px 4px" }}><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M15 6l-6 6 6 6"></path></svg>Configuration</button>
      <div style={{ display: "flex", alignItems: "center", gap: "9px", margin: "6px 0 3px" }}><span style={{ width: "9px", height: "9px", borderRadius: "2px", background: a.zoneColor, flex: "0 0 auto" }}></span><span style={{ fontSize: "var(--fs-2xl)", fontWeight: 600, flex: 1, minWidth: 0 }}>{a.name}</span>{a.dirty && (<span className="lab" style={{ padding: "2px 8px", borderRadius: "var(--r-pill)", background: "var(--brand-tint)", color: "var(--brand)", fontSize: "var(--fs-2xs)", flex: "0 0 auto" }}>Unpublished</span>)}</div>
      <div className="lab" style={{ color: "var(--tx3)", marginBottom: "14px" }}>{a.role}</div>
      <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
        {/* Assigned model */}
        <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "13px 14px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "9px" }}><span className="lab">Assigned model</span><button onClick={a.openCatalog} style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: "6px", minHeight: "36px", padding: "0 12px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd-2)", background: "transparent", color: "var(--tx)", fontSize: "var(--fs-xs)", fontWeight: 600 }}><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M20 20l-3.2-3.2"></path></svg>Change</button></div>
          <div style={{ fontSize: "var(--fs-lg)", fontWeight: 600 }}>{a.modelName}</div>
          <div className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", marginTop: "2px", wordBreak: "break-all" }}>{a.modelId}</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "16px", marginTop: "10px" }}><div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Provider</span><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "2px" }}>{a.modelProvider}</div></div><div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Context</span><div className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "2px" }}>{a.modelCtx}</div></div><div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>$ in / out</span><div className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "2px" }}>{a.modelIn} / {a.modelOut}</div></div></div>
        </div>

        {/* Judge calibration */}
        {a.isJudge && (
          <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "13px 14px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "9px", marginBottom: "10px" }}><span className="lab">Judge calibration</span><span style={{ marginLeft: "auto", fontSize: "var(--fs-sm)", fontWeight: 600, color: a.calibColor }}>{a.calibLabel}</span></div>
            {a.judgeInvalid && (<div style={{ display: "flex", alignItems: "flex-start", gap: "8px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-md)", background: "var(--warn-t)", padding: "11px 13px", marginBottom: "11px" }}><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--warn)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto", marginTop: "1px" }}><path d="M12 3l9.5 17H2.5z M12 9.5v5 M12 17.5h.01"></path></svg><p style={{ margin: 0, fontSize: "var(--fs-sm)", color: "var(--tx)", lineHeight: 1.5 }}>Model, rubric, or threshold changed. Non-oracle cases <strong>fail closed to INDETERMINATE</strong> until a calibration result is recorded. Publishing does not recalibrate.</p></div>)}
            <span className="lab" style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)" }}>Simulate calibration result · review-only</span>
            <div style={{ display: "flex", gap: "9px", marginTop: "8px" }}><button onClick={a.calibPass} style={{ flex: 1, minHeight: "42px", borderRadius: "var(--r-sm)", border: "1px solid var(--phos)", background: "var(--phos-tint)", color: "var(--phos)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Record PASSING</button><button onClick={a.calibFail} style={{ flex: 1, minHeight: "42px", borderRadius: "var(--r-sm)", border: "1px solid var(--v-conf)", background: "var(--v-conf-t)", color: "var(--v-conf)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Record FAILED</button></div>
          </div>
        )}

        {/* Parameters */}
        <div>
          <span className="lab">Parameters</span>
          <div style={{ marginTop: "9px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "9px" }}>
            {(a.params as any[]).map((p: any, i: number) => (<div key={i} style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>{p.k}</span><div className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx)", marginTop: "3px" }}>{p.v}</div></div>))}
          </div>
          {a.isJudge && (<button onClick={a.judgeInvalidate} style={{ marginTop: "9px", width: "100%", minHeight: "40px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd-2)", background: "transparent", color: "var(--tx2)", fontSize: "var(--fs-xs)", fontWeight: 600 }}>Change threshold / rubric (invalidates calibration)</button>)}
        </div>

        {/* Fallback chain */}
        {a.hasFallback && (
          <div>
            <span className="lab">Fallback chain</span>
            <div style={{ marginTop: "6px", fontSize: "var(--fs-xs)", color: "var(--tx3)", marginBottom: "8px" }}>Explicit, ordered — never a silent provider switch.</div>
            <div style={{ display: "flex", flexDirection: "column", gap: "7px" }}>{(a.fallback as any[]).map((f: any, i: number) => (<div key={i} style={{ display: "flex", alignItems: "center", gap: "9px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}><span className="mono" style={{ width: "20px", height: "20px", borderRadius: "var(--r-xs)", background: "var(--bg-inset)", color: "var(--tx3)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "var(--fs-2xs)", flex: "0 0 auto" }}>{f.ord}</span><span style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)" }}>{f.name}</span></div>))}</div>
          </div>
        )}

        {/* Effective configuration */}
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "9px" }}><span className="lab">Effective configuration</span></div>
          <div style={{ display: "flex", gap: "6px", overflowX: "auto", paddingBottom: "4px", marginBottom: "10px" }}>{(a.scopes as any[]).map((s: any) => (<button key={s.label} onClick={s.onClick} style={{ minHeight: "34px", padding: "0 12px", borderRadius: "var(--r-pill)", border: "1px solid var(--bd)", fontSize: "var(--fs-2xs)", fontWeight: 600, whiteSpace: "nowrap", flex: "0 0 auto", background: s.bg, color: s.fg }}>{s.label}</button>))}</div>
          <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", overflow: "hidden" }}>{(a.effRows as any[]).map((r: any, i: number) => (<div key={i} style={{ padding: "10px 12px", borderBottom: "1px solid var(--sep)" }}><div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "9px" }}><span style={{ fontSize: "var(--fs-sm)", color: "var(--tx)" }}>{r.k}</span><span className="mono" style={{ fontSize: "var(--fs-sm)", fontWeight: 600, color: "var(--tx)" }}>{r.eff}</span></div>{r.lock && (<div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "5px", fontSize: "var(--fs-2xs)", color: "var(--warn)" }}><svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M7 10V7.5a5 5 0 0 1 10 0V10 M5.5 10h13v9h-13z"></path></svg>{r.lock}</div>)}</div>))}</div>
        </div>

        {/* Activation / publish */}
        <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "14px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "9px", marginBottom: "11px" }}><span className="lab">Activation</span><span className="lab" style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)" }}>draft → review → active next campaign</span></div>
          {a.pubActive && (<div style={{ display: "flex", alignItems: "flex-start", gap: "9px", padding: "11px 13px", border: "1px solid var(--phos)", borderRadius: "var(--r-md)", background: "var(--phos-tint)" }}><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--phos)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto", marginTop: "1px" }}><path d="M4 12l5 5 11-11"></path></svg><span style={{ fontSize: "var(--fs-sm)", color: "var(--tx)", lineHeight: 1.5 }}>Published as an immutable snapshot — active <strong>on the next campaign only</strong>. The running campaign is never mutated.</span></div>)}
          {a.pubIdle && (
            <>
              {a.canPublish && (
                <>
                  <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginBottom: "9px", lineHeight: 1.5 }}>Publishing requires a rationale and produces an audit event. Non-optimistic — applies only after backend acknowledgement.</div>
                  <textarea value={a.pubRationale} onInput={a.onRationale} placeholder="Rationale for this change (required)" aria-label="Publication rationale" style={{ width: "100%", boxSizing: "border-box", minHeight: "70px", resize: "vertical", background: "var(--bg-inset)", border: "1px solid " + (a.pubErr ? "var(--v-conf)" : "var(--bd)"), borderRadius: "var(--r-sm)", padding: "10px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", fontFamily: "inherit", outline: "none" }}></textarea>
                  {a.pubErr && (<div style={{ fontSize: "var(--fs-xs)", color: "var(--v-conf)", marginTop: "5px" }}>A rationale is required before publishing.</div>)}
                  <button onClick={a.validate} style={{ marginTop: "10px", width: "100%", minHeight: "44px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", border: "1px solid var(--brand)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Validate &amp; review</button>
                </>
              )}
              {a.noPublish && (<div style={{ fontSize: "var(--fs-sm)", color: "var(--tx3)", lineHeight: 1.5 }}>No pending changes. Publish becomes available after you stage a model or parameter change.</div>)}
            </>
          )}
          {a.pubValidating && (<div style={{ display: "flex", alignItems: "center", gap: "9px", fontSize: "var(--fs-sm)", color: "var(--tx2)" }}><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--brand)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ animation: "hs-spin 1s linear infinite" }}><path d="M12 3a9 9 0 1 0 9 9"></path></svg>Validating configuration…</div>)}
          {a.pubReview && (<><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx)", marginBottom: "10px", lineHeight: 1.5 }}>Validation passed. Confirm to publish — audited and active on the next campaign.</div><button onClick={a.publish} style={{ width: "100%", minHeight: "44px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", border: "1px solid var(--brand)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Confirm &amp; publish</button></>)}
          {a.pubPublished && (<div style={{ display: "flex", alignItems: "center", gap: "9px", fontSize: "var(--fs-sm)", color: "var(--tx2)" }}><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--brand)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ animation: "hs-spin 1s linear infinite" }}><path d="M12 3a9 9 0 1 0 9 9"></path></svg>Publishing… awaiting acknowledgement</div>)}
        </div>
      </div>
    </div>
  );
}

/* ================= MORE ================= */
function MobileMore({ app }: ScreenProps) {
  const core = app.core();
  return (
    <div style={{ padding: "16px 14px" }}>
      <div style={{ fontSize: "var(--fs-3xl)", fontWeight: 600, marginBottom: "14px" }}>More</div>
      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
        {(core.moreItems as any[]).map((m: any) => (
          <button key={m.label} onClick={m.onClick} style={{ width: "100%", textAlign: "left", minHeight: "52px", border: "1px solid var(--bd)", borderRadius: "var(--r-xl)", padding: "14px", background: "var(--bg-panel)", display: "flex", alignItems: "center", gap: "12px" }}>
            <span style={{ width: "30px", height: "30px", borderRadius: "var(--r-md)", background: "var(--bg-inset)", color: "var(--tx2)", display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}>{m.iconEl}</span>
            <span style={{ flex: 1, fontSize: "var(--fs-md)", fontWeight: 500 }}>{m.label}</span>
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M9 6l6 6-6 6"></path></svg>
          </button>
        ))}
      </div>
      <div style={{ marginTop: "14px", padding: "11px 13px", border: "1px solid var(--bd)", borderRadius: "var(--r-lg)", background: "var(--bg-inset)" }}><span className="lab" style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)", lineHeight: 1.5, display: "block" }}>Prototype controls — theme, density, desktop/mobile preview, principal switching, and failure simulation — are review-only and live in the desktop shell.</span></div>
    </div>
  );
}

/* ================= COVERAGE ================= */
function MobileCoverage({ app }: ScreenProps) {
  const vm = app.coverageVM();
  return (
    <div style={{ padding: "16px 14px" }}>
      <div style={{ fontSize: "var(--fs-3xl)", fontWeight: 600, marginBottom: "3px" }}>Coverage</div>
      <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginBottom: "14px" }}>{vm.covTested} tested · {vm.covPartial} partial · {vm.covUntested} untested</div>
      <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-xl)", overflow: "hidden" }}>
        {(vm.covRows as any[]).map((c: any, i: number) => (<div key={i} style={{ display: "flex", alignItems: "center", gap: "9px", padding: "11px 13px", borderBottom: "1px solid var(--sep)", background: c.rowBg }}><span className="mono" style={{ fontSize: "var(--fs-2xs)", padding: "1px 5px", borderRadius: "3px", background: "var(--bg-inset)", color: "var(--tx2)", flex: "0 0 auto" }}>{c.tag}</span><span style={{ flex: 1, minWidth: 0, fontSize: "var(--fs-sm)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{c.name}</span><span style={{ padding: "2px 8px", borderRadius: "var(--r-xs)", fontSize: "var(--fs-2xs)", fontWeight: 600, color: c.stColor, background: c.stBg, border: "1px solid " + c.stColor, flex: "0 0 auto" }}>{c.stLabel}</span></div>))}
      </div>
    </div>
  );
}

/* ================= RESILIENCE ================= */
function MobileResilience({ app }: ScreenProps) {
  const vm = app.resilienceVM();
  return (
    <div style={{ padding: "16px 14px" }}>
      <div style={{ fontSize: "var(--fs-3xl)", fontWeight: 600, marginBottom: "3px" }}>Resilience</div>
      <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginBottom: "14px" }}>Exploit rate across target versions</div>
      <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-xl)", padding: "14px", marginBottom: "14px" }}>
        <div style={{ display: "flex", alignItems: "flex-end", gap: "10px", height: "118px", borderBottom: "1px solid var(--bd)" }}>
          {(vm.resVersions as any[]).map((v: any, i: number) => (<div key={i} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "flex-end", height: "100%" }}><div style={{ display: "flex", alignItems: "flex-end", gap: "4px", height: "96px" }}><div style={{ width: "14px", height: v.confH, background: "var(--v-conf)", borderRadius: "3px 3px 0 0" }}></div><div style={{ width: "14px", height: v.likelyH, background: "var(--v-likely)", borderRadius: "3px 3px 0 0" }}></div></div></div>))}
        </div>
        <div style={{ display: "flex", gap: "10px", marginTop: "6px" }}>{(vm.resVersions as any[]).map((v: any, i: number) => (<div key={i} style={{ flex: 1, textAlign: "center" }}><div className="mono" style={{ fontSize: "var(--fs-xs)", fontWeight: 600 }}>{v.v}</div><div className="mono" style={{ fontSize: "var(--fs-2xs)", color: v.nColor }}>n={v.n}</div></div>))}</div>
      </div>
      <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-xl)", overflow: "hidden" }}>
        {(vm.resCats as any[]).map((c: any, i: number) => (<div key={i} style={{ display: "flex", alignItems: "center", gap: "9px", padding: "10px 13px", borderBottom: "1px solid var(--sep)" }}><span style={{ flex: 1, minWidth: 0, fontSize: "var(--fs-sm)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{c.name}</span><span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)" }}>{c.prev}→{c.now}</span><span className="mono" style={{ fontSize: "var(--fs-xs)", fontWeight: 600, color: c.deltaColor, width: "60px", textAlign: "right" }}>{c.delta}</span></div>))}
      </div>
    </div>
  );
}

/* ================= TRACES ================= */
function MobileTraces({ app }: ScreenProps) {
  const vm = app.tracesVM();
  const h: any = vm.trHeader;
  const sel: any = vm.trSel;
  return (
    <div style={{ padding: "16px 14px" }}>
      <div style={{ fontSize: "var(--fs-3xl)", fontWeight: 600, marginBottom: "3px" }}>Agent trace</div>
      <div className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", marginBottom: "14px" }}>{h.run} · {h.attempt} · {h.total}</div>
      <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-xl)", overflow: "hidden" }}>
        {(vm.trSpans as any[]).map((s: any) => (<button key={s.id} onClick={s.onClick} style={{ width: "100%", textAlign: "left", minHeight: "44px", display: "flex", alignItems: "center", gap: "10px", padding: "10px 13px", borderBottom: "1px solid var(--sep)", background: s.rowBg }}><span style={{ width: "3px", alignSelf: "stretch", borderRadius: "2px", background: s.zoneColor, flex: "0 0 auto" }}></span><span style={{ flex: 1, minWidth: 0 }}><span style={{ display: "block", fontSize: "var(--fs-sm)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{s.label}</span><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>{s.agent}</span></span><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx2)" }}>{s.dur}</span><span style={{ width: "8px", height: "8px", borderRadius: "50%", background: s.statusColor, flex: "0 0 auto" }}></span></button>))}
      </div>
      <div style={{ marginTop: "12px", border: "1px solid var(--bd)", borderRadius: "var(--r-xl)", padding: "14px" }}><div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}><span style={{ width: "3px", height: "16px", borderRadius: "2px", background: sel.zoneColor }}></span><span style={{ fontSize: "var(--fs-md)", fontWeight: 600 }}>{sel.label}</span></div><p style={{ margin: "0 0 8px", fontSize: "var(--fs-sm)", lineHeight: 1.5, color: "var(--tx2)" }}>{sel.desc}</p><div className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{sel.dur} · {sel.tokens} · {sel.cost} · {sel.corr}</div></div>
    </div>
  );
}

/* ================= COSTS ================= */
function MobileCosts({ app }: ScreenProps) {
  const vm = app.costsVM();
  return (
    <div style={{ padding: "16px 14px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "14px" }}><span style={{ fontSize: "var(--fs-3xl)", fontWeight: 600 }}>Cost &amp; budget</span><span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: "6px", padding: "3px 9px", borderRadius: "var(--r-xs)", fontSize: "var(--fs-xs)", fontWeight: 600, color: vm.coStateColor, border: "1px solid " + vm.coStateColor }}>{vm.coState}</span></div>
      <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-xl)", padding: "14px", marginBottom: "14px" }}><div style={{ display: "flex", alignItems: "baseline", gap: "8px" }}><span className="mono" style={{ fontSize: "var(--fs-4xl)", fontWeight: 600, color: vm.coBudgetColor }}>{vm.coUsed}</span><span className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx3)" }}>/ {vm.coCap} · {vm.coPct}</span></div><div style={{ height: "6px", borderRadius: "3px", background: "var(--bg-inset)", overflow: "hidden", marginTop: "9px" }}><div style={{ height: "100%", width: vm.coPct, background: vm.coBudgetColor }}></div></div><div className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", marginTop: "8px" }}>{vm.coBurn}/hr · proj cap {vm.coProj}</div></div>
      <span className="lab">Spend by agent</span>
      <div style={{ marginTop: "10px", display: "flex", flexDirection: "column", gap: "9px" }}>
        {(vm.coAgents as any[]).map((a: any, i: number) => (<div key={i}><div style={{ display: "flex", justifyContent: "space-between", fontSize: "var(--fs-sm)", marginBottom: "4px" }}><span>{a.k}</span><span className="mono" style={{ color: "var(--tx2)" }}>{a.v}</span></div><div style={{ height: "6px", borderRadius: "3px", background: "var(--bg-inset)", overflow: "hidden" }}><div style={{ height: "100%", width: a.w, background: a.c }}></div></div></div>))}
      </div>
      <div style={{ display: "flex", gap: "10px", marginTop: "14px" }}><div style={{ flex: 1, border: "1px solid var(--bd)", borderRadius: "var(--r-lg)", padding: "11px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Retry cost</span><div className="mono" style={{ fontSize: "var(--fs-xl)", fontWeight: 600, color: "var(--warn)", marginTop: "4px" }}>{vm.coRetry}</div></div><div style={{ flex: 1, border: "1px solid var(--bd)", borderRadius: "var(--r-lg)", padding: "11px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Low-signal</span><div className="mono" style={{ fontSize: "var(--fs-xl)", fontWeight: 600, marginTop: "4px" }}>{vm.coLow}</div></div></div>
    </div>
  );
}

/* ================= NODE bottom-sheet (birdseye per-node) ================= */
function MobileNodeSheet({ app }: ScreenProps) {
  const be = app.birdseyeVM();
  const s: any = be.beSheet;
  return (
    <>
      <div onClick={be.closeNode} aria-hidden="true" style={{ position: "absolute", inset: 0, zIndex: 40, background: "var(--scrim)" }}></div>
      <div role="dialog" aria-modal="true" aria-label="Component detail" data-overlay="1" style={{ position: "absolute", left: 0, right: 0, bottom: 0, zIndex: 41, maxHeight: "84%", display: "flex", flexDirection: "column", background: "var(--bg-panel)", borderTop: "1px solid var(--bd)", borderRadius: "18px 18px 0 0", boxShadow: "var(--shadow)", animation: "hs-sheet .26s var(--ease-drawer)" }}>
        <div style={{ flex: "0 0 auto", display: "flex", justifyContent: "center", padding: "8px 0 2px" }}><span style={{ width: "36px", height: "4px", borderRadius: "2px", background: "var(--bd-2)" }}></span></div>
        <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "10px", padding: "8px 14px 12px", borderBottom: "1px solid var(--sep)" }}>
          <span style={{ color: s.zoneColor, display: "flex", flex: "0 0 auto" }}>{s.typeIconEl}</span>
          <div style={{ flex: 1, minWidth: 0 }}><div style={{ fontSize: "var(--fs-lg)", fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{s.name}</div><div style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-2xs)", fontWeight: 600, color: s.stateColor, marginTop: "2px" }}>{s.stateIconEl}{s.stateLabel}</div></div>
          <button onClick={be.closeNode} aria-label="Close detail" style={{ width: "44px", height: "44px", flex: "0 0 auto", display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "transparent", color: "var(--tx2)" }}><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M6 6l12 12 M18 6L6 18"></path></svg></button>
        </div>
        <div style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "14px", display: "flex", flexDirection: "column", gap: "14px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}><span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-2xs)", fontWeight: 600, color: s.zoneColor, border: "1px solid " + s.zoneColor, borderRadius: "var(--r-xs)", padding: "2px 7px" }}>{s.zoneLabel}</span><span className="lab" style={{ color: s.availColor, fontSize: "var(--fs-2xs)" }}>{s.availLabel}</span></div>
          <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", lineHeight: 1.5 }}>{s.purpose}</div>
          <div><span className="lab">Current task</span><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx)", marginTop: "5px", lineHeight: 1.45 }}>{s.task}</div></div>
          {s.hasModel && (<div><span className="lab">Assigned model</span><div className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", marginTop: "5px", wordBreak: "break-all" }}>{s.model}</div></div>)}
          <div><span className="lab">Health</span><div style={{ marginTop: "7px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
            <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "9px 11px" }}><div className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Last seen</div><div className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600, marginTop: "3px" }}>{s.hb}</div></div>
            <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "9px 11px" }}><div className="lab" style={{ fontSize: "var(--fs-2xs)" }}>p50</div><div className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600, marginTop: "3px" }}>{s.p50}</div></div>
          </div></div>
          {s.hasRel && (<div><span className="lab">Related</span><div style={{ marginTop: "8px", display: "flex", flexWrap: "wrap", gap: "7px" }}>{(s.relAtt as any[]).map((r: any) => (<button key={r.id} onClick={r.onClick} className="mono" style={{ minHeight: "34px", fontSize: "var(--fs-2xs)", color: "var(--brand)", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", padding: "5px 10px", background: "transparent" }}>{r.id}</button>))}{(s.relFind as any[]).map((r: any) => (<button key={r.id} onClick={r.onClick} className="mono" style={{ minHeight: "34px", fontSize: "var(--fs-2xs)", color: "var(--v-conf)", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", padding: "5px 10px", background: "transparent" }}>{r.id}</button>))}</div></div>)}
        </div>
      </div>
    </>
  );
}

/* ================= ROOT ================= */
export function Mobile({ app }: ScreenProps) {
  const core = app.core();
  const be = app.birdseyeVM();

  const phoneFrame: boolean = core.phoneFrame;
  const campAborted: boolean = core.campAborted;
  const mNodeSheet: boolean = be.mNodeSheet;

  const mViewNone: boolean = core.mViewNone;
  const screenLabel = ((app.nav as any[]).find((n) => n.id === app.state.screen) || {}).label || "Console";

  return (
    <div style={parseStyle(core.mOuter as string)}>
      <div style={parseStyle(core.mFrame as string)}>

        {/* Prototype-only phone status bar (surface preview) — dropped on real mobile viewport */}
        {phoneFrame && (
          <div style={{ flex: "0 0 auto", height: "42px", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 24px", position: "relative" }}>
            <span className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>2:47</span>
            <span style={{ position: "absolute", left: "50%", top: "9px", transform: "translateX(-50%)", width: "74px", height: "20px", borderRadius: "var(--r-xl)", background: "var(--bg-inset)" }}></span>
            <span style={{ display: "flex", alignItems: "center", gap: "7px" }}><span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "var(--phos)" }}></span><svg viewBox="0 0 24 14" width="22" height="13" fill="none"><rect x="1" y="2" width="18" height="10" rx="2.5" stroke="var(--tx2)" strokeWidth="1.3"></rect><rect x="3" y="4" width="12" height="6" rx="1" fill="var(--tx2)"></rect><path d="M21 5v4" stroke="var(--tx2)" strokeWidth="1.6" strokeLinecap="round"></path></svg></span>
          </div>
        )}

        {/* App header */}
        <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "9px", padding: "4px 16px 12px", borderBottom: "1px solid var(--sep)" }}>
          <svg width="22" height="22" viewBox="0 0 32 32" fill="none" aria-hidden="true"><rect x="6" y="5.4" width="6" height="9" rx="2.6" fill="currentColor" /><rect x="6" y="17.6" width="6" height="9" rx="2.6" fill="currentColor" /><rect x="20" y="5.4" width="6" height="9" rx="2.6" fill="currentColor" /><rect x="20" y="17.6" width="6" height="9" rx="2.6" fill="currentColor" /><rect x="11" y="14.6" width="10" height="2.8" rx="1.4" fill="currentColor" opacity=".5" /><circle cx="16" cy="16" r="2.5" fill="var(--phos)" /></svg>
          <span style={{ fontSize: "var(--fs-lg)", fontWeight: 600 }}>Headshot</span>
          <div style={{ flex: 1 }}></div>
          <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "3px 8px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)" }}><span style={{ width: "5px", height: "5px", borderRadius: "50%", background: "var(--phos)" }}></span><span className="mono" style={{ fontSize: "var(--fs-xs)", fontWeight: 600 }}>RUN 042</span></span>
          <button onClick={core.openAbort} aria-label="Abort campaign RUN 042" disabled={campAborted} style={{ width: "44px", height: "44px", border: "1px solid var(--v-conf)", borderRadius: "var(--r-lg)", color: "var(--v-conf)", opacity: core.abortMobileOpacity as number, display: "flex", alignItems: "center", justifyContent: "center" }}><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M8.5 3h7l5 5v7l-5 5h-7l-5-5V8z M9.5 12h5"></path></svg></button>
        </div>

        {/* Scrollable body */}
        <div role="main" aria-label={screenLabel} style={{ flex: 1, minHeight: 0, overflowY: "auto", position: "relative" }}>
          {mViewNone && (
            <>
              {core.mTabApprovals && <MobileApprovals app={app} />}
              {core.mTabLive && <MobileLive app={app} />}
              {core.mTabFindings && <MobileFindings app={app} />}
              {core.mTargetsList && <MobileTargets app={app} />}
              {core.mConfigList && <MobileConfig app={app} />}
              {core.mMore && <MobileMore app={app} />}
              {core.mTabCoverage && <MobileCoverage app={app} />}
              {core.mTabResilience && <MobileResilience app={app} />}
              {core.mTabTraces && <MobileTraces app={app} />}
              {core.mTabCosts && <MobileCosts app={app} />}
            </>
          )}

          {core.mViewApproval && <MobileApproval app={app} />}
          {core.mViewAttempt && <MobileAttempt app={app} />}
          {core.mViewFinding && <MobileFinding app={app} />}
          {core.mViewTarget && <MobileTarget app={app} />}
          {core.mViewAgent && <MobileAgent app={app} />}
        </div>

        {/* Birdseye per-node bottom sheet */}
        {mNodeSheet && <MobileNodeSheet app={app} />}

        {/* 5-tab bottom nav — extends into the home-indicator area (safe-area-inset-bottom) so the
            panel background fills it while the 62px of tappable content stays above the inset. */}
        <nav aria-label="Primary" style={{ flex: "0 0 auto", height: "calc(62px + env(safe-area-inset-bottom, 0px))", paddingBottom: "env(safe-area-inset-bottom, 0px)", borderTop: "1px solid var(--sep)", background: "var(--bg-panel)", display: "flex" }}>
          {(core.mNav as any[]).map((t: any) => (
            <button key={t.id} onClick={t.onClick} aria-current={t.active ? "page" : undefined} aria-label={t.hasBadge ? t.label + ", " + t.badge + " pending" : t.label} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: "3px", color: t.color, position: "relative" }}>
              {t.hasBadge && (<span aria-hidden="true" className="mono" style={{ position: "absolute", top: "8px", left: "calc(50% + 8px)", minWidth: "15px", height: "15px", padding: "0 4px", borderRadius: "var(--r-md)", background: "var(--warn)", color: "var(--tx-inv)", fontSize: "var(--fs-2xs)", fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center" }}>{t.badge}</span>)}
              <span style={{ display: "flex" }}>{t.iconEl}</span>
              <span style={{ fontSize: "var(--fs-2xs)", fontWeight: 600 }}>{t.label}</span>
            </button>
          ))}
        </nav>

      </div>
    </div>
  );
}
