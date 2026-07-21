/*
 * Targets — faithful port of the TARGETS screen (Headshot Console.dc.html lines 1261–1396).
 *
 * Target registry list + six-tab detail (Overview / Attack surfaces / Controls / Credentials /
 * Authorization / History). Lifecycle DRAFT→VALIDATING→READY→DISABLED(+ARCHIVED). Structural
 * validation is local; connectivity/preflight needs an approver≠launcher probe authorization.
 * Credentials are shown by reference only.
 *
 * Data + handlers come from app.targetsVM() (App.tsx `targetsVM`), which mirrors the prototype's
 * render context: tList, tDet, tFilters, tQuery, onTQuery, newTargetStart. The surface-editor
 * drawer / new-target flow / edit drawer / probe-authorization are OVERLAYS — this screen only
 * renders the list+detail and triggers them (openSurface / openSurfaceNew / openEditTarget /
 * newTargetStart / openAuthProbe).
 *
 * <sc-if isTargets> is handled upstream (Shell routes here only when screen === "targets"), so
 * this component renders the inner content directly, starting at the data-screen-label wrapper.
 */
import type { ScreenProps } from "../types";

export function Targets({ app }: ScreenProps) {
  const vm = app.targetsVM();
  const tList = vm.tList as any[];
  const tDet = vm.tDet as any;
  const tFilters = vm.tFilters as any[];

  return (
    <div data-screen-label="Targets" style={{ flex: 1, minHeight: 0, overflow: "hidden" }}>
      <div style={{ height: "100%", minWidth: 0, display: "flex", flexDirection: "column" }}>
        <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "12px", padding: "13px 18px", borderBottom: "1px solid var(--bd)" }}>
          <span style={{ fontSize: "var(--fs-2xl)", fontWeight: 600 }}>Target registry</span>
          <span className="lab" style={{ color: "var(--tx3)" }}>Lifecycle &amp; attack-surface management</span>
          <div style={{ flex: 1 }}></div>
          <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "6px", color: "var(--tx3)" }}>
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M6.5 10V7.5a5.5 5.5 0 0 1 11 0V10 M5 10h14v9.5A1.5 1.5 0 0 1 17.5 21h-11A1.5 1.5 0 0 1 5 19.5z"></path></svg>
            Credential values are never shown
          </span>
          <button onClick={() => vm.newTargetStart()} style={{ display: "inline-flex", alignItems: "center", gap: "6px", minHeight: "32px", padding: "0 12px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", fontSize: "var(--fs-sm)", fontWeight: 600, border: "1px solid var(--brand)" }}>
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 5v14 M5 12h14"></path></svg>
            New target
          </button>
        </div>
        <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "minmax(288px,0.85fr) 1.75fr" }}>
          {/* ===== list column ===== */}
          <section aria-label="Targets" style={{ minHeight: 0, display: "flex", flexDirection: "column", borderRight: "1px solid var(--bd)" }}>
            <div style={{ flex: "0 0 auto", padding: "11px 13px", borderBottom: "1px solid var(--sep)", display: "flex", flexDirection: "column", gap: "9px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "0 10px", background: "var(--bg-inset)" }}>
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto" }}><path d="M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M20 20l-3.2-3.2"></path></svg>
                <input value={vm.tQuery} onInput={(e) => vm.onTQuery(e)} placeholder="Search targets" aria-label="Search targets" style={{ flex: 1, minWidth: 0, background: "transparent", border: "none", outline: "none", color: "var(--tx)", fontSize: "var(--fs-sm)", height: "34px" }} />
              </div>
              <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                {tFilters.map((f) => (
                  <button key={f.id} onClick={() => f.onClick()} style={{ padding: "4px 10px", borderRadius: "var(--r-pill)", border: "1px solid var(--bd)", fontSize: "var(--fs-2xs)", fontWeight: 600, background: f.bg, color: f.fg }}>{f.label}</button>
                ))}
              </div>
            </div>
            <div style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
              {tList.map((t) => (
                <button key={t.id} onClick={() => t.onClick()} style={{ width: "100%", display: "flex", alignItems: "center", gap: "10px", padding: "13px 15px", position: "relative", textAlign: "left", background: t.rowBg, borderBottom: "1px solid var(--sep)" }}>
                  <span style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: "2px", background: t.rowLine }}></span>
                  <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: t.eligColor, flex: "0 0 auto" }}></span>
                  <span style={{ flex: 1, minWidth: 0 }}>
                    <span style={{ display: "block", fontSize: "var(--fs-base)", fontWeight: 500, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{t.name}</span>
                    <span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)" }}>{t.env} · {t.ver}</span>
                  </span>
                  <span className="lab" style={{ padding: "2px 8px", borderRadius: "var(--r-pill)", background: t.lifeBg, color: t.lifeColor, fontSize: "var(--fs-2xs)", flex: "0 0 auto" }}>{t.lifeLabel}</span>
                </button>
              ))}
            </div>
          </section>
          {/* ===== detail column ===== */}
          <section aria-label="Target detail" style={{ minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg-panel)" }}>
            <div style={{ flex: "0 0 auto", padding: "15px 18px 0" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "11px", flexWrap: "wrap" }}>
                <span style={{ fontSize: "var(--fs-2xl)", fontWeight: 600 }}>{tDet.name}</span>
                <span className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx3)" }}>{tDet.ver}</span>
                <span className="lab" style={{ padding: "2px 9px", borderRadius: "var(--r-pill)", background: tDet.lifeBg, color: tDet.lifeColor, fontSize: "var(--fs-2xs)" }}>{tDet.lifeLabel}</span>
                <div style={{ flex: 1 }}></div>
                <div style={{ display: "flex", gap: "7px" }}>
                  {tDet.actions.map((a: any, i: number) => (
                    <button key={i} onClick={() => a.onClick()} style={{ minHeight: "30px", padding: "0 12px", borderRadius: "var(--r-sm)", fontSize: "var(--fs-xs)", fontWeight: 600, background: a.bg, color: a.fg, border: "1px solid " + a.bd }}>{a.label}</button>
                  ))}
                </div>
              </div>
              <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", padding: "6px 12px", border: "1px solid " + tDet.eligColor, borderRadius: "var(--r-sm)", marginBottom: "13px" }}>
                <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: tDet.eligColor }}></span>
                <span style={{ fontSize: "var(--fs-sm)", fontWeight: 600, color: tDet.eligColor }}>{tDet.eligLabel}</span>
              </div>
              <div role="tablist" aria-label="Target sections" style={{ display: "flex", gap: "1px", overflowX: "auto", borderBottom: "1px solid var(--bd)" }}>
                {tDet.tabs.map((tb: any) => (
                  <button key={tb.id} role="tab" aria-selected={tb.active} onClick={() => tb.onClick()} style={{ position: "relative", minHeight: "36px", padding: "0 13px", fontSize: "var(--fs-sm)", fontWeight: 600, color: tb.fg, background: "transparent", whiteSpace: "nowrap", flex: "0 0 auto" }}>
                    <span>{tb.label}</span>
                    <span style={{ position: "absolute", left: "8px", right: "8px", bottom: "-1px", height: "2px", background: tb.line }}></span>
                  </button>
                ))}
              </div>
            </div>
            <div style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "15px 18px 22px" }}>
              {/* ---- Overview ---- */}
              {tDet.tabOverview && (
                <>
                  {tDet.hasBlockers && (
                    <div style={{ marginBottom: "14px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-md)", background: "var(--warn-t)", padding: "11px 13px" }}>
                      <span className="lab" style={{ color: "var(--warn)" }}>Readiness blockers</span>
                      <div style={{ display: "flex", flexDirection: "column", gap: "5px", marginTop: "7px" }}>
                        {(tDet.blockers as any[]).map((b, i) => (
                          <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: "8px", fontSize: "var(--fs-sm)", color: "var(--tx)" }}>
                            <span style={{ color: "var(--warn)", flex: "0 0 auto" }}>•</span>{b}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "9px", marginBottom: "13px" }}>
                    {(tDet.fields as any[]).map((f, i) => (
                      <div key={i} style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px", minWidth: 0 }}>
                        <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>{f.k}</span>
                        <div className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx)", marginTop: "3px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{f.v}</div>
                      </div>
                    ))}
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "9px", marginBottom: "16px" }}>
                    <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}>
                      <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Synthetic data</span>
                      <div style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: tDet.synthColor, marginTop: "3px" }}>{tDet.synthLabel}</div>
                    </div>
                    <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}>
                      <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Allowlist</span>
                      <div style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: tDet.allowColor, marginTop: "3px" }}>{tDet.allowLabel}</div>
                    </div>
                    <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}>
                      <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Attack surfaces</span>
                      <div style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: "var(--tx)", marginTop: "3px" }}>{tDet.enabledCount} / {tDet.surfaceCount} on</div>
                    </div>
                  </div>
                  <span className="lab">Readiness checklist</span>
                  <div style={{ marginTop: "8px", border: "1px solid var(--bd)", borderRadius: "var(--r-md)", overflow: "hidden" }}>
                    {(tDet.checks as any[]).map((c, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: "10px", padding: "10px 12px", borderBottom: "1px solid var(--sep)" }}>
                        <span style={{ width: "18px", height: "18px", borderRadius: "var(--r-xs)", background: "var(--bg-inset)", color: c.color, display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto", marginTop: "1px" }}>{c.iconEl}</span>
                        <div style={{ flex: 1 }}>
                          <span style={{ fontSize: "var(--fs-base)", fontWeight: 500 }}>{c.label}</span>
                          <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "1px" }}>{c.detail}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              )}
              {/* ---- Attack surfaces ---- */}
              {tDet.tabSurfaces && (
                <>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "11px" }}>
                    <span className="lab">Attack surfaces</span>
                    <span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)" }}>{tDet.enabledCount} of {tDet.surfaceCount} enabled · versioned</span>
                    <div style={{ flex: 1 }}></div>
                    <button onClick={() => tDet.newSurface()} style={{ display: "inline-flex", alignItems: "center", gap: "5px", minHeight: "30px", padding: "0 11px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd-2)", background: "transparent", color: "var(--tx)", fontSize: "var(--fs-xs)", fontWeight: 600 }}>
                      <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 5v14 M5 12h14"></path></svg>
                      Add surface
                    </button>
                  </div>
                  {!!tDet.surfaceCount && (
                    <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", overflow: "hidden" }}>
                      <div style={{ display: "grid", gridTemplateColumns: "1.6fr 0.9fr 0.6fr 0.9fr 0.5fr", gap: "8px", padding: "8px 12px", borderBottom: "1px solid var(--bd)", background: "var(--bg-inset)" }}>
                        <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Surface</span>
                        <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Type</span>
                        <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Risk</span>
                        <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>OWASP</span>
                        <span className="lab" style={{ fontSize: "var(--fs-2xs)", textAlign: "right" }}>On</span>
                      </div>
                      {(tDet.surfaces as any[]).map((s) => (
                        <div key={s.id} style={{ display: "grid", gridTemplateColumns: "1.6fr 0.9fr 0.6fr 0.9fr 0.5fr", gap: "8px", padding: "10px 12px", borderBottom: "1px solid var(--sep)", alignItems: "center" }}>
                          <button onClick={() => s.onEdit()} style={{ textAlign: "left", minWidth: 0, background: "transparent" }}>
                            <span style={{ display: "block", fontSize: "var(--fs-sm)", fontWeight: 500, color: "var(--brand)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{s.name}</span>
                            <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{s.locator} · {s.ver}</span>
                          </button>
                          <span style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>{s.typeLabel}</span>
                          <span style={{ fontSize: "var(--fs-xs)", fontWeight: 600, color: s.riskColor }}>{s.risk}</span>
                          <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{s.ow} · {s.ol}</span>
                          <button onClick={() => s.onToggle()} aria-label="Toggle surface" style={{ justifySelf: "end", display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "var(--fs-2xs)", fontWeight: 600, color: s.enabledColor, background: "transparent" }}>
                            <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: s.enabledColor }}></span>{s.enabledLabel}
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                  {tDet.noSurfaces && (
                    <div style={{ border: "1px dashed var(--bd)", borderRadius: "var(--r-md)", padding: "22px", textAlign: "center", fontSize: "var(--fs-sm)", color: "var(--tx3)" }}>No attack surfaces yet. Add one to describe an endpoint, tool, RAG index, memory, file, or action to evaluate.</div>
                  )}
                </>
              )}
              {/* ---- Controls ---- */}
              {tDet.tabControls && (
                <>
                  <span className="lab">Target-level limits</span>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "9px", marginTop: "9px", marginBottom: "13px" }}>
                    <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 13px" }}>
                      <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Budget</span>
                      <div className="mono" style={{ fontSize: "var(--fs-md)", color: "var(--tx)", marginTop: "4px" }}>{tDet.budget}</div>
                    </div>
                    <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 13px" }}>
                      <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Rate limit</span>
                      <div className="mono" style={{ fontSize: "var(--fs-md)", color: "var(--tx)", marginTop: "4px" }}>{tDet.rate}</div>
                    </div>
                    <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 13px" }}>
                      <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Attempt cap</span>
                      <div className="mono" style={{ fontSize: "var(--fs-md)", color: "var(--tx)", marginTop: "4px" }}>{tDet.attemptCap}</div>
                    </div>
                    <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 13px" }}>
                      <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Timeout</span>
                      <div className="mono" style={{ fontSize: "var(--fs-md)", color: "var(--tx)", marginTop: "4px" }}>{tDet.timeout}</div>
                    </div>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "9px", padding: "10px 13px", border: "1px solid var(--bd)", borderRadius: "var(--r-md)", background: "var(--bg-inset)", fontSize: "var(--fs-sm)", color: "var(--tx2)" }}>
                    <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto" }}><path d="M6.5 10V7.5a5.5 5.5 0 0 1 11 0V10 M5 10h14v9.5A1.5 1.5 0 0 1 17.5 21h-11A1.5 1.5 0 0 1 5 19.5z"></path></svg>
                    These are display values. Budget, rate, attempt cap, timeout, and hard abort are enforced server-side by the Policy Gateway — no UI control can exceed them.
                  </div>
                </>
              )}
              {/* ---- Credentials ---- */}
              {tDet.tabCredentials && (
                <>
                  <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "13px 14px", marginBottom: "11px" }}>
                    <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Credential binding</span>
                    <div className="mono" style={{ fontSize: "var(--fs-md)", color: "var(--tx)", marginTop: "4px" }}>{tDet.cred}</div>
                    <div style={{ display: "flex", alignItems: "center", gap: "7px", marginTop: "8px", fontSize: "var(--fs-xs)", color: "var(--tx3)" }}>
                      <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M6.5 10V7.5a5.5 5.5 0 0 1 11 0V10 M5 10h14v9.5A1.5 1.5 0 0 1 17.5 21h-11A1.5 1.5 0 0 1 5 19.5z"></path></svg>
                      Reference only — the secret value is never entered, returned, or stored in the browser.
                    </div>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "9px" }}>
                    <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 13px" }}>
                      <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Synthetic-data attestation</span>
                      <div style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: tDet.synthColor, marginTop: "4px" }}>{tDet.synthLabel}</div>
                      <div className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", marginTop: "4px" }}>{tDet.fixture}</div>
                    </div>
                    <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 13px" }}>
                      <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Canary / reference</span>
                      <div className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "4px" }}>{tDet.canary}</div>
                    </div>
                  </div>
                </>
              )}
              {/* ---- Authorization ---- */}
              {tDet.tabAuthorization && (
                <div style={{ display: "flex", flexDirection: "column", gap: "11px" }}>
                  <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "13px 14px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "9px" }}>
                      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--v-clear)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12l5 5 11-11"></path></svg>
                      <span style={{ fontSize: "var(--fs-md)", fontWeight: 600 }}>Structural validation</span>
                      <span style={{ marginLeft: "auto", fontSize: "var(--fs-sm)", fontWeight: 600, color: tDet.structuralColor }}>{tDet.structuralLabel}</span>
                    </div>
                    <p style={{ margin: "8px 0 10px", fontSize: "var(--fs-sm)", color: "var(--tx2)", lineHeight: 1.5 }}>Local checks only — schema, allowlist syntax, credential-reference resolution, synthetic-data attestation. <strong>Does not contact the target.</strong></p>
                    <button onClick={() => tDet.runStructural()} style={{ minHeight: "32px", padding: "0 13px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd-2)", background: "transparent", color: "var(--tx)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Run structural validation</button>
                  </div>
                  <div style={{ border: "1px solid " + tDet.connColor, borderRadius: "var(--r-md)", padding: "13px 14px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "9px" }}>
                      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke={tDet.connColor} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12.5a7 7 0 0 1 14 0 M8.5 15a3.5 3.5 0 0 1 7 0 M12 18h.01"></path></svg>
                      <span style={{ fontSize: "var(--fs-md)", fontWeight: 600 }}>Connectivity / preflight</span>
                      <span style={{ marginLeft: "auto", fontSize: "var(--fs-sm)", fontWeight: 600, color: tDet.connColor }}>{tDet.connLabel}</span>
                    </div>
                    <p style={{ margin: "8px 0 10px", fontSize: "var(--fs-sm)", color: "var(--tx2)", lineHeight: 1.5 }}><strong>Live probing of the target.</strong> Requires explicit, auditable authorization from an approver distinct from the launcher; every authorization is written to the audit log.</p>
                    {tDet.canAuthorize && (
                      <button onClick={() => tDet.openAuthProbe()} style={{ minHeight: "32px", padding: "0 13px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", border: "1px solid var(--brand)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Authorize live probe</button>
                    )}
                    {tDet.probeAuthd && (
                      <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "var(--fs-sm)", color: "var(--phos)" }}>
                        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12l5 5 11-11"></path></svg>
                        Authorized · logged
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)" }}>Authorization owner · {tDet.owner}</div>
                </div>
              )}
              {/* ---- History ---- */}
              {tDet.tabHistory && (
                <>
                  <span className="lab">Audit history</span>
                  <div style={{ marginTop: "9px", borderLeft: "2px solid var(--bd)", paddingLeft: "14px", display: "flex", flexDirection: "column", gap: "13px" }}>
                    {(tDet.audit as any[]).map((a, i) => (
                      <div key={i} style={{ position: "relative" }}>
                        <span style={{ position: "absolute", left: "-19px", top: "4px", width: "8px", height: "8px", borderRadius: "50%", background: "var(--brand)", border: "2px solid var(--bg-panel)" }}></span>
                        <div style={{ display: "flex", alignItems: "baseline", gap: "9px" }}>
                          <span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)", flex: "0 0 auto" }}>{a.t}</span>
                          <span style={{ fontSize: "var(--fs-sm)", fontWeight: 600 }}>{a.who}</span>
                        </div>
                        <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", lineHeight: 1.45, marginTop: "2px" }}>{a.ev}</div>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
