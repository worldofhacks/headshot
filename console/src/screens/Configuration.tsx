/*
 * Configuration.tsx — faithful port of the prototype CONFIGURATION screen
 * (Headshot Console.dc.html template lines 1397–1503).
 *
 * Data comes from app.agentsVM() → { agentList, detComps, aDet } (line 3158). The template
 * reads app.state.cfgAgent / cfgScope / agentModel / judgeCalib / cfgPublish through that VM;
 * we do NOT duplicate the data. The publish lifecycle (draft → validating → review → published
 * → active) is non-optimistic and rationale-required; the Judge calibration invariant
 * (model/rubric/threshold change → INDETERMINATE until recalibrated) is carried by aDet.
 */
import type { ScreenProps } from "../types";

export function Configuration({ app }: ScreenProps) {
  const { agentList, detComps, aDet } = app.agentsVM();

  return (
    <div data-screen-label="Configuration" style={{ flex: 1, minHeight: 0, overflow: "hidden" }}>
      <div style={{ height: "100%", minWidth: 0, display: "flex", flexDirection: "column" }}>
        <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "12px", padding: "13px 18px", borderBottom: "1px solid var(--bd)" }}>
          <span style={{ fontSize: "var(--fs-2xl)", fontWeight: 600 }}>Configuration</span>
          <span className="lab" style={{ color: "var(--tx3)" }}>Model-backed agents · effective config · activation</span>
          <div style={{ flex: 1 }} />
          <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "3px 9px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-xs)", color: "var(--warn)", background: "var(--warn-t)", fontSize: "var(--fs-2xs)" }}>Simulated catalog · no OpenRouter call</span>
        </div>
        <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "minmax(272px,0.8fr) 1.8fr" }}>
          <section aria-label="Agents" style={{ minHeight: 0, display: "flex", flexDirection: "column", borderRight: "1px solid var(--bd)", overflowY: "auto" }}>
            <div style={{ padding: "12px 14px 6px" }}><span className="lab">Model-backed agents</span></div>
            {agentList.map((a: any) => (
              <button key={a.id} onClick={a.onClick} style={{ width: "100%", display: "flex", alignItems: "center", gap: "10px", padding: "12px 14px", position: "relative", textAlign: "left", background: a.bg, borderBottom: "1px solid var(--sep)" }}>
                <span style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: "2px", background: a.line }} />
                <span style={{ width: "8px", height: "8px", borderRadius: "2px", background: a.zoneColor, flex: "0 0 auto" }} />
                <span style={{ flex: 1, minWidth: 0 }}>
                  <span style={{ display: "block", fontSize: "var(--fs-base)", fontWeight: 600 }}>{a.name}</span>
                  <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", display: "block" }}>{a.model}</span>
                </span>
                {a.uncal && <span className="lab" style={{ padding: "1px 6px", borderRadius: "var(--r-xs)", background: "var(--warn-t)", color: "var(--warn)", fontSize: "var(--fs-2xs)", flex: "0 0 auto" }}>Uncalibrated</span>}
                {a.dirty && <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: "var(--brand)", flex: "0 0 auto" }} />}
              </button>
            ))}
            <div style={{ padding: "14px 14px 6px" }}><span className="lab">Deterministic — no model</span></div>
            {detComps.map((d: any, i: number) => (
              <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: "10px", padding: "11px 14px", borderBottom: "1px solid var(--sep)", opacity: 0.9 }}>
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto", marginTop: "2px" }}><path d="M6.5 10V7.5a5.5 5.5 0 0 1 11 0V10 M5 10h14v9.5A1.5 1.5 0 0 1 17.5 21h-11A1.5 1.5 0 0 1 5 19.5z" /></svg>
                <span style={{ flex: 1, minWidth: 0 }}>
                  <span style={{ display: "block", fontSize: "var(--fs-sm)", fontWeight: 600, color: "var(--tx2)" }}>{d.name}</span>
                  <span style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", lineHeight: 1.4 }}>{d.why}</span>
                </span>
              </div>
            ))}
          </section>
          <section aria-label="Agent configuration" style={{ minHeight: 0, display: "flex", flexDirection: "column", overflowY: "auto", background: "var(--bg-panel)" }}>
            <div style={{ padding: "16px 18px 22px", display: "flex", flexDirection: "column", gap: "15px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <span style={{ width: "9px", height: "9px", borderRadius: "2px", background: aDet.zoneColor }} />
                <span style={{ fontSize: "var(--fs-2xl)", fontWeight: 600 }}>{aDet.name}</span>
                <span className="lab" style={{ color: "var(--tx3)" }}>{aDet.role}</span>
                {aDet.dirty && <span className="lab" style={{ padding: "2px 8px", borderRadius: "var(--r-pill)", background: "var(--brand-tint)", color: "var(--brand)", fontSize: "var(--fs-2xs)" }}>Unpublished changes</span>}
              </div>

              <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "14px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "11px" }}>
                  <span className="lab">Assigned model</span>
                  <div style={{ flex: 1 }} />
                  <button onClick={aDet.openCatalog} style={{ display: "inline-flex", alignItems: "center", gap: "6px", minHeight: "30px", padding: "0 12px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd-2)", background: "transparent", color: "var(--tx)", fontSize: "var(--fs-xs)", fontWeight: 600 }}>
                    <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M20 20l-3.2-3.2" /></svg>Change model
                  </button>
                </div>
                <div style={{ fontSize: "var(--fs-lg)", fontWeight: 600, marginBottom: "2px" }}>{aDet.modelName}</div>
                <div className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", marginBottom: "10px" }}>{aDet.modelId}</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "16px" }}>
                  <div>
                    <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Provider</span>
                    <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "2px" }}>{aDet.modelProvider}</div>
                  </div>
                  <div>
                    <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Context</span>
                    <div className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "2px" }}>{aDet.modelCtx}</div>
                  </div>
                  <div>
                    <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>In / out / 1M</span>
                    <div className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "2px" }}>{aDet.modelIn} / {aDet.modelOut}</div>
                  </div>
                  <div style={{ flex: 1, minWidth: "120px" }}>
                    <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Supported params</span>
                    <div className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", marginTop: "3px" }}>{aDet.modelParams}</div>
                  </div>
                </div>
              </div>

              {aDet.isJudge && (
                <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "13px 14px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "9px", marginBottom: "10px" }}>
                    <span className="lab">Judge calibration</span>
                    <span style={{ marginLeft: "auto", fontSize: "var(--fs-sm)", fontWeight: 600, color: aDet.calibColor }}>{aDet.calibLabel}</span>
                  </div>
                  {aDet.judgeInvalid && (
                    <div style={{ display: "flex", alignItems: "flex-start", gap: "8px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-md)", background: "var(--warn-t)", padding: "11px 13px", marginBottom: "11px" }}>
                      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--warn)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto", marginTop: "1px" }}><path d="M12 3l9.5 17H2.5z M12 9.5v5 M12 17.5h.01" /></svg>
                      <p style={{ margin: 0, fontSize: "var(--fs-sm)", color: "var(--tx)", lineHeight: 1.5 }}>Model, rubric, or threshold changed. Until a calibration result is acknowledged, non-oracle cases <strong>fail closed to INDETERMINATE</strong>. Deterministic oracle precedence is enforced outside the model and is unaffected. <strong>Publishing does not recalibrate.</strong></p>
                    </div>
                  )}
                  <div style={{ display: "flex", alignItems: "center", gap: "9px", flexWrap: "wrap" }}>
                    <span className="lab" style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)" }}>Simulate calibration result · review-only</span>
                    <div style={{ flex: 1, minWidth: "20px" }} />
                    <button onClick={aDet.calibPass} style={{ minHeight: "30px", padding: "0 12px", borderRadius: "var(--r-sm)", border: "1px solid var(--phos)", background: "var(--phos-tint)", color: "var(--phos)", fontSize: "var(--fs-xs)", fontWeight: 600 }}>Record PASSING</button>
                    <button onClick={aDet.calibFail} style={{ minHeight: "30px", padding: "0 12px", borderRadius: "var(--r-sm)", border: "1px solid var(--v-conf)", background: "var(--v-conf-t)", color: "var(--v-conf)", fontSize: "var(--fs-xs)", fontWeight: 600 }}>Record FAILED</button>
                  </div>
                </div>
              )}

              <div>
                <span className="lab">Parameters</span>
                <div style={{ marginTop: "9px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "9px" }}>
                  {aDet.params.map((p: any, i: number) => (
                    <div key={i} style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}>
                      <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>{p.k}</span>
                      <div className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx)", marginTop: "3px" }}>{p.v}</div>
                    </div>
                  ))}
                </div>
                {aDet.isJudge && (
                  <button onClick={aDet.judgeInvalidate} style={{ marginTop: "9px", minHeight: "30px", padding: "0 12px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd-2)", background: "transparent", color: "var(--tx2)", fontSize: "var(--fs-xs)", fontWeight: 600 }}>Change threshold / rubric (invalidates calibration)</button>
                )}
              </div>

              {aDet.hasFallback && (
                <div>
                  <span className="lab">Fallback chain</span>
                  <div style={{ marginTop: "8px", fontSize: "var(--fs-xs)", color: "var(--tx3)", marginBottom: "8px" }}>Explicit, ordered — never a silent provider switch.</div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "7px" }}>
                    {aDet.fallback.map((f: any, i: number) => (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: "9px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}>
                        <span className="mono" style={{ width: "20px", height: "20px", borderRadius: "var(--r-xs)", background: "var(--bg-inset)", color: "var(--tx3)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "var(--fs-2xs)", flex: "0 0 auto" }}>{f.ord}</span>
                        <span style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)" }}>{f.name}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "9px" }}>
                  <span className="lab">Effective configuration</span>
                  <span className="lab" style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)" }}>workspace → target → campaign</span>
                </div>
                <div style={{ display: "flex", gap: "6px", marginBottom: "10px" }}>
                  {aDet.scopes.map((s: any) => (
                    <button key={s.id} onClick={s.onClick} style={{ padding: "5px 11px", borderRadius: "var(--r-pill)", border: "1px solid var(--bd)", fontSize: "var(--fs-2xs)", fontWeight: 600, background: s.bg, color: s.fg }}>{s.label}</button>
                  ))}
                </div>
                <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", overflow: "hidden" }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1.1fr 0.8fr 0.9fr 0.9fr 0.7fr", gap: "8px", padding: "8px 12px", borderBottom: "1px solid var(--bd)", background: "var(--bg-inset)" }}>
                    <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Setting</span>
                    <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Workspace</span>
                    <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Target</span>
                    <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Campaign</span>
                    <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Effective</span>
                  </div>
                  {aDet.effRows.map((r: any, i: number) => (
                    <div key={i} style={{ padding: "9px 12px", borderBottom: "1px solid var(--sep)" }}>
                      <div style={{ display: "grid", gridTemplateColumns: "1.1fr 0.8fr 0.9fr 0.9fr 0.7fr", gap: "8px", alignItems: "center" }}>
                        <span style={{ fontSize: "var(--fs-sm)", color: "var(--tx)" }}>{r.k}</span>
                        <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{r.ws}</span>
                        <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{r.tg}</span>
                        <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{r.cp}</span>
                        <span className="mono" style={{ fontSize: "var(--fs-sm)", fontWeight: 600, color: "var(--tx)" }}>{r.eff}</span>
                      </div>
                      {r.lock && (
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "5px", fontSize: "var(--fs-2xs)", color: "var(--warn)" }}>
                          <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M7 10V7.5a5 5 0 0 1 10 0V10 M5.5 10h13v9h-13z" /></svg>{r.lock}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "14px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "9px", marginBottom: "11px" }}>
                  <span className="lab">Activation</span>
                  <span className="lab" style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)" }}>draft → validating → review → published → active on next campaign</span>
                </div>
                {aDet.pubActive && (
                  <div style={{ display: "flex", alignItems: "center", gap: "9px", padding: "11px 13px", border: "1px solid var(--phos)", borderRadius: "var(--r-md)", background: "var(--phos-tint)" }}>
                    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--phos)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12l5 5 11-11" /></svg>
                    <span style={{ fontSize: "var(--fs-sm)", color: "var(--tx)" }}>Published. This configuration is captured as an immutable snapshot and becomes active <strong>on the next campaign only</strong> — the running campaign is never mutated.</span>
                  </div>
                )}
                {aDet.pubIdle && (
                  <>
                    {aDet.canPublish && (
                      <>
                        <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginBottom: "9px" }}>Publishing critical configuration requires a rationale and produces an audit event. It is non-optimistic — it applies only after backend acknowledgement.</div>
                        <textarea value={aDet.pubRationale} onInput={aDet.onRationale} placeholder="Rationale for this configuration change (required)" aria-label="Publication rationale" style={{ width: "100%", boxSizing: "border-box", minHeight: "64px", resize: "vertical", background: "var(--bg-inset)", border: "1px solid " + aDet.pubErr, borderRadius: "var(--r-sm)", padding: "9px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", fontFamily: "inherit", outline: "none" }} />
                        {aDet.pubErr && <div style={{ fontSize: "var(--fs-xs)", color: "var(--v-conf)", marginTop: "5px" }}>A rationale is required before publishing.</div>}
                        <button onClick={aDet.validate} style={{ marginTop: "10px", minHeight: "34px", padding: "0 14px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", border: "1px solid var(--brand)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Validate &amp; review</button>
                      </>
                    )}
                    {aDet.noPublish && <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx3)" }}>No pending changes. Publish becomes available after you stage a model or parameter change.</div>}
                  </>
                )}
                {aDet.pubValidating && (
                  <div style={{ display: "flex", alignItems: "center", gap: "9px", fontSize: "var(--fs-sm)", color: "var(--tx2)" }}>
                    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--brand)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ animation: "hs-spin 1s linear infinite" }}><path d="M12 3a9 9 0 1 0 9 9" /></svg>Validating configuration…
                  </div>
                )}
                {aDet.pubReview && (
                  <>
                    <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx)", marginBottom: "10px" }}>Validation passed. Confirm to publish — the change is audited and activates on the next campaign.</div>
                    <button onClick={aDet.publish} style={{ minHeight: "34px", padding: "0 14px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", border: "1px solid var(--brand)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Confirm &amp; publish</button>
                  </>
                )}
                {aDet.pubPublished && (
                  <div style={{ display: "flex", alignItems: "center", gap: "9px", fontSize: "var(--fs-sm)", color: "var(--tx2)" }}>
                    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--brand)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ animation: "hs-spin 1s linear infinite" }}><path d="M12 3a9 9 0 1 0 9 9" /></svg>Publishing… awaiting backend acknowledgement
                  </div>
                )}
              </div>

            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
