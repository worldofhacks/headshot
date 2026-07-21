/*
 * Findings.tsx — faithful 1:1 port of the prototype FINDINGS screen
 * (Headshot Console.dc.html lines 750–922).
 *
 * List-detail: a filterable findings list (findingsVM → fList / filteredFindings / vChip)
 * beside a tabbed detail pane (buildFinding → fd, tabs Overview/Evidence/Reproduction/
 * Remediation/History, setFTab / state.fTab). In Integration state the fabricated live
 * numbers are dropped and an honest "No live projection" empty-state is shown — never
 * hardcode demo numbers here (the prototype gates them on scenario).
 *
 * The outer `<sc-if value="{{ isFindings }}">` (line 751) is the shell router's job; this
 * component IS that screen's body. VMs (findingsVM / core) compute every color, chip, and
 * icon element (svgEl → React element via app.svgEl); we consume them verbatim.
 */
import type { ScreenProps } from "../types";

export function Findings({ app }: ScreenProps) {
  const core = app.core();
  const integ: boolean = core.integ;
  const notInteg: boolean = core.notInteg;
  const setDemo: () => void = core.setDemo;

  const vm = app.findingsVM();
  const fList: any[] = vm.fList;
  const fCount: number = vm.fCount;
  const fShown: number = vm.fShown;
  const fQuery: string = vm.fQuery;
  const onFSearch: (e: any) => void = vm.onFSearch;
  const fEmpty: boolean = vm.fEmpty;
  const fd: any = vm.fd;

  return (
    <>
      {/* ===== INTEGRATION STATE — no live projection ===== */}
      {integ && (
        <div style={{ flex: 1, minHeight: 0, overflowY: "auto", display: "flex", alignItems: "center", justifyContent: "center", padding: "48px 24px" }}>
          <div style={{ maxWidth: "540px", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center", gap: "13px" }}>
            <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="var(--tx3)" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z" opacity=".45"></path><path d="M8.5 12h7"></path></svg>
            <div style={{ fontSize: "var(--fs-2xl)", fontWeight: 600, color: "var(--tx)", letterSpacing: "-.01em" }}>No live projection</div>
            <div style={{ fontSize: "var(--fs-base)", color: "var(--tx2)", lineHeight: 1.55 }}>Finding read models are not projected to the console yet. The evidence behind them — the append-only, content-hashed AttemptResult and the Judge Verdict — is implemented in the platform, but no finding query or command API is exposed.</div>
            <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "4px 11px", border: "1px solid var(--bd)", borderRadius: "var(--r-pill)", color: "var(--tx2)", fontSize: "var(--fs-2xs)" }}>Verdict data IMPLEMENTED · finding API PROPOSED</span>
            <button onClick={setDemo} style={{ marginTop: "4px", height: "32px", padding: "0 15px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "transparent", color: "var(--tx2)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>View demo scenario</button>
          </div>
        </div>
      )}

      {/* ===== DEMO STATE — list-detail ===== */}
      {notInteg && (
        <div style={{ flex: 1, minHeight: 0, overflowX: "hidden", overflowY: "hidden" }}>
          <div style={{ height: "100%", minWidth: 0, display: "flex", flexDirection: "column" }}>
            <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", gap: "12px", padding: "12px 16px", borderBottom: "1px solid var(--bd)" }}>
              <div style={{ display: "flex", alignItems: "baseline", gap: "9px" }}><span style={{ fontSize: "var(--fs-2xl)", fontWeight: 600 }}>Findings</span><span className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx3)" }}>{fShown} / {fCount}</span></div>
              <div style={{ flex: 1 }}></div>
              <div style={{ display: "flex", alignItems: "center", gap: "7px", height: "32px", padding: "0 10px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "var(--bg-panel)", width: "230px" }}>
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M20 20l-3.6-3.6"></path></svg>
                <input value={fQuery} onInput={onFSearch} placeholder="Search findings…" style={{ flex: 1, minWidth: 0, background: "none", border: "none", outline: "none", fontSize: "var(--fs-base)", color: "var(--tx)" }} />
                <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>/</span>
              </div>
              <div style={{ display: "flex", gap: "6px" }}>
                <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "5px 9px", border: "1px solid var(--brand-line)", borderRadius: "var(--r-xs)", color: "var(--brand)", background: "var(--brand-tint)", fontSize: "var(--fs-2xs)" }}>Critical · open</span>
                <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "5px 9px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", color: "var(--tx2)", fontSize: "var(--fs-2xs)" }}>Needs review</span>
                <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "5px 9px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", color: "var(--tx2)", fontSize: "var(--fs-2xs)" }}>My queue</span>
              </div>
            </div>

            <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "minmax(380px,1fr) 1.75fr" }}>
              {/* LIST */}
              <section aria-label="Findings list" style={{ minHeight: 0, display: "flex", flexDirection: "column", borderRight: "1px solid var(--bd)" }}>
                <div style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
                  {fList.map((f: any) => (
                    <button key={f.id} onClick={f.onClick} style={{ width: "100%", display: "flex", flexDirection: "column", gap: "6px", padding: "11px 15px 11px 16px", position: "relative", textAlign: "left", background: f.rowBg, borderBottom: "1px solid var(--sep)" }}>
                      <span style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: "2px", background: f.rowLine }}></span>
                      <div style={{ display: "flex", alignItems: "center", gap: "9px" }}>
                        <span style={{ width: "9px", height: "9px", borderRadius: "2px", background: f.sevColor, flex: "0 0 auto" }}></span>
                        <span className="mono" style={{ fontSize: "var(--fs-sm)", fontWeight: 600 }}>{f.id}</span>
                        <span style={{ fontSize: "var(--fs-xs)", color: f.sevColor, fontWeight: 600 }}>{f.sevLabel}</span>
                        <div style={{ flex: 1 }}></div>
                        <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "2px 8px", borderRadius: "var(--r-xs)", fontSize: "var(--fs-xs)", fontWeight: 600, color: f.vColor, background: f.vTint, border: "1px solid " + f.vBorder }}>{f.vIconEl}{f.vLabel}</span>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>
                        <span className="mono" style={{ fontSize: "var(--fs-2xs)", padding: "1px 4px", borderRadius: "3px", background: "var(--bg-inset)", color: "var(--tx3)" }}>{f.owasp}</span>
                        <span style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{f.catShort}</span>
                        <div style={{ flex: 1 }}></div>
                        <span style={{ display: "inline-flex", alignItems: "center", gap: "4px" }}><span style={{ width: "5px", height: "5px", borderRadius: "50%", background: f.provColor }}></span>{f.prov}</span>
                        <span style={{ color: f.statusColor }}>{f.status}</span>
                        <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", width: "56px", textAlign: "right" }}>{f.age}</span>
                      </div>
                    </button>
                  ))}
                  {fEmpty && (
                    <div style={{ padding: "44px 24px", textAlign: "center", color: "var(--tx3)" }}><div style={{ fontSize: "var(--fs-base)", fontWeight: 500, color: "var(--tx2)", marginBottom: "4px" }}>No findings match</div><div style={{ fontSize: "var(--fs-sm)" }}>Clear the search to see all {fCount} findings.</div></div>
                  )}
                </div>
              </section>

              {/* DETAIL */}
              <section aria-label="Finding detail" style={{ minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg-panel)" }}>
                <div style={{ flex: "0 0 auto", padding: "15px 18px", borderBottom: "1px solid var(--sep)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "9px" }}>
                    <span className="mono" style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: "var(--brand)" }}>{fd.id}</span>
                    <span style={{ width: "9px", height: "9px", borderRadius: "2px", background: fd.sevColor }}></span>
                    <span style={{ fontSize: "var(--fs-sm)", fontWeight: 600, color: fd.sevColor }}>{fd.sevLabel}</span>
                    <div style={{ flex: 1 }}></div>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "4px 11px", borderRadius: "var(--r-sm)", fontSize: "var(--fs-sm)", fontWeight: 600, color: fd.vColor, background: fd.vTint, border: "1px solid " + fd.vBorder }}>{fd.vIconEl}{fd.vLabel}</span>
                  </div>
                  <div style={{ fontSize: "var(--fs-3xl)", fontWeight: 600, letterSpacing: "-.01em", marginBottom: "4px" }}>{fd.title}</div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                    <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "5px", color: "var(--tx2)" }}><span style={{ width: "5px", height: "5px", borderRadius: "50%", background: fd.vColor }}></span>{fd.prov}</span>
                    <span style={{ color: "var(--tx3)" }}>·</span>
                    <span style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)" }}>{fd.target} <span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)" }}>{fd.ver}</span></span>
                    <span style={{ color: "var(--tx3)" }}>·</span>
                    <span style={{ fontSize: "var(--fs-sm)", color: fd.statusColor }}>{fd.status}</span>
                  </div>
                </div>

                <div style={{ flex: "0 0 auto", display: "flex", gap: "2px", padding: "0 18px", borderBottom: "1px solid var(--sep)" }}>
                  {fd.tabs.map((t: any) => (
                    <button key={t.id} onClick={t.onClick} style={{ padding: "10px 12px", fontSize: "var(--fs-base)", fontWeight: 500, color: t.fg, borderBottom: "2px solid " + t.bd, marginBottom: "-1px" }}>{t.label}</button>
                  ))}
                </div>

                <div style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "18px" }}>

                  {fd.tabOverview && (
                    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                      <div><span className="lab">Summary</span><p style={{ margin: "6px 0 0", fontSize: "var(--fs-md)", lineHeight: 1.55 }}>{fd.summary}</p></div>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                        <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 12px" }}><span className="lab">Exploitability</span><p style={{ margin: "5px 0 0", fontSize: "var(--fs-sm)", lineHeight: 1.5, color: "var(--tx2)" }}>{fd.exploit}</p></div>
                        <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 12px" }}><span className="lab">Confirmation source</span><p style={{ margin: "5px 0 0", fontSize: "var(--fs-base)", color: "var(--tx)" }}>{fd.confSource}</p><span className="lab" style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)", marginTop: "3px", display: "block" }}>Regression: {fd.reg}</span></div>
                      </div>
                      <div style={{ border: "1px solid var(--v-conf)", borderLeftWidth: "2.5px", borderRadius: "var(--r-sm)", padding: "11px 12px", background: "var(--v-conf-t)" }}><span className="lab" style={{ color: "var(--v-conf)" }}>Impact</span><p style={{ margin: "5px 0 0", fontSize: "var(--fs-base)", lineHeight: 1.5, color: "var(--tx)" }}>{fd.impact}</p></div>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                        <div><span className="lab" style={{ color: "var(--v-clear)" }}>Expected behavior</span><p style={{ margin: "5px 0 0", fontSize: "var(--fs-sm)", lineHeight: 1.5, color: "var(--tx2)" }}>{fd.expected}</p></div>
                        <div><span className="lab" style={{ color: "var(--v-conf)" }}>Observed behavior</span><p style={{ margin: "5px 0 0", fontSize: "var(--fs-sm)", lineHeight: 1.5, color: "var(--tx2)" }}>{fd.observed}</p></div>
                      </div>
                      <div style={{ display: "flex", gap: "10px" }}>
                        <div style={{ flex: 1, border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "10px 12px" }}><span className="lab">OWASP Web (2021)</span><div className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "4px" }}>{fd.owaspWeb}</div></div>
                        <div style={{ flex: 1, border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "10px 12px" }}><span className="lab">OWASP LLM (2025)</span><div className="mono" style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "4px" }}>{fd.owaspLLM}</div></div>
                      </div>
                    </div>
                  )}

                  {fd.tabEvidence && (
                    <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "10px", padding: "11px 13px", border: "1px solid " + fd.hashColor, borderRadius: "var(--r-md)" }}>
                        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke={fd.hashColor} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M6.5 10V7.5a5.5 5.5 0 0 1 11 0V10 M5 10h14v9.5A1.5 1.5 0 0 1 17.5 21h-11A1.5 1.5 0 0 1 5 19.5z"></path></svg>
                        <div style={{ flex: 1 }}><div style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Recorder-owned append-only AttemptResult · hash {fd.hashLabel}</div><div className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", marginTop: "1px" }}>recorder-svc 2.3.1 · schema v1 · attempt {fd.att}</div></div>
                        <span style={{ padding: "3px 9px", borderRadius: "var(--r-xs)", fontSize: "var(--fs-xs)", fontWeight: 600, color: fd.hashColor, background: "var(--bg-inset)" }}>{fd.hashLabel}</span>
                      </div>
                      {fd.hasOracle && (<div style={{ border: "1px solid var(--phos-line)", borderRadius: "var(--r-md)", padding: "11px 12px", background: "var(--phos-tint)" }}><div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px", color: "var(--phos)" }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12.5l5 5 11-11"></path></svg><span style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Deterministic oracle · canary-sensitive-record</span></div><p style={{ margin: 0, fontSize: "var(--fs-sm)", lineHeight: 1.5, color: "var(--tx)" }}>Synthetic canary token CN-7731 observed verbatim in the target response — deterministic sensitive-data leak signal. Takes precedence over the LLM judge.</p></div>)}
                      {fd.hasJudge && (<div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "11px 12px" }}><div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}><span style={{ color: "var(--tz-gov)", display: "flex" }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3v3 M7 6h10l2 6H5z M6 12v6a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2v-6"></path></svg></span><span style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Judge assessment</span><span className="mono" style={{ marginLeft: "auto", fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>judge-sonnet-4.6</span></div><div style={{ display: "flex", gap: "18px", marginBottom: "8px" }}><div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Score</span><div className="mono" style={{ fontSize: "var(--fs-xl)", fontWeight: 600, color: fd.vColor }}>{fd.judgeScore}</div></div><div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Threshold</span><div className="mono" style={{ fontSize: "var(--fs-xl)", fontWeight: 600, color: "var(--tx2)" }}>0.80</div></div><div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Calibration</span><div className="mono" style={{ fontSize: "var(--fs-base)", color: fd.calibColor, marginTop: "2px" }}>{fd.calib}</div></div></div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Rubric</span><span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", marginLeft: "6px" }}>rubric-data-exfiltration-v1</span></div>)}
                      <div><span className="lab" style={{ color: "var(--tx3)" }}>Target request</span><pre className="mono" style={{ margin: "5px 0 0", padding: "10px 11px", border: "1px solid var(--bd)", borderLeft: "2.5px solid var(--tz-ext)", borderRadius: "var(--r-sm)", background: "var(--bg-inset)", fontSize: "var(--fs-xs)", lineHeight: 1.5, whiteSpace: "pre-wrap", wordBreak: "break-word", color: "var(--tx2)" }}>{fd.req}</pre></div>
                      <div><span className="lab" style={{ color: "var(--tx3)" }}>Target response</span><pre className="mono" style={{ margin: "5px 0 0", padding: "10px 11px", border: "1px solid var(--bd)", borderLeft: "2.5px solid var(--tz-ext)", borderRadius: "var(--r-sm)", background: "var(--bg-inset)", fontSize: "var(--fs-xs)", lineHeight: 1.5, whiteSpace: "pre-wrap", wordBreak: "break-word", color: "var(--tx)" }}>{fd.resp}</pre></div>
                    </div>
                  )}

                  {fd.tabRepro && (
                    <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}><span className="lab">Minimal reproduction</span><span className="lab" style={{ padding: "2px 7px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", color: "var(--tx2)" }}>Deterministic replay</span></div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
                        {fd.repro.map((r: any, i: number) => (
                          <div key={i} style={{ display: "flex", gap: "12px", alignItems: "flex-start" }}>
                            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", flex: "0 0 auto" }}><span className="mono" style={{ width: "22px", height: "22px", borderRadius: "var(--r-sm)", background: "var(--bg-inset)", border: "1px solid var(--bd)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "var(--fs-xs)", fontWeight: 600, color: "var(--brand)" }}>{r.n}</span><span style={{ width: "1.5px", flex: 1, minHeight: "12px", background: "var(--sep)" }}></span></div>
                            <p style={{ margin: "1px 0 14px", fontSize: "var(--fs-base)", lineHeight: 1.5 }}>{r.s}</p>
                          </div>
                        ))}
                      </div>
                      <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "11px 13px", background: "var(--bg-inset)", display: "flex", alignItems: "center", gap: "10px" }}><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--tx2)" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a9 9 0 1 0 9 9 M21 3v5h-5"></path></svg><span style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)" }}>Regression runs generate a fresh run-id and re-execute against the live target — verdicts are never reused.</span></div>
                    </div>
                  )}

                  {fd.tabRemediation && (
                    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                      <div><span className="lab">Remediation proposal</span><p style={{ margin: "6px 0 0", fontSize: "var(--fs-base)", lineHeight: 1.55 }}>{fd.remediation}</p></div>
                      <div><span className="lab">Fix-validation history</span>
                        <div style={{ marginTop: "8px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", overflow: "hidden" }}>
                          {fd.fix.map((x: any, i: number) => (
                            <div key={i} style={{ display: "flex", alignItems: "center", gap: "11px", padding: "10px 12px", borderBottom: "1px solid var(--sep)" }}><span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", width: "52px" }}>{x.v}</span><span style={{ width: "7px", height: "7px", borderRadius: "50%", background: x.color }}></span><span style={{ fontSize: "var(--fs-sm)", color: "var(--tx)", flex: 1 }}>{x.t}</span></div>
                          ))}
                        </div>
                      </div>
                      {fd.showRemediate && (
                        <div style={{ display: "flex", alignItems: "center", gap: "11px", padding: "12px 14px", border: "1px solid var(--bd)", borderRadius: "var(--r-md)", background: "var(--bg-inset)" }}>
                          <div style={{ flex: 1 }}><div style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Remediation requires approval</div><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "2px" }}>Every remediation needs an Approver distinct from the run launcher.</div></div>
                          <button onClick={fd.openRemediate} style={{ display: "flex", alignItems: "center", gap: "6px", padding: "8px 13px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Open in approvals</button>
                        </div>
                      )}
                    </div>
                  )}

                  {fd.tabHistory && (
                    <div><span className="lab">Audit history</span>
                      <div style={{ marginTop: "10px", display: "flex", flexDirection: "column", gap: 0 }}>
                        {fd.audit.map((a: any, i: number) => (
                          <div key={i} style={{ display: "flex", gap: "12px", alignItems: "flex-start" }}><div style={{ display: "flex", flexDirection: "column", alignItems: "center", flex: "0 0 auto" }}><span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "var(--brand)", marginTop: "4px" }}></span><span style={{ width: "1.5px", flex: 1, minHeight: "20px", background: "var(--sep)" }}></span></div><div style={{ paddingBottom: "16px" }}><div style={{ display: "flex", alignItems: "center", gap: "8px" }}><span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>{a.t}</span><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{a.who}</span></div><p style={{ margin: "3px 0 0", fontSize: "var(--fs-base)", lineHeight: 1.45 }}>{a.ev}</p></div></div>
                        ))}
                      </div>
                    </div>
                  )}

                </div>
              </section>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
