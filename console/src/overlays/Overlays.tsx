/*
 * Overlays.tsx — the single desktop overlay host. Faithful 1:1 translation of the
 * prototype's OVERLAYS block (Headshot Console.dc.html lines 2046–2407): every desktop
 * overlay rendered conditionally from app.state, plus the visually-hidden aria-live
 * status region.
 *
 * Overlays rendered here (in prototype order): model catalog modal (catalogOpen),
 * attack-surface editor drawer (surfaceEdit/surfaceDraft), new-target guided flow (newT),
 * target-edit drawer (editT), authorize-live-probe dialog (authProbe), role/principal menu
 * (roleMenu), command palette (palOpen), guarded abort dialog (abortOpen), decision sheet
 * (decision), and the toast.
 *
 * Data comes from the same VM builders the screens consume — app.core() (palette / abort /
 * roleMenu / camp / toast), app.apprVM() (decision sheet `dv`), app.targetsVM() (surface /
 * edit / authProbe / newT), app.agentsVM() (catInfo). We DO NOT duplicate that data; we
 * read it. Colors are always the prototype's CSS variables — never literals.
 *
 * Every overlay carries role="dialog" + aria-modal + aria-label + data-overlay="1", exactly
 * as the prototype. Focus-move-in/return, focus-trap, scroll-lock, and Escape-closes-topmost
 * are ported at the App level (App.componentDidUpdate / App.onKey against overlayOpen /
 * focusOverlay); this host only renders the markup those mechanisms operate on. The palette
 * input carries [data-autofocus] so focusOverlay lands there first (mirrors `autofocus`).
 */
import type { ScreenProps } from "../types";

export function Overlays({ app }: ScreenProps) {
  const core: any = app.core();
  const appr: any = app.apprVM();
  const tv: any = app.targetsVM();
  const av: any = app.agentsVM();

  const {
    // palette
    palOpen, palQ, palItems, palEmpty, onPalInput, closePalette, stop,
    // abort
    abortOpen, closeAbort, abortConfirm, abortWorking, abortDone, abortError,
    abortInfo, abortAck, toggleAbortAck, ackBorder, ackBg, simFail, toggleSimFail,
    doAbort, abortDisabled, abortBtnBg, abortBtnFg, abortBtnOp, retryAbort, camp,
    // role menu
    roleMenu, closeRoleMenu, roles,
    // toast + live region
    hasToast, toast, live,
  } = core;

  const { hasDecision, dv } = appr;
  const { catInfo } = av;
  const {
    surfaceEditOpen, sDraft, editOpen, eDraft, authOpen, authDraft,
    newTOpen, newTStep, newTStep1, newTStep2, newTStep3, newTNotStep1, newTNotStep3,
    newTName, newTVer, newTSynth, newTAdapters, newTEnvs, newTBaseUrl, newTHosts, newTCred,
    newTAdapterVal, newTEnvVal, newTSetName, newTSetVer, newTToggleSynth,
    newTSetBaseUrl, newTSetHosts, newTSetCred, newTCancel, newTNext, newTBack, newTCreate,
  } = tv;

  return (
    <>
      {/* MODEL CATALOG (simulated) */}
      {catInfo.open && (
        <div onClick={catInfo.close} className="scrim" style={{ position: "fixed", inset: 0, zIndex: 94, display: "flex", justifyContent: "center", alignItems: "center", padding: "24px", animation: "hs-fade .14s var(--ease-out)" }}>
          <div onClick={stop} role="dialog" aria-modal="true" aria-label="Model catalog" data-overlay="1" className="glass" style={{ width: "min(940px,96vw)", maxHeight: "88vh", display: "flex", flexDirection: "column", border: "1px solid var(--bd-2)", borderRadius: "var(--r-lg)", boxShadow: "var(--shadow)", overflow: "hidden" }}>
            <div style={{ flex: "0 0 auto", padding: "14px 16px", borderBottom: "1px solid var(--sep)", display: "flex", alignItems: "center", gap: "11px" }}>
              <div style={{ flex: 1, minWidth: 0 }}><div style={{ fontSize: "var(--fs-lg)", fontWeight: 600 }}>Model catalog</div><div className="lab" style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)" }}>Assign to {catInfo.forName} · {catInfo.count} models</div></div>
              <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "3px 8px", border: "1px solid var(--warn-line)", borderRadius: "var(--r-xs)", color: "var(--warn)", background: "var(--warn-t)", fontSize: "var(--fs-2xs)" }}>Simulated · no OpenRouter call</span>
              <button onClick={catInfo.cycleState} title="Simulate catalog state" aria-label="Simulate catalog state" style={{ minHeight: "30px", padding: "0 10px", border: "1px solid var(--bd-2)", borderRadius: "var(--r-sm)", background: "transparent", color: "var(--tx2)", fontSize: "var(--fs-2xs)", fontWeight: 600 }}>Simulate state</button>
              <button onClick={catInfo.close} aria-label="Close catalog" style={{ width: "30px", height: "30px", borderRadius: "var(--r-sm)", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--tx2)", background: "transparent" }}><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M6 6l12 12 M18 6L6 18"></path></svg></button>
            </div>
            <div style={{ flex: "0 0 auto", padding: "11px 16px", borderBottom: "1px solid var(--sep)", display: "flex", flexDirection: "column", gap: "9px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "9px", flexWrap: "wrap" }}>
                <div style={{ flex: 1, minWidth: "180px", display: "flex", alignItems: "center", gap: "8px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "0 10px", background: "var(--bg-inset)" }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M20 20l-3.2-3.2"></path></svg><input value={catInfo.q} onInput={catInfo.onQ} placeholder="Search model name or canonical ID" aria-label="Search models" style={{ flex: 1, minWidth: 0, background: "transparent", border: "none", outline: "none", color: "var(--tx)", fontSize: "var(--fs-sm)", height: "34px" }} /></div>
                <div style={{ display: "flex", alignItems: "center", gap: "6px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>Sort</span>{catInfo.sorts.map((s: any) => (<button key={s.id} onClick={s.onClick} style={{ padding: "4px 9px", borderRadius: "var(--r-pill)", border: "1px solid var(--bd)", fontSize: "var(--fs-2xs)", fontWeight: 600, background: s.bg, color: s.fg }}>{s.label}</button>))}</div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>{catInfo.providers.map((p: any) => (<button key={p.id} onClick={p.onClick} style={{ padding: "4px 9px", borderRadius: "var(--r-pill)", border: "1px solid var(--bd)", fontSize: "var(--fs-2xs)", fontWeight: 600, background: p.bg, color: p.fg }}>{p.label}</button>))}</div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}><span style={{ width: "7px", height: "7px", borderRadius: "50%", background: "var(--phos)" }}></span><span className="lab" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{catInfo.freshLabel}</span><button onClick={catInfo.refresh} style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: "5px", minHeight: "28px", padding: "0 10px", border: "1px solid var(--bd-2)", borderRadius: "var(--r-sm)", background: "transparent", color: "var(--tx2)", fontSize: "var(--fs-2xs)", fontWeight: 600 }}><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M20 11a8 8 0 1 0-2.3 5.7 M20 5v6h-6"></path></svg>Refresh</button></div>
              {catInfo.banner && (<div style={{ display: "flex", alignItems: "center", gap: "8px", padding: "8px 11px", border: "1px solid " + catInfo.bannerColor, borderRadius: "var(--r-sm)", fontSize: "var(--fs-xs)", color: "var(--tx)" }}><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke={catInfo.bannerColor} strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto" }}><path d="M12 3l9.5 17H2.5z M12 9.5v5 M12 17.5h.01"></path></svg>{catInfo.bannerText}</div>)}
            </div>
            <div style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
              {catInfo.loading && (<div style={{ padding: "40px", display: "flex", flexDirection: "column", alignItems: "center", gap: "11px", color: "var(--tx3)" }}><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="var(--brand)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ animation: "hs-spin 1s linear infinite" }}><path d="M12 3a9 9 0 1 0 9 9"></path></svg><span style={{ fontSize: "var(--fs-sm)" }}>Fetching account-filtered catalog…</span></div>)}
              {catInfo.showRows && (
                <>
                  <div style={{ display: "grid", gridTemplateColumns: "1.9fr 1fr 0.7fr 0.9fr 0.9fr 0.5fr", gap: "8px", padding: "8px 16px", borderBottom: "1px solid var(--bd)", background: "var(--bg-inset)", position: "sticky", top: 0 }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Model</span><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Provider</span><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Context</span><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>$ in/out</span><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Availability</span><span className="lab" style={{ fontSize: "var(--fs-2xs)", textAlign: "right" }}>Cmp</span></div>
                  {catInfo.rows.map((m: any) => (
                    <div key={m.id} style={{ display: "grid", gridTemplateColumns: "1.9fr 1fr 0.7fr 0.9fr 0.9fr 0.5fr", gap: "8px", padding: "10px 16px", borderBottom: "1px solid var(--sep)", alignItems: "center" }}>
                      <button onClick={m.onPick} style={{ textAlign: "left", minWidth: 0, background: "transparent" }}><span style={{ display: "flex", alignItems: "center", gap: "7px" }}><span style={{ fontSize: "var(--fs-sm)", fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{m.name}</span>{m.current && (<span className="lab" style={{ padding: "1px 6px", borderRadius: "var(--r-xs)", background: "var(--brand-tint)", color: "var(--brand)", fontSize: "var(--fs-2xs)", flex: "0 0 auto" }}>Current</span>)}</span><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", display: "block" }}>{m.id} · {m.mods}</span></button>
                      <span style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{m.provider}</span>
                      <span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>{m.ctx}</span>
                      <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx2)" }}>{m.inP}/{m.outP}</span>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-2xs)", fontWeight: 600, color: m.availColor }}><span style={{ width: "6px", height: "6px", borderRadius: "50%", background: m.availColor }}></span>{m.availLabel}</span>
                      <button onClick={m.onCompare} aria-label="Toggle compare" style={{ justifySelf: "end", width: "22px", height: "22px", borderRadius: "var(--r-xs)", border: "1px solid var(--bd-2)", display: "flex", alignItems: "center", justifyContent: "center", background: m.inCompare, color: "var(--tx2)" }}><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 7h16 M4 12h16 M4 17h10"></path></svg></button>
                    </div>
                  ))}
                </>
              )}
              {catInfo.rate && (<div style={{ padding: "40px", textAlign: "center", color: "var(--tx2)", fontSize: "var(--fs-sm)" }}>Rate-limited by the catalog provider. No silent substitution — retry the refresh shortly.</div>)}
              {catInfo.err && (<div style={{ padding: "40px", textAlign: "center", color: "var(--tx2)", fontSize: "var(--fs-sm)" }}>The catalog provider returned an error. The current assignment is unchanged — a model is never silently replaced.</div>)}
            </div>
            {catInfo.hasCompare && (
              <div style={{ flex: "0 0 auto", borderTop: "1px solid var(--sep)", padding: "11px 16px", background: "var(--bg-inset)" }}>
                <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Compare ({catInfo.compareN})</span>
                <div style={{ display: "flex", gap: "9px", marginTop: "8px", overflowX: "auto" }}>
                  {catInfo.compare.map((c: any, i: number) => (<div key={i} style={{ flex: "0 0 auto", minWidth: "150px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}><div style={{ fontSize: "var(--fs-sm)", fontWeight: 600 }}>{c.name}</div><div className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", marginTop: "3px" }}>ctx {c.ctx} · {c.inP}/{c.outP}</div><div style={{ fontSize: "var(--fs-2xs)", color: c.availColor, marginTop: "3px" }}>{c.avail}</div></div>))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ATTACK SURFACE EDITOR (drawer) */}
      {surfaceEditOpen && (
        <div onClick={sDraft.cancel} className="scrim" style={{ position: "fixed", inset: 0, zIndex: 93, display: "flex", justifyContent: "flex-end", animation: "hs-fade .14s var(--ease-out)" }}>
          <div onClick={stop} role="dialog" aria-modal="true" aria-label="Attack surface editor" data-overlay="1" style={{ width: "min(460px,94vw)", height: "100%", background: "var(--bg-panel)", borderLeft: "1px solid var(--bd-2)", boxShadow: "var(--shadow)", display: "flex", flexDirection: "column", animation: "hs-in .2s var(--ease-out)" }}>
            <div style={{ flex: "0 0 auto", padding: "15px 17px", borderBottom: "1px solid var(--sep)", display: "flex", alignItems: "center", gap: "10px" }}>
              <div style={{ flex: 1, minWidth: 0 }}><div style={{ fontSize: "var(--fs-lg)", fontWeight: 600 }}>{sDraft.title}</div><div className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{sDraft.id} · {sDraft.verLabel}</div></div>
              <button onClick={sDraft.cancel} aria-label="Close" style={{ width: "30px", height: "30px", borderRadius: "var(--r-sm)", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--tx2)", background: "transparent" }}><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M6 6l12 12 M18 6L6 18"></path></svg></button>
            </div>
            <div style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "16px 17px", display: "flex", flexDirection: "column", gap: "13px" }}>
              <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Name</span><input value={sDraft.name} onInput={sDraft.setName} placeholder="Surface name" aria-label="Surface name" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
              <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Type</span><div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "6px" }}>{sDraft.types.map((o: any) => (<button key={o.v} onClick={o.onClick} style={{ padding: "5px 11px", borderRadius: "var(--r-pill)", border: "1px solid var(--bd)", fontSize: "var(--fs-2xs)", fontWeight: 600, background: o.bg, color: o.fg }}>{o.label}</button>))}</div></div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "11px" }}>
                <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Risk</span><div style={{ display: "flex", flexWrap: "wrap", gap: "5px", marginTop: "6px" }}>{sDraft.risks.map((o: any) => (<button key={o.v} onClick={o.onClick} style={{ padding: "4px 9px", borderRadius: "var(--r-pill)", border: "1px solid var(--bd)", fontSize: "var(--fs-2xs)", fontWeight: 600, background: o.bg, color: o.fg }}>{o.v}</button>))}</div></div>
                <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Trust boundary</span><div style={{ display: "flex", flexWrap: "wrap", gap: "5px", marginTop: "6px" }}>{sDraft.trusts.map((o: any) => (<button key={o.v} onClick={o.onClick} style={{ padding: "4px 9px", borderRadius: "var(--r-pill)", border: "1px solid var(--bd)", fontSize: "var(--fs-2xs)", fontWeight: 600, background: o.bg, color: o.fg }}>{o.v}</button>))}</div></div>
              </div>
              <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Locator / route / resource</span><input value={sDraft.locator} onInput={sDraft.setLocator} placeholder="POST /v1/… · tool: … · index: …" aria-label="Locator" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "11px" }}>
                <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Authentication</span><input value={sDraft.auth} onInput={sDraft.setAuth} aria-label="Authentication" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "8px 10px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
                <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Categories</span><input value={sDraft.cats} onInput={sDraft.setCats} placeholder="inj · exfil …" aria-label="Categories" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "8px 10px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "11px" }}>
                <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>OWASP Web</span><input value={sDraft.ow} onInput={sDraft.setOw} aria-label="OWASP Web" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "8px 10px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
                <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>OWASP LLM</span><input value={sDraft.ol} onInput={sDraft.setOl} aria-label="OWASP LLM" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "8px 10px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
              </div>
              <button onClick={sDraft.toggleEnabled} role="switch" aria-checked={sDraft.enabled} style={{ display: "flex", alignItems: "center", gap: "10px", padding: "11px 13px", border: "1px solid var(--bd)", borderRadius: "var(--r-md)", background: "transparent", textAlign: "left" }}><span style={{ width: "20px", height: "20px", borderRadius: "var(--r-xs)", border: "1.5px solid var(--bd-2)", display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto", color: "var(--phos)" }}>{sDraft.enabled && (<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12l5 5 11-11"></path></svg>)}</span><span style={{ flex: 1 }}><span style={{ display: "block", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Enabled for evaluation</span><span style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>Disabled surfaces are excluded from campaigns</span></span></button>
            </div>
            <div style={{ flex: "0 0 auto", borderTop: "1px solid var(--sep)", padding: "12px 17px", display: "flex", gap: "9px" }}>
              <button onClick={sDraft.publish} style={{ flex: 1, minHeight: "38px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", border: "1px solid var(--brand)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>{sDraft.publishLabel}</button>
              <button onClick={sDraft.cancel} style={{ minHeight: "38px", padding: "0 15px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd-2)", background: "transparent", color: "var(--tx)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* NEW TARGET FLOW (guided) */}
      {newTOpen && (
        <div onClick={newTCancel} className="scrim" style={{ position: "fixed", inset: 0, zIndex: 93, display: "flex", justifyContent: "center", alignItems: "center", padding: "24px", animation: "hs-fade .14s var(--ease-out)" }}>
          <div onClick={stop} role="dialog" aria-modal="true" aria-label="Create target" data-overlay="1" className="glass" style={{ width: "min(560px,96vw)", maxHeight: "88vh", display: "flex", flexDirection: "column", border: "1px solid var(--bd-2)", borderRadius: "var(--r-lg)", boxShadow: "var(--shadow)", overflow: "hidden" }}>
            <div style={{ flex: "0 0 auto", padding: "15px 18px", borderBottom: "1px solid var(--sep)", display: "flex", alignItems: "center", gap: "10px" }}>
              <div style={{ flex: 1 }}><div style={{ fontSize: "var(--fs-lg)", fontWeight: 600 }}>New target</div><div className="lab" style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)" }}>Step {newTStep} of 3 · created in DRAFT</div></div>
              <button onClick={newTCancel} aria-label="Cancel" style={{ width: "30px", height: "30px", borderRadius: "var(--r-sm)", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--tx2)", background: "transparent" }}><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M6 6l12 12 M18 6L6 18"></path></svg></button>
            </div>
            <div style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "17px 18px", display: "flex", flexDirection: "column", gap: "13px" }}>
              {newTStep1 && (
                <>
                  <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Display name</span><input value={newTName} onInput={newTSetName} placeholder="e.g. Billing Agent" aria-label="Display name" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
                  <div style={{ display: "flex", alignItems: "center", gap: "9px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>System target ID assigned on create · immutable</span></div>
                  <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Version</span><input value={newTVer} onInput={newTSetVer} aria-label="Version" style={{ width: "140px", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
                  <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Adapter type</span><div style={{ display: "flex", gap: "6px", marginTop: "6px" }}>{newTAdapters.map((a: any) => (<button key={a.label} onClick={a.onClick} style={{ padding: "6px 12px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd)", fontSize: "var(--fs-sm)", fontWeight: 600, background: a.bg, color: a.fg }}>{a.label}</button>))}</div></div>
                  <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Environment</span><div style={{ display: "flex", gap: "6px", marginTop: "6px" }}>{newTEnvs.map((e: any) => (<button key={e.label} onClick={e.onClick} style={{ padding: "6px 12px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd)", fontSize: "var(--fs-sm)", fontWeight: 600, background: e.bg, color: e.fg }}>{e.label}</button>))}</div></div>
                </>
              )}
              {newTStep2 && (
                <>
                  <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Base URL</span><input value={newTBaseUrl} onInput={newTSetBaseUrl} placeholder="https://target.env.internal" aria-label="Base URL" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
                  <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Allowlisted hosts</span><input value={newTHosts} onInput={newTSetHosts} placeholder="host1.internal, host2.internal" aria-label="Allowlisted hosts" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
                  <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Credential reference</span><input value={newTCred} onInput={newTSetCred} placeholder="cb-… (reference only)" aria-label="Credential reference" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /><div style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", marginTop: "4px" }}>The secret value is never entered here.</div></div>
                  <button onClick={newTToggleSynth} role="switch" aria-checked={newTSynth} style={{ display: "flex", alignItems: "center", gap: "10px", padding: "11px 13px", border: "1px solid var(--bd)", borderRadius: "var(--r-md)", background: "transparent", textAlign: "left" }}><span style={{ width: "20px", height: "20px", borderRadius: "var(--r-xs)", border: "1.5px solid var(--bd-2)", display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto", color: "var(--phos)" }}>{newTSynth && (<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12l5 5 11-11"></path></svg>)}</span><span style={{ flex: 1 }}><span style={{ display: "block", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Synthetic-data attestation</span><span style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>I attest fixtures contain only synthetic data — synthetic data only · no production or personal data</span></span></button>
                </>
              )}
              {newTStep3 && (
                <>
                  <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", overflow: "hidden" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", padding: "10px 13px", borderBottom: "1px solid var(--sep)" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Name</span><span style={{ fontSize: "var(--fs-sm)", fontWeight: 600 }}>{newTName}</span></div>
                    <div style={{ display: "flex", justifyContent: "space-between", padding: "10px 13px", borderBottom: "1px solid var(--sep)" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Version</span><span className="mono" style={{ fontSize: "var(--fs-sm)" }}>{newTVer}</span></div>
                    <div style={{ display: "flex", justifyContent: "space-between", padding: "10px 13px", borderBottom: "1px solid var(--sep)" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Adapter</span><span style={{ fontSize: "var(--fs-sm)" }}>{newTAdapterVal}</span></div>
                    <div style={{ display: "flex", justifyContent: "space-between", padding: "10px 13px", borderBottom: "1px solid var(--sep)" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Environment</span><span style={{ fontSize: "var(--fs-sm)" }}>{newTEnvVal}</span></div>
                    <div style={{ display: "flex", justifyContent: "space-between", padding: "10px 13px" }}><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Synthetic attestation</span><span style={{ fontSize: "var(--fs-sm)" }}>{String(newTSynth)}</span></div>
                  </div>
                  <div style={{ display: "flex", alignItems: "flex-start", gap: "8px", fontSize: "var(--fs-xs)", color: "var(--tx2)", lineHeight: 1.5 }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto", marginTop: "1px" }}><path d="M12 3a9 9 0 1 0 9 9 M12 8v5 M12 16.5h.01"></path></svg>The target is created in DRAFT. It cannot be selected for a campaign until structural validation passes and a live-probe authorization is granted.</div>
                </>
              )}
            </div>
            <div style={{ flex: "0 0 auto", borderTop: "1px solid var(--sep)", padding: "12px 18px", display: "flex", alignItems: "center", gap: "9px" }}>
              {newTStep1 && (<button onClick={newTCancel} style={{ minHeight: "38px", padding: "0 15px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd-2)", background: "transparent", color: "var(--tx)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Cancel</button>)}
              {newTNotStep1 && (<button onClick={newTBack} style={{ minHeight: "38px", padding: "0 15px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd-2)", background: "transparent", color: "var(--tx)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Back</button>)}
              <div style={{ flex: 1 }}></div>
              {newTStep3 && (<button onClick={newTCreate} style={{ minHeight: "38px", padding: "0 16px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", border: "1px solid var(--brand)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Create target</button>)}
              {newTNotStep3 && (<button onClick={newTNext} style={{ minHeight: "38px", padding: "0 16px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", border: "1px solid var(--brand)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Continue</button>)}
            </div>
          </div>
        </div>
      )}

      {/* TARGET EDIT (drawer) */}
      {editOpen && (
        <div onClick={eDraft.cancel} className="scrim" style={{ position: "fixed", inset: 0, zIndex: 93, display: "flex", justifyContent: "flex-end", animation: "hs-fade .14s var(--ease-out)" }}>
          <div onClick={stop} role="dialog" aria-modal="true" aria-label="Edit target" data-overlay="1" style={{ width: "min(480px,96vw)", height: "100%", background: "var(--bg-panel)", borderLeft: "1px solid var(--bd-2)", boxShadow: "var(--shadow)", display: "flex", flexDirection: "column", animation: "hs-in .2s var(--ease-out)" }}>
            <div style={{ flex: "0 0 auto", padding: "15px 17px", borderBottom: "1px solid var(--sep)", display: "flex", alignItems: "center", gap: "10px" }}>
              <div style={{ flex: 1, minWidth: 0 }}><div style={{ fontSize: "var(--fs-lg)", fontWeight: 600 }}>Edit target</div><div className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{eDraft.id} · immutable id</div></div>
              <button onClick={eDraft.cancel} aria-label="Close" style={{ width: "30px", height: "30px", borderRadius: "var(--r-sm)", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--tx2)", background: "transparent" }}><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M6 6l12 12 M18 6L6 18"></path></svg></button>
            </div>
            <div style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "16px 17px", display: "flex", flexDirection: "column", gap: "12px" }}>
              <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "10px" }}>
                <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Display name</span><input value={eDraft.name} onInput={eDraft.setName} aria-label="Display name" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
                <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Version</span><input value={eDraft.ver} onInput={eDraft.setVer} aria-label="Version" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
              </div>
              <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Adapter type</span><div style={{ display: "flex", gap: "6px", marginTop: "6px" }}>{eDraft.adapters.map((a: any) => (<button key={a.label} onClick={a.onClick} style={{ padding: "6px 12px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd)", fontSize: "var(--fs-sm)", fontWeight: 600, background: a.bg, color: a.fg }}>{a.label}</button>))}</div></div>
              <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Environment</span><div style={{ display: "flex", gap: "6px", marginTop: "6px" }}>{eDraft.envs.map((e: any) => (<button key={e.label} onClick={e.onClick} style={{ padding: "6px 12px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd)", fontSize: "var(--fs-sm)", fontWeight: 600, background: e.bg, color: e.fg }}>{e.label}</button>))}</div></div>
              <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Base URL</span><input value={eDraft.baseUrl} onInput={eDraft.setBaseUrl} aria-label="Base URL" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
              <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Allowlisted hosts</span><input value={eDraft.hosts} onInput={eDraft.setHosts} aria-label="Allowlisted hosts" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
              <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Credential reference</span><input value={eDraft.cred} onInput={eDraft.setCred} aria-label="Credential reference" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /><div style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", marginTop: "4px" }}>Reference only — the secret value is never entered or stored.</div></div>
              <button onClick={eDraft.toggleSynth} role="switch" aria-checked={eDraft.synthVerified} style={{ display: "flex", alignItems: "center", gap: "10px", padding: "11px 13px", border: "1px solid var(--bd)", borderRadius: "var(--r-md)", background: "transparent", textAlign: "left" }}><span style={{ width: "20px", height: "20px", borderRadius: "var(--r-xs)", border: "1.5px solid var(--bd-2)", display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto", color: "var(--phos)" }}>{eDraft.synthVerified && (<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12l5 5 11-11"></path></svg>)}</span><span style={{ flex: 1 }}><span style={{ display: "block", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Synthetic-data attestation</span><span style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>Fixtures contain only synthetic data — synthetic data only · no production or personal data</span></span></button>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Budget</span><input value={eDraft.budget} onInput={eDraft.setBudget} aria-label="Budget" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "8px 10px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
                <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Rate limit</span><input value={eDraft.rate} onInput={eDraft.setRate} aria-label="Rate" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "8px 10px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
                <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Attempt cap</span><input value={eDraft.attemptCap} onInput={eDraft.setCap} aria-label="Attempt cap" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "8px 10px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
                <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Timeout</span><input value={eDraft.timeout} onInput={eDraft.setTimeoutV} aria-label="Timeout" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "8px 10px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
              </div>
              <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Canary / reference</span><input value={eDraft.canary} onInput={eDraft.setCanary} aria-label="Canary reference" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", background: "var(--bg-inset)", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "8px 10px", color: "var(--tx)", fontSize: "var(--fs-sm)", outline: "none" }} /></div>
              <div style={{ display: "flex", alignItems: "flex-start", gap: "8px", fontSize: "var(--fs-xs)", color: "var(--tx2)", lineHeight: 1.5, border: "1px solid var(--warn-line)", borderRadius: "var(--r-md)", background: "var(--warn-t)", padding: "10px 12px" }}><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--warn)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto", marginTop: "1px" }}><path d="M12 3l9.5 17H2.5z M12 9.5v5 M12 17.5h.01"></path></svg>Changing base URL, hosts, credential, adapter, or environment invalidates readiness and any live-probe authorization — the target returns to VALIDATING and must be re-authorized.</div>
            </div>
            <div style={{ flex: "0 0 auto", borderTop: "1px solid var(--sep)", padding: "12px 17px", display: "flex", gap: "9px" }}>
              <button onClick={eDraft.save} style={{ flex: 1, minHeight: "38px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", border: "1px solid var(--brand)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Save changes</button>
              <button onClick={eDraft.cancel} style={{ minHeight: "38px", padding: "0 15px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd-2)", background: "transparent", color: "var(--tx)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* AUTHORIZE LIVE PROBE (two-person) */}
      {authOpen && (
        <div onClick={authDraft.cancel} className="scrim" style={{ position: "fixed", inset: 0, zIndex: 94, display: "flex", justifyContent: "center", alignItems: "center", padding: "24px", animation: "hs-fade .14s var(--ease-out)" }}>
          <div onClick={stop} role="dialog" aria-modal="true" aria-label="Authorize live probe" data-overlay="1" className="glass" style={{ width: "min(520px,96vw)", border: "1px solid var(--bd-2)", borderRadius: "var(--r-lg)", boxShadow: "var(--shadow)", overflow: "hidden" }}>
            <div style={{ padding: "16px 18px", borderBottom: "1px solid var(--sep)" }}><div style={{ fontSize: "var(--fs-lg)", fontWeight: 600 }}>Authorize live probe</div><div className="lab" style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)" }}>{authDraft.target} · scope {authDraft.scope}</div></div>
            <div style={{ padding: "16px 18px", display: "flex", flexDirection: "column", gap: "12px" }}>
              <div style={{ display: "flex", alignItems: "flex-start", gap: "9px", padding: "11px 13px", border: "1px solid var(--bd)", borderRadius: "var(--r-md)", background: "var(--bg-inset)" }}><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="var(--phos)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto", marginTop: "1px" }}><path d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M5 20a7 7 0 0 1 14 0"></path></svg><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx)", lineHeight: 1.5 }}>Two-person rule: <strong>{authDraft.principal}</strong> (approver) authorizing — distinct from launcher <strong>{authDraft.launcher}</strong>. Live probing contacts the target; the authorization and its scope are written to the audit log.</div></div>
              <div><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>Authorization rationale (required)</span><textarea value={authDraft.rationale} onInput={authDraft.setRationale} placeholder="Why this target may be probed live now" aria-label="Authorization rationale" style={{ width: "100%", boxSizing: "border-box", marginTop: "5px", minHeight: "64px", resize: "vertical", background: "var(--bg-inset)", border: "1px solid " + (authDraft.err ? "var(--v-conf)" : "var(--bd)"), borderRadius: "var(--r-sm)", padding: "9px 11px", color: "var(--tx)", fontSize: "var(--fs-sm)", fontFamily: "inherit", outline: "none" }}></textarea>{authDraft.err && (<div style={{ fontSize: "var(--fs-xs)", color: "var(--v-conf)", marginTop: "5px" }}>A rationale is required to authorize live probing.</div>)}</div>
            </div>
            <div style={{ borderTop: "1px solid var(--sep)", padding: "12px 18px", display: "flex", gap: "9px", justifyContent: "flex-end" }}>
              <button onClick={authDraft.cancel} style={{ minHeight: "38px", padding: "0 15px", borderRadius: "var(--r-sm)", border: "1px solid var(--bd-2)", background: "transparent", color: "var(--tx)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Cancel</button>
              <button onClick={authDraft.confirm} style={{ minHeight: "38px", padding: "0 16px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", border: "1px solid var(--brand)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>Authorize probe</button>
            </div>
          </div>
        </div>
      )}

      {/* ROLE / PRINCIPAL MENU (prototype) */}
      {roleMenu && (
        <div onClick={closeRoleMenu} style={{ position: "fixed", inset: 0, zIndex: 88 }}>
          <div onClick={stop} role="dialog" aria-modal="true" aria-label="Switch signed-in principal (prototype)" data-overlay="1" className="glass-sm" style={{ position: "fixed", left: "12px", bottom: "66px", width: "256px", maxWidth: "90vw", border: "1px solid var(--bd-2)", borderRadius: "var(--r-lg)", overflow: "hidden", transformOrigin: "bottom left", animation: "hs-pop .16s var(--ease-out)" }}>
            <div style={{ padding: "10px 13px", borderBottom: "1px solid var(--sep)" }}><span className="lab">Signed in as</span></div>
            {roles.map((r: any, i: number) => (
              <button key={i} onClick={r.onClick} aria-current={r.active} style={{ width: "100%", display: "flex", alignItems: "center", gap: "10px", padding: "9px 13px", textAlign: "left", background: r.bg }}>
                <span style={{ width: "26px", height: "26px", borderRadius: "var(--r-md)", background: "var(--brand-tint)", color: "var(--brand)", fontSize: "var(--fs-2xs)", fontWeight: 600, display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}>{r.initials}</span>
                <span style={{ flex: 1, minWidth: 0 }}><span style={{ display: "block", fontSize: "var(--fs-base)", fontWeight: 500 }}>{r.name}</span><span className="lab" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{r.roleLine}</span></span>
                {r.active && (<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--brand)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12.5l5 5 11-11"></path></svg>)}
              </button>
            ))}
            <div style={{ padding: "8px 13px", borderTop: "1px solid var(--sep)" }}><span className="lab" style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)" }}>Prototype review control · demonstrates permission &amp; two-person states</span></div>
          </div>
        </div>
      )}

      {/* COMMAND PALETTE */}
      {palOpen && (
        <div onClick={closePalette} className="scrim" style={{ position: "fixed", inset: 0, zIndex: 80, display: "flex", justifyContent: "center", alignItems: "flex-start", paddingTop: "12vh" }}>
          <div onClick={stop} role="dialog" aria-modal="true" aria-label="Command palette" data-overlay="1" className="glass" style={{ width: "min(600px,92vw)", border: "1px solid var(--bd-2)", borderRadius: "var(--r-lg)", overflow: "hidden" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", padding: "13px 15px", borderBottom: "1px solid var(--sep)" }}>
              <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M20 20l-3.6-3.6"></path></svg>
              <input autoFocus data-autofocus value={palQ} onInput={onPalInput} placeholder="Search screens, findings, targets, actions…" style={{ flex: 1, background: "none", border: "none", outline: "none", fontSize: "var(--fs-md)", color: "var(--tx)" }} />
              <span className="mono" style={{ fontSize: "var(--fs-2xs)", padding: "2px 6px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", color: "var(--tx3)" }}>esc</span>
            </div>
            <div style={{ maxHeight: "min(52vh,420px)", overflowY: "auto", padding: "7px" }}>
              {palItems.map((p: any, i: number) => (
                <button key={i} onClick={p.run} style={{ width: "100%", display: "flex", alignItems: "center", gap: "11px", padding: "9px 11px", borderRadius: "var(--r-sm)", textAlign: "left", background: p.bg }}>
                  <span style={{ width: "26px", height: "26px", borderRadius: "var(--r-sm)", background: p.iconBg, color: p.iconFg, display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}>{p.iconEl}</span>
                  <span style={{ flex: 1, minWidth: 0 }}><span style={{ display: "block", fontSize: "var(--fs-base)", fontWeight: 500, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{p.label}</span><span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>{p.group}</span></span>
                  <span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>{p.hint}</span>
                </button>
              ))}
              {palEmpty && (
                <div style={{ padding: "26px", textAlign: "center", color: "var(--tx3)", fontSize: "var(--fs-base)" }}>No matches for “{palQ}”.</div>
              )}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "14px", padding: "8px 15px", borderTop: "1px solid var(--sep)", color: "var(--tx3)" }}>
              <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "5px" }}><span className="mono" style={{ padding: "1px 5px", border: "1px solid var(--bd)", borderRadius: "3px" }}>↑↓</span>navigate</span>
              <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "5px" }}><span className="mono" style={{ padding: "1px 5px", border: "1px solid var(--bd)", borderRadius: "3px" }}>↵</span>select</span>
            </div>
          </div>
        </div>
      )}

      {/* ABORT DIALOG */}
      {abortOpen && (
        <div onClick={closeAbort} className="scrim" style={{ position: "fixed", inset: 0, zIndex: 90, display: "flex", alignItems: "center", justifyContent: "center", padding: "24px", animation: "hs-fade .14s var(--ease-out)" }}>
          <div onClick={stop} role="dialog" aria-modal="true" aria-label="Abort campaign confirmation" data-overlay="1" className="glass" style={{ width: "min(540px,94vw)", border: "1px solid var(--v-conf)", borderRadius: "var(--r-lg)", overflow: "hidden", animation: "hs-pop .18s var(--ease-out)" }}>
            {abortConfirm && (
              <div style={{ padding: "18px 20px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "11px", marginBottom: "14px" }}>
                  <span style={{ width: "34px", height: "34px", borderRadius: "var(--r-md)", background: "var(--v-conf-t)", border: "1px solid var(--v-conf)", color: "var(--v-conf)", display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M8.5 3h7l5 5v7l-5 5h-7l-5-5V8z M9.5 12h5"></path></svg></span>
                  <div><div style={{ fontSize: "var(--fs-xl)", fontWeight: 600 }}>Abort campaign {camp.run}?</div><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "1px" }}>This stops all adversarial testing against the target.</div></div>
                </div>
                <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", overflow: "hidden", marginBottom: "14px" }}>
                  {abortInfo.map((r: any, i: number) => (
                    <div key={i} style={{ display: "flex", gap: "12px", padding: "9px 12px", borderBottom: "1px solid var(--sep)" }}><span className="lab" style={{ width: "130px", flex: "0 0 auto", paddingTop: "1px" }}>{r.k}</span><span style={{ fontSize: "var(--fs-sm)", color: "var(--tx)" }}>{r.v}</span></div>
                  ))}
                </div>
                <label style={{ display: "flex", alignItems: "center", gap: "9px", marginBottom: "14px", cursor: "pointer", fontSize: "var(--fs-base)", color: "var(--tx2)" }}>
                  <button onClick={toggleAbortAck} role="checkbox" aria-checked={abortAck} style={{ width: "18px", height: "18px", borderRadius: "var(--r-xs)", border: "1.5px solid " + ackBorder, background: ackBg, display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}>{abortAck && (<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12.5l5 5 11-11"></path></svg>)}</button>
                  I understand queued attempts will be cancelled and in-flight execution will be recorded, then stopped.
                </label>
                <label style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px", cursor: "pointer", fontSize: "var(--fs-xs)", color: "var(--tx3)" }}><button onClick={toggleSimFail} role="checkbox" aria-checked={simFail} aria-label="Simulate a failed abort — prototype review control" style={{ width: "15px", height: "15px", borderRadius: "var(--r-xs)", border: "1.5px solid var(--bd-2)", display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}>{simFail && (<svg viewBox="0 0 24 24" width="10" height="10" fill="none" stroke="var(--warn)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12.5l5 5 11-11"></path></svg>)}</button><span className="lab" style={{ fontSize: "var(--fs-2xs)", color: "var(--warn)" }}>prototype</span> Simulate a recoverable failure</label>
                <div style={{ display: "flex", gap: "9px", justifyContent: "flex-end" }}>
                  <button onClick={closeAbort} style={{ padding: "9px 15px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", fontSize: "var(--fs-base)", fontWeight: 500, color: "var(--tx)" }}>Keep running</button>
                  <button onClick={doAbort} disabled={abortDisabled} style={{ padding: "9px 16px", borderRadius: "var(--r-sm)", fontSize: "var(--fs-base)", fontWeight: 600, background: abortBtnBg, color: abortBtnFg, opacity: abortBtnOp }}>Abort campaign</button>
                </div>
              </div>
            )}
            {abortWorking && (
              <div style={{ padding: "34px 20px", display: "flex", flexDirection: "column", alignItems: "center", gap: "13px", textAlign: "center" }}>
                <span style={{ width: "30px", height: "30px", border: "3px solid var(--bd)", borderTopColor: "var(--v-conf)", borderRadius: "50%", animation: "hs-spin .7s linear infinite" }}></span>
                <div style={{ fontSize: "var(--fs-md)", fontWeight: 600 }}>Propagating abort…</div>
                <div className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>Cancelling queued work · draining in-flight execution</div>
              </div>
            )}
            {abortDone && (
              <div style={{ padding: "24px 20px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "11px", marginBottom: "13px" }}>
                  <span style={{ width: "34px", height: "34px", borderRadius: "var(--r-md)", background: "var(--phos-tint)", border: "1px solid var(--phos-line)", color: "var(--phos)", display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12.5l5 5 11-11"></path></svg></span>
                  <div><div style={{ fontSize: "var(--fs-xl)", fontWeight: 600 }}>Campaign aborted</div><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "1px" }}>{camp.run} · {camp.target} {camp.ver}</div></div>
                </div>
                <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "11px 13px", marginBottom: "14px", display: "flex", flexDirection: "column", gap: "6px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "var(--fs-sm)" }}><span style={{ color: "var(--tx3)" }}>Queued attempts</span><span className="mono" style={{ color: "var(--v-err)" }}>6 cancelled</span></div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "var(--fs-sm)" }}><span style={{ color: "var(--tx3)" }}>In-flight execution</span><span className="mono" style={{ color: "var(--tx2)" }}>2 recorded &amp; stopped</span></div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "var(--fs-sm)" }}><span style={{ color: "var(--tx3)" }}>Partial evidence</span><span className="mono" style={{ color: "var(--v-clear)" }}>retained</span></div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "var(--fs-sm)" }}><span style={{ color: "var(--tx3)" }}>Audit event</span><span className="mono" style={{ color: "var(--tx2)" }}>written · 02:47:1X</span></div>
                </div>
                <div style={{ display: "flex", justifyContent: "flex-end" }}><button onClick={closeAbort} style={{ padding: "9px 16px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", fontSize: "var(--fs-base)", fontWeight: 600 }}>Done</button></div>
              </div>
            )}
            {abortError && (
              <div style={{ padding: "22px 20px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "11px", marginBottom: "12px" }}><span style={{ width: "34px", height: "34px", borderRadius: "var(--r-md)", background: "var(--v-err-t)", border: "1px solid var(--v-err)", color: "var(--v-err)", display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M8.5 3h7l5 5v7l-5 5h-7l-5-5V8z M12 8v5 M12 16.5h.01"></path></svg></span><div><div style={{ fontSize: "var(--fs-xl)", fontWeight: 600 }}>Abort did not complete</div><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "1px" }}>The campaign is still running — no changes were made.</div></div></div>
                <p style={{ margin: "0 0 14px", fontSize: "var(--fs-sm)", lineHeight: 1.5, color: "var(--tx2)" }}>The abort signal was not acknowledged by the control plane. Queued work was not cancelled and evidence is unchanged, so it is safe to retry.</p>
                <div style={{ display: "flex", gap: "9px", justifyContent: "flex-end" }}><button onClick={closeAbort} style={{ padding: "9px 15px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", fontSize: "var(--fs-base)", fontWeight: 500, color: "var(--tx)" }}>Cancel</button><button onClick={retryAbort} style={{ padding: "9px 16px", borderRadius: "var(--r-sm)", background: "var(--v-conf)", color: "#fff", fontSize: "var(--fs-base)", fontWeight: 600 }}>Retry abort</button></div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* DECISION SHEET */}
      {hasDecision && (
        <div onClick={dv.onCancel} className="scrim" style={{ position: "fixed", inset: 0, zIndex: 92, display: "flex", justifyContent: "center", alignItems: dv.sheetAlign, padding: dv.overlayPad, animation: "hs-fade .14s var(--ease-out)" }}>
          <div onClick={stop} ref={dv.sheetRef} role="dialog" aria-modal="true" aria-label="Confirm decision" data-overlay="1" className="glass" style={{ width: "100%", maxWidth: dv.sheetMaxW, border: "1px solid var(--bd-2)", borderRadius: dv.sheetRadius, overflow: "hidden", animation: "hs-sheet .2s var(--ease-out)" }}>
            {dv.dragGrab && (<div onPointerDown={dv.onDragStart} onPointerMove={dv.onDragMove} onPointerUp={dv.onDragEnd} onPointerCancel={dv.onDragEnd} role="separator" aria-label="Drag down to dismiss" style={{ touchAction: "none", cursor: "grab", display: "flex", justifyContent: "center", padding: "9px 0 2px" }}><span style={{ width: "38px", height: "4px", borderRadius: "var(--r-pill)", background: "var(--bd-2)" }}></span></div>)}

            {dv.isForm && (
              <div style={{ padding: "18px 20px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}><span className="lab" style={{ color: "var(--tx3)" }}>Confirm decision</span><span className="mono" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)", marginLeft: "auto" }}>{dv.fid}</span></div>
                <div style={{ fontSize: "var(--fs-2xl)", fontWeight: 600, marginBottom: "12px" }}>{dv.label}</div>
                <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "12px 13px", background: "var(--bg-inset)", marginBottom: "14px" }}>
                  <span className="lab" style={{ color: "var(--tx3)" }}>What happens</span>
                  <p style={{ margin: "6px 0 0", fontSize: "var(--fs-base)", lineHeight: 1.5, color: "var(--tx)" }}>{dv.cons}</p>
                </div>
                {dv.needsNote && (
                  <div style={{ marginBottom: "14px" }}>
                    <span className="lab" style={{ color: "var(--tx2)" }}>Rationale <span style={{ color: "var(--v-conf)" }}>· required</span></span>
                    <textarea value={dv.note} onInput={dv.onNote} placeholder="Record why — this is written to the audit log and the finding history." rows={3} style={{ marginTop: "6px", width: "100%", resize: "vertical", background: "var(--bg-inset)", border: "1px solid " + dv.noteBorder, borderRadius: "var(--r-sm)", padding: "9px 11px", fontSize: "var(--fs-base)", lineHeight: 1.45, color: "var(--tx)", outline: "none" }}></textarea>
                    {dv.noteError && (<span style={{ fontSize: "var(--fs-xs)", color: "var(--v-conf)", marginTop: "4px", display: "block" }}>A rationale is required to record this decision.</span>)}
                  </div>
                )}
                <label style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px", cursor: "pointer", fontSize: "var(--fs-xs)", color: "var(--tx3)" }}><button onClick={dv.onSimFail} role="checkbox" aria-checked={dv.simFail} aria-label="Simulate a failed submission — prototype review control" style={{ width: "15px", height: "15px", borderRadius: "var(--r-xs)", border: "1.5px solid var(--bd-2)", display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}>{dv.simFail && (<svg viewBox="0 0 24 24" width="10" height="10" fill="none" stroke="var(--warn)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12.5l5 5 11-11"></path></svg>)}</button><span className="lab" style={{ fontSize: "var(--fs-2xs)", color: "var(--warn)" }}>prototype</span> Simulate a recoverable failure</label>
                <div style={{ display: "flex", gap: "9px", justifyContent: "flex-end" }}>
                  <button onClick={dv.onCancel} style={{ padding: "10px 16px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", fontSize: "var(--fs-base)", fontWeight: 500 }}>Cancel</button>
                  <button onClick={dv.onConfirm} style={{ padding: "10px 18px", borderRadius: "var(--r-sm)", fontSize: "var(--fs-base)", fontWeight: 600, background: dv.btnBg, color: dv.btnFg, border: "1px solid transparent" }}>{dv.label}</button>
                </div>
              </div>
            )}

            {dv.isSubmitting && (
              <div style={{ padding: "38px 20px", display: "flex", flexDirection: "column", alignItems: "center", gap: "13px", textAlign: "center" }}>
                <span style={{ width: "30px", height: "30px", border: "3px solid var(--bd)", borderTopColor: "var(--brand)", borderRadius: "50%", animation: "hs-spin .7s linear infinite" }}></span>
                <div style={{ fontSize: "var(--fs-md)", fontWeight: 600 }}>Submitting…</div>
                <div className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>Recording decision · awaiting durable acknowledgment</div>
              </div>
            )}

            {dv.isDone && (
              <div style={{ padding: "22px 20px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "11px", marginBottom: "13px" }}>
                  <span style={{ width: "34px", height: "34px", borderRadius: "var(--r-md)", background: "var(--phos-tint)", border: "1px solid var(--phos-line)", color: "var(--phos)", display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12.5l5 5 11-11"></path></svg></span>
                  <div><div style={{ fontSize: "var(--fs-xl)", fontWeight: 600 }}>Acknowledged</div><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "1px" }}>{dv.label} · {dv.fid}</div></div>
                </div>
                <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", overflow: "hidden", marginBottom: "14px" }}>
                  {dv.summary.map((s: any, i: number) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: "9px", padding: "9px 12px", borderBottom: "1px solid var(--sep)" }}><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="var(--phos)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12.5l5 5 11-11"></path></svg><span style={{ fontSize: "var(--fs-sm)", color: "var(--tx)" }}>{s}</span></div>
                  ))}
                </div>
                <div style={{ display: "flex", justifyContent: "flex-end" }}><button onClick={dv.onDone} style={{ padding: "10px 18px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", fontSize: "var(--fs-base)", fontWeight: 600 }}>Done</button></div>
              </div>
            )}

            {dv.isError && (
              <div style={{ padding: "20px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "11px", marginBottom: "12px" }}><span style={{ width: "34px", height: "34px", borderRadius: "var(--r-md)", background: "var(--v-err-t)", border: "1px solid var(--v-err)", color: "var(--v-err)", display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M8.5 3h7l5 5v7l-5 5h-7l-5-5V8z M12 8v5 M12 16.5h.01"></path></svg></span><div><div style={{ fontSize: "var(--fs-xl)", fontWeight: 600 }}>Submission failed</div><div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", marginTop: "1px" }}>{dv.label} · {dv.fid} — not applied</div></div></div>
                <p style={{ margin: "0 0 12px", fontSize: "var(--fs-sm)", lineHeight: 1.5, color: "var(--tx2)" }}>The decision was not acknowledged, so nothing changed — the queue, finding, and audit record are untouched. Your rationale is preserved.</p>
                <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px", background: "var(--bg-inset)", marginBottom: "14px" }}><span className="lab" style={{ color: "var(--tx3)" }}>Rationale · preserved</span><p style={{ margin: "5px 0 0", fontSize: "var(--fs-sm)", color: "var(--tx)" }}>{dv.note}</p></div>
                <div style={{ display: "flex", gap: "9px", justifyContent: "flex-end" }}><button onClick={dv.onCancel} style={{ padding: "10px 16px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", fontSize: "var(--fs-base)", fontWeight: 500 }}>Cancel</button><button onClick={dv.onRetry} style={{ padding: "10px 18px", borderRadius: "var(--r-sm)", background: "var(--brand)", color: "#fff", fontSize: "var(--fs-base)", fontWeight: 600 }}>Retry</button></div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TOAST */}
      {hasToast && (
        <div className="glass-sm" style={{ position: "fixed", bottom: "20px", left: "50%", transform: "translateX(-50%)", zIndex: 95, display: "flex", alignItems: "center", gap: "10px", padding: "11px 16px", border: "1px solid var(--bd-2)", borderRadius: "var(--r-md)", animation: "hs-sheet .2s var(--ease-out)", maxWidth: "90vw" }}>
          <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: toast.color, flex: "0 0 auto" }}></span>
          <span style={{ fontSize: "var(--fs-base)", color: "var(--tx)" }}>{toast.msg}</span>
        </div>
      )}

      {/* Visually-hidden live region — screen-reader announcements (app.state.live) */}
      <div
        role="status"
        aria-live="polite"
        aria-atomic="true"
        style={{ position: "absolute", width: "1px", height: "1px", padding: 0, margin: "-1px", overflow: "hidden", clip: "rect(0 0 0 0)", whiteSpace: "nowrap", border: 0 }}
      >
        {live}
      </div>
    </>
  );
}
