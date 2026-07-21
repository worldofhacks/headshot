/*
 * TopBar — the main <header>. Faithful 1:1 port of Headshot Console.dc.html
 * lines 164–226. Reads the shell view-model from `app.core()`:
 *   camp / campColor            — campaign context + state channel
 *   showAttest                  — synthetic-data / allowlist / auth chips (xl only)
 *   toggleScenario / scenarioBtnLabel / scenarioBtnColor  — Demo ⇄ Integration
 *   openPalette                 — ⌘K command-palette trigger
 *   goApprovals / hasAppr / apprCount — approvals bell + badge
 *   setDesktop / setMobile + deskBg/deskFg/mobBg/mobFg  — surface toggle
 *   toggleTheme / isDark / isLight — theme toggle
 *   openAbort                   — guarded Abort
 *
 * Every status channel keeps icon + shape + label (never color alone). The four
 * top-bar attestation chips are honest platform facts (synthetic data / allowlisted
 * / authorized), matching the frozen prototype exactly.
 */
import type { ScreenProps } from "../types";

export function TopBar({ app }: ScreenProps) {
  const vm = app.core();
  const camp = vm.camp as any;

  return (
    <header style={{ height: "52px", flex: "0 0 auto", background: "var(--bg-head)", borderBottom: "1px solid var(--bd)", display: "flex", alignItems: "center", gap: "12px", padding: "0 14px", overflow: "hidden" }}>
      {/* campaign context */}
      <div style={{ display: "flex", alignItems: "center", gap: "9px", flex: "0 1 auto", minWidth: 0, overflow: "hidden", whiteSpace: "nowrap" }}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: "7px", padding: "5px 10px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "var(--bg-panel)", whiteSpace: "nowrap" }}>
          <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "var(--phos)", boxShadow: "0 0 0 3px var(--phos-tint)", animation: "hs-pulse 2.4s ease-in-out infinite" }} />
          <span className="mono" style={{ fontSize: "var(--fs-sm)", fontWeight: 600 }}>{camp.run}</span>
          <span style={{ fontSize: "var(--fs-base)", color: "var(--tx2)" }}>·</span>
          <span style={{ fontSize: "var(--fs-base)", fontWeight: 500, display: "inline-block", maxWidth: "190px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", verticalAlign: "bottom" }}>{camp.target}</span>
          <span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx2)" }}>{camp.ver}</span>
          {vm.showAttest && (
            <span className="lab" style={{ fontSize: "var(--fs-2xs)", padding: "1px 5px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", color: "var(--tx2)" }}>{camp.env}</span>
          )}
        </span>
      </div>

      {/* campaign state channel */}
      <span aria-live="polite" title="Campaign state" style={{ flex: "0 0 auto", display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "var(--fs-sm)", fontWeight: 500, color: vm.campColor as string, whiteSpace: "nowrap" }}>
        <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: vm.campColor as string }} />
        {camp.state}
      </span>

      {/* synthetic-data / allowlist / auth attestation chips (xl) */}
      {vm.showAttest && (
        <div style={{ display: "flex", alignItems: "center", gap: "7px", marginLeft: "4px", flex: "0 1 auto", minWidth: 0, overflow: "hidden" }}>
          <span className="lab" title="Synthetic fixtures only" style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "4px 8px", border: "1px solid var(--phos-line)", borderRadius: "var(--r-xs)", color: "var(--phos)", background: "var(--phos-tint)", fontSize: "var(--fs-2xs)" }}>
            <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12.5l5 5 11-11" /></svg>Synthetic data
          </span>
          <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "4px 8px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", color: "var(--tx2)", fontSize: "var(--fs-2xs)" }}>Allowlisted</span>
          <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "4px 8px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", color: "var(--tx2)", fontSize: "var(--fs-2xs)" }}>Authorized</span>
        </div>
      )}

      <div style={{ flex: 1 }} />

      <div style={{ display: "flex", alignItems: "center", gap: "6px", flex: "0 0 auto" }}>
        {/* Demo ⇄ Integration */}
        <button
          onClick={vm.toggleScenario as () => void}
          title="Data source — click to toggle Demo scenario / Integration state"
          aria-label={"Data source: " + (vm.scenarioBtnLabel as string)}
          style={{ display: "inline-flex", alignItems: "center", gap: "6px", height: "32px", padding: "0 11px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "var(--bg-panel)", fontSize: "var(--fs-sm)", color: vm.scenarioBtnColor as string, fontWeight: 500 }}
        >
          <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: vm.scenarioBtnColor as string }} />{vm.scenarioBtnLabel}
        </button>

        {/* command palette */}
        <button
          onClick={vm.openPalette as () => void}
          title="Command palette"
          aria-label="Open command palette"
          aria-keyshortcuts="Meta+K"
          style={{ display: "flex", alignItems: "center", gap: "8px", height: "32px", padding: "0 9px 0 10px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "var(--bg-panel)", color: "var(--tx2)" }}
        >
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M20 20l-3.6-3.6" /></svg>
          <span style={{ fontSize: "var(--fs-sm)" }}>Search</span>
          <span className="mono" style={{ fontSize: "var(--fs-xs)", padding: "2px 5px", border: "1px solid var(--bd)", borderRadius: "var(--r-xs)", color: "var(--tx3)" }}>⌘K</span>
        </button>

        {/* approvals bell */}
        <button
          onClick={vm.goApprovals as () => void}
          aria-label={vm.hasAppr ? "Pending approvals — " + vm.apprCount + " pending" : "Pending approvals — none"}
          title="Pending approvals"
          style={{ position: "relative", width: "32px", height: "32px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--tx2)" }}
        >
          <svg aria-hidden="true" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M6.5 9a5.5 5.5 0 0 1 11 0c0 5.5 2.5 6 2.5 7.5H4C4 15 6.5 14.5 6.5 9z M10 20a2 2 0 0 0 4 0" /></svg>
          {vm.hasAppr && (
            <span aria-hidden="true" className="mono" style={{ position: "absolute", top: "-6px", right: "-6px", minWidth: "16px", height: "16px", padding: "0 4px", borderRadius: "var(--r-md)", background: "var(--warn)", color: "var(--tx-inv)", fontSize: "var(--fs-2xs)", fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", border: "2px solid var(--bg-head)" }}>{vm.apprCount}</span>
          )}
        </button>

        {/* surface toggle (desktop / mobile) */}
        <div style={{ display: "flex", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", overflow: "hidden" }}>
          <button onClick={vm.setDesktop as () => void} title="Desktop" style={{ width: "30px", height: "32px", display: "flex", alignItems: "center", justifyContent: "center", background: vm.deskBg as string, color: vm.deskFg as string }}>
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M3 5h18v11H3z M9 20h6 M12 16v4" /></svg>
          </button>
          <button onClick={vm.setMobile as () => void} title="Mobile" style={{ width: "30px", height: "32px", display: "flex", alignItems: "center", justifyContent: "center", borderLeft: "1px solid var(--bd)", background: vm.mobBg as string, color: vm.mobFg as string }}>
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M8 3h8a1.5 1.5 0 0 1 1.5 1.5v15A1.5 1.5 0 0 1 16 21H8a1.5 1.5 0 0 1-1.5-1.5v-15A1.5 1.5 0 0 1 8 3z M10.5 18h3" /></svg>
          </button>
        </div>

        {/* theme toggle */}
        <button onClick={vm.toggleTheme as () => void} title="Toggle theme" style={{ width: "32px", height: "32px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--tx2)" }}>
          {(vm.isDark as boolean) && (
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z" /></svg>
          )}
          {(vm.isLight as boolean) && (
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10z M12 2v2 M12 20v2 M4 12H2 M22 12h-2 M5.6 5.6L4.2 4.2 M19.8 19.8l-1.4-1.4 M18.4 5.6l1.4-1.4 M4.2 19.8l1.4-1.4" /></svg>
          )}
        </button>

        {/* guarded Abort */}
        <button
          onClick={vm.openAbort as () => void}
          aria-label="Abort campaign RUN 042"
          style={{ display: "flex", alignItems: "center", gap: "7px", height: "32px", padding: "0 13px", borderRadius: "var(--r-sm)", background: "var(--v-conf-t)", border: "1px solid var(--v-conf)", color: "var(--v-conf)", fontWeight: 600, fontSize: "var(--fs-sm)" }}
        >
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M8.5 3h7l5 5v7l-5 5h-7l-5-5V8z M9.5 12h5" /></svg>Abort
        </button>
      </div>
    </header>
  );
}
