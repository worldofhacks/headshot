/*
 * Sidebar — left navigation rail. Faithful 1:1 port of Headshot Console.dc.html
 * lines 110–163 (the <aside>). Reads the shell view-model from `app.core()`:
 *   nav[]  (id, label, iconEl, go, active, aria, fg, bg, rail, hasBadge, badge)
 *   navExpanded / navJustify  (collapse to a 64px rail below xl)
 *   operator (currentPrincipal) + openRole
 *
 * Wordmark glyph is inline SVG (template 114–125). Selected item gets the
 * mineral-cobalt (--brand) rail + aria-current="page".
 */
import type { ScreenProps } from "../types";
import { Icon } from "./Icon";

export function Sidebar({ app }: ScreenProps) {
  const vm = app.core();
  const nav = vm.nav as any[];
  const navExpanded = vm.navExpanded as boolean;
  const navJustify = vm.navJustify as string;
  const operator = vm.operator as any;

  return (
    <aside style={{ background: "var(--bg-panel)", borderRight: "1px solid var(--bd)", display: "flex", flexDirection: "column", minHeight: 0 }}>
      {/* wordmark */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px", padding: "16px 16px 14px", borderBottom: "1px solid var(--sep)" }}>
        <div style={{ color: "var(--tx)", display: "flex" }}>
          <svg width="26" height="26" viewBox="0 0 32 32" fill="none" aria-hidden="true">
            <rect x="6" y="5.4" width="6" height="9" rx="2.6" fill="currentColor" />
            <rect x="6" y="17.6" width="6" height="9" rx="2.6" fill="currentColor" />
            <rect x="20" y="5.4" width="6" height="9" rx="2.6" fill="currentColor" />
            <rect x="20" y="17.6" width="6" height="9" rx="2.6" fill="currentColor" />
            <rect x="11" y="14.6" width="10" height="2.8" rx="1.4" fill="currentColor" opacity=".5" />
            <circle cx="16" cy="16" r="2.5" fill="var(--phos)" />
            <path d="M3 8.5V4.8A1.8 1.8 0 0 1 4.8 3H8.5" stroke="currentColor" strokeWidth="1.3" opacity=".34" strokeLinecap="round" />
            <path d="M23.5 3h3.7A1.8 1.8 0 0 1 29 4.8V8.5" stroke="currentColor" strokeWidth="1.3" opacity=".34" strokeLinecap="round" />
            <path d="M29 23.5v3.7a1.8 1.8 0 0 1-1.8 1.8H23.5" stroke="currentColor" strokeWidth="1.3" opacity=".34" strokeLinecap="round" />
            <path d="M8.5 29H4.8A1.8 1.8 0 0 1 3 27.2V23.5" stroke="currentColor" strokeWidth="1.3" opacity=".34" strokeLinecap="round" />
          </svg>
        </div>
        {navExpanded && (
          <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.05 }}>
            <span style={{ fontSize: "var(--fs-lg)", fontWeight: 600, letterSpacing: "-.01em" }}>Headshot</span>
            <span className="lab" style={{ fontSize: "var(--fs-2xs)", color: "var(--tx3)" }}>Adversarial eval</span>
          </div>
        )}
      </div>

      {/* nav */}
      <nav style={{ padding: "10px 8px", display: "flex", flexDirection: "column", gap: "2px", flex: 1, minHeight: 0, overflow: "auto" }}>
        {nav.map((item) => (
          <button
            key={item.id}
            onClick={item.go}
            aria-current={item.aria}
            aria-label={item.hasBadge ? item.label + ", " + item.badge + " pending" : item.label}
            title={item.label}
            style={{ display: "flex", alignItems: "center", gap: "11px", padding: "0 10px", height: "36px", borderRadius: "var(--r-sm)", position: "relative", color: item.fg, background: item.bg, fontSize: "var(--fs-base)", fontWeight: 500, textAlign: "left", justifyContent: navJustify }}
          >
            <span style={{ position: "absolute", left: "-8px", top: "8px", bottom: "8px", width: "2.5px", borderRadius: "2px", background: item.rail }} />
            <span style={{ flex: "0 0 auto", display: "flex" }}>
              <Icon path={item.icon} size={17} stroke={1.7} />
            </span>
            {navExpanded && <span style={{ flex: 1 }}>{item.label}</span>}
            {item.hasBadge && (
              <span aria-hidden="true" className="mono" style={{ minWidth: "18px", height: "18px", padding: "0 5px", borderRadius: "var(--r-lg)", background: "var(--warn-t)", color: "var(--warn)", fontSize: "var(--fs-xs)", fontWeight: 600, display: "flex", alignItems: "center", justifyContent: "center", position: "absolute", right: "6px", top: "4px" }}>{item.badge}</span>
            )}
          </button>
        ))}
      </nav>

      {/* principal switcher */}
      <div style={{ padding: "10px", borderTop: "1px solid var(--sep)" }}>
        <button
          onClick={vm.openRole as () => void}
          aria-label="Switch principal (prototype)"
          title={"Signed in as " + operator.name}
          style={{ width: "100%", display: "flex", alignItems: "center", gap: "10px", padding: "8px", borderRadius: "var(--r-sm)", justifyContent: navJustify }}
        >
          <span style={{ width: "28px", height: "28px", borderRadius: "var(--r-md)", background: "var(--brand-tint)", color: "var(--brand)", fontSize: "var(--fs-xs)", fontWeight: 600, display: "flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto" }}>{operator.initials}</span>
          {navExpanded && (
            <>
              <span style={{ display: "flex", flexDirection: "column", lineHeight: 1.15, flex: 1, minWidth: 0, textAlign: "left" }}>
                <span style={{ fontSize: "var(--fs-base)", fontWeight: 500, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{operator.name}</span>
                <span className="lab" style={{ fontSize: "var(--fs-2xs)" }}>{operator.role}</span>
              </span>
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--tx3)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M8 9l4-4 4 4 M8 15l4 4 4-4" /></svg>
            </>
          )}
        </button>
      </div>
    </aside>
  );
}
