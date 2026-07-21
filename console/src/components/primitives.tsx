/*
 * primitives.tsx — recurring UI atoms, each a faithful 1:1 extraction of a repeated
 * inline-styled pattern in the prototype (Headshot Console.dc.html). Colors are ALWAYS
 * CSS variables — never literals — and every semantic channel is icon + shape + label,
 * never color alone (DESIGN_SYSTEM.md §5).
 *
 * These mirror the prototype's VMETA / SEVMETA / --tz-* metadata. Most atoms take plain
 * values (they are pure); none needs `app`. VMETA/SEVMETA are duplicated here as small
 * frozen tables so screens can render a chip from a Verdict/Severity key without threading
 * `app` through — matching the prototype tables at lines 2421 & 2505.
 */
import type { CSSProperties, ReactNode } from "react";
import type { Verdict, Severity, TrustZone, Provenance } from "../types";
import { Icon } from "./Icon";

/* ---- VMETA (Headshot Console.dc.html line 2421) — verdict channel ---- */
interface VMetaEntry { short: string; label: string; color: string; tint: string; border: string; icon: string; dotR: string; }
export const VMETA: Record<Verdict, VMetaEntry> = {
  EXPLOIT_CONFIRMED: { short: "Confirmed", label: "Exploit confirmed", color: "var(--v-conf)", tint: "var(--v-conf-t)", border: "var(--v-conf)", icon: "M12 3l7 2.5v5.5c0 4.3-3 7.4-7 8.5-4-1.1-7-4.2-7-8.5V5.5L12 3z M9 12l2 2 4-4", dotR: "2px" },
  EXPLOIT_LIKELY: { short: "Likely", label: "Exploit likely", color: "var(--v-likely)", tint: "var(--v-likely-t)", border: "var(--v-likely)", icon: "M12 3l9.5 17H2.5z M12 9.5v5 M12 17.5h.01", dotR: "2px" },
  NO_EXPLOIT_OBSERVED: { short: "No exploit observed", label: "No exploit observed", color: "var(--v-clear)", tint: "var(--v-clear-t)", border: "var(--bd)", icon: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M8.5 12.5l2.5 2.5 4.5-4.5", dotR: "50%" },
  INDETERMINATE: { short: "Needs review", label: "Needs review", color: "var(--v-indet)", tint: "var(--v-indet-t)", border: "var(--v-indet)", icon: "M12 3l9 9-9 9-9-9z M12 8v5 M12 16h.01", dotR: "1px" },
  ERROR: { short: "Error", label: "Evaluation error", color: "var(--v-err)", tint: "var(--v-err-t)", border: "var(--v-err)", icon: "M8.5 3h7l5 5v7l-5 5h-7l-5-5V8z M12 8v5 M12 16.5h.01", dotR: "2px" },
};

/* ---- SEVMETA (Headshot Console.dc.html line 2505) — severity channel ---- */
interface SevMetaEntry { label: string; color: string; n: number; }
export const SEVMETA: Record<Severity, SevMetaEntry> = {
  critical: { label: "Critical", color: "var(--sv-crit)", n: 3 },
  high: { label: "High", color: "var(--sv-high)", n: 3 },
  medium: { label: "Medium", color: "var(--sv-med)", n: 2 },
  low: { label: "Low", color: "var(--sv-low)", n: 1 },
};

/* ---- trust-zone channel — maps a zone to its --tz-* token + label ---- */
const TZ: Record<TrustZone, { color: string; label: string }> = {
  trust: { color: "var(--tz-trust)", label: "Trusted control" },
  gov: { color: "var(--tz-gov)", label: "Governed" },
  quar: { color: "var(--tz-quar)", label: "Quarantined" },
  ext: { color: "var(--tz-ext)", label: "External" },
  data: { color: "var(--tz-data)", label: "Data" },
  human: { color: "var(--tz-human)", label: "Human" },
};

/* ================================================================= *
 *  VerdictChip — tint + icon + label + provenance                    *
 *  (findings row line 792 · finding detail 818 · approval 984)       *
 *  Confirmed vs Likely never render identically — distinct icon,     *
 *  color, tint AND label per VMETA.                                  *
 * ================================================================= */
export function VerdictChip({ v, size = "sm", provenance }: { v: Verdict; size?: "xs" | "sm" | "md"; provenance?: Provenance }) {
  const m = VMETA[v] || VMETA.ERROR;
  const dims: Record<string, { pad: string; fs: string; gap: string; icon: number; sw: number; radius: string }> = {
    xs: { pad: "2px 8px", fs: "var(--fs-2xs)", gap: "5px", icon: 11, sw: 2, radius: "var(--r-xs)" },
    sm: { pad: "2px 8px", fs: "var(--fs-xs)", gap: "5px", icon: 12, sw: 1.9, radius: "var(--r-xs)" },
    md: { pad: "4px 11px", fs: "var(--fs-sm)", gap: "6px", icon: 13, sw: 1.9, radius: "var(--r-sm)" },
  };
  const d = dims[size];
  const provLabel = provenance === "oracle" ? "Oracle" : provenance === "human" ? "Human" : null;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: d.gap }}>
      <span style={{ display: "inline-flex", alignItems: "center", gap: d.gap, padding: d.pad, borderRadius: d.radius, fontSize: d.fs, fontWeight: 600, color: m.color, background: m.tint, border: "1px solid " + m.border }}>
        <Icon path={m.icon} size={d.icon} stroke={d.sw} />
        {m.label}
      </span>
      {provLabel && (
        <span className="lab" style={{ fontSize: "var(--fs-2xs)", color: provenance === "oracle" ? "var(--phos)" : "var(--tz-human)" }}>{provLabel}</span>
      )}
    </span>
  );
}

/* ================================================================= *
 *  SeverityMarker — square marker + label (findings 788 · 815)       *
 * ================================================================= */
export function SeverityMarker({ sev, size = "sm" }: { sev: Severity; size?: "sm" | "md" }) {
  const m = SEVMETA[sev];
  const marker = size === "md" ? "9px" : "9px";
  const fs = size === "md" ? "var(--fs-sm)" : "var(--fs-xs)";
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: "8px" }}>
      <span style={{ width: marker, height: marker, borderRadius: "2px", background: m.color, flex: "0 0 auto" }} />
      <span style={{ fontSize: fs, color: m.color, fontWeight: 600 }}>{m.label}</span>
    </span>
  );
}

/* ================================================================= *
 *  TrustRail — thin vertical rail per --tz-* (birdseye band edge)    *
 * ================================================================= */
export function TrustRail({ zone, height = "100%" }: { zone: TrustZone; height?: string }) {
  const tz = TZ[zone];
  return <span aria-hidden="true" style={{ width: "2.5px", borderRadius: "2px", background: tz.color, height, flex: "0 0 auto" }} />;
}

/* ================================================================= *
 *  TrustBadge — outlined source badge per --tz-* (icon+shape+label)  *
 * ================================================================= */
export function TrustBadge({ zone, label }: { zone: TrustZone; label?: string }) {
  const tz = TZ[zone];
  return (
    <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "2px 8px", border: "1px solid " + tz.color, borderRadius: "var(--r-xs)", color: tz.color, fontSize: "var(--fs-2xs)" }}>
      <span style={{ width: "9px", height: "9px", borderRadius: "2px", background: tz.color, flex: "0 0 auto" }} />
      {label ?? tz.label}
    </span>
  );
}

/* ================================================================= *
 *  IntegrityChip — evidence hash / integrity state (evidence 652)    *
 * ================================================================= */
export function IntegrityChip({ label, color, tint, border }: { label: string; color: string; tint: string; border: string }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", padding: "2px 8px", borderRadius: "var(--r-xs)", fontSize: "var(--fs-xs)", fontWeight: 600, color, background: tint, border: "1px solid " + border }}>{label}</span>
  );
}

/* ================================================================= *
 *  AttentionDot — attention channel marker (queue state / SLA)       *
 *  distinct from verdict & severity; icon+shape carried by `kind`.   *
 * ================================================================= */
export function AttentionDot({ kind }: { kind: "human" | "review" | "none" | string }) {
  if (kind === "none" || !kind) return null;
  const isHuman = kind === "human";
  const color = isHuman ? "var(--v-conf)" : "var(--v-indet)";
  const radius = isHuman ? "2px" : "1px";
  return <span aria-label={isHuman ? "Human review required" : "Needs review"} title={isHuman ? "Human review required" : "Needs review"} style={{ width: "8px", height: "8px", borderRadius: radius, background: color, flex: "0 0 auto" }} />;
}

/* ================================================================= *
 *  Lab — the .lab micro-label used everywhere (utility class)        *
 * ================================================================= */
export function Lab({ children, style }: { children: ReactNode; style?: CSSProperties }) {
  return <span className="lab" style={style}>{children}</span>;
}

/* ================================================================= *
 *  Seg — segmented control (tab-style, one bordered group)          *
 *  mirrors the inspector tab row (line 429) & filter pills.         *
 * ================================================================= */
export interface SegOption { id: string; label: string; }
export function Seg({ options, value, onChange, ariaLabel }: { options: SegOption[]; value: string; onChange: (id: string) => void; ariaLabel?: string }) {
  return (
    <div role="tablist" aria-label={ariaLabel} style={{ display: "flex", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", overflow: "hidden" }}>
      {options.map((o, i) => {
        const active = o.id === value;
        return (
          <button
            key={o.id}
            role="tab"
            aria-selected={active}
            onClick={() => onChange(o.id)}
            style={{ padding: "5px 12px", fontSize: "var(--fs-sm)", fontWeight: 500, borderLeft: i === 0 ? undefined : "1px solid var(--bd)", background: active ? "var(--sel)" : "transparent", color: active ? "var(--brand)" : "var(--tx2)" }}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

/* ================================================================= *
 *  Toggle — role="switch" with a dot + label (attack-surface 1796)  *
 * ================================================================= */
export function Toggle({ on, onToggle, onLabel = "On", offLabel = "Off", ariaLabel }: { on: boolean; onToggle: () => void; onLabel?: string; offLabel?: string; ariaLabel?: string }) {
  const color = on ? "var(--phos)" : "var(--tx3)";
  return (
    <button
      onClick={onToggle}
      role="switch"
      aria-checked={on}
      aria-label={ariaLabel}
      style={{ display: "inline-flex", alignItems: "center", gap: "5px", minHeight: "34px", padding: "0 11px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", fontSize: "var(--fs-2xs)", fontWeight: 600, color, background: "transparent", flex: "0 0 auto" }}
    >
      <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: color }} />
      {on ? onLabel : offLabel}
    </button>
  );
}
