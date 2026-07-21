/*
 * Icon — faithful React equivalent of the prototype's `svgEl(d, w, sw)` helper
 * (Headshot Console.dc.html line 3264 / App.tsx `svgEl`).
 *
 * The prototype stores every icon as an SVG path `d` string (space-or-M-delimited) in
 * `app.ic` and `VMETA[x].icon`, then renders it as a stroke-based line icon:
 *   <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width={sw}
 *        stroke-linecap="round" stroke-linejoin="round" aria-hidden><path d={d}/></svg>
 *
 * Defaults mirror svgEl(): size 16, strokeWidth 1.8, fill "none", currentColor stroke,
 * round caps/joins, aria-hidden. Extra props (className, style, aria-*) pass through.
 */
import type { CSSProperties } from "react";

export interface IconProps {
  /** SVG path 'd' (from app.ic[x] or VMETA[x].icon). */
  path: string;
  /** Square edge in px — maps to both width & height (svgEl's `w`). Default 16. */
  size?: number | string;
  /** Stroke width (svgEl's `sw`). Default 1.8. */
  stroke?: number | string;
  /** Stroke color. Default "currentColor" — the parent's color cascades in. */
  strokeColor?: string;
  /** Fill. Default "none" (line icons). */
  fill?: string;
  className?: string;
  style?: CSSProperties;
  [k: string]: unknown;
}

export function Icon({
  path,
  size = 16,
  stroke = 1.8,
  strokeColor = "currentColor",
  fill = "none",
  ...rest
}: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill={fill}
      stroke={strokeColor}
      strokeWidth={stroke}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...rest}
    >
      <path d={path} />
    </svg>
  );
}
