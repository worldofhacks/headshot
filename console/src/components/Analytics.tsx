import type { ReactNode } from "react";

export interface MetricValue {
  label: string;
  value: string;
  note: string;
}

export interface DistributionRow {
  label: string;
  value: number;
  display?: string;
  tone?: "success" | "queued" | "failure" | "brand";
}

export const count = (value: number) => new Intl.NumberFormat("en-US").format(value);

export const percent = (value: number) => `${Math.round(value * 100)}%`;

export const money = (value: number) =>
  `${value < 0 ? "−" : ""}$${Math.abs(value).toFixed(Math.abs(value) >= 1 ? 2 : 4)}`;

export const shortId = (value: string | null | undefined) =>
  value ? `${value.slice(0, 8)}…${value.slice(-4)}` : "—";

export const time = (value: string) => new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "numeric",
  hour: "numeric",
  minute: "2-digit",
  second: "2-digit",
}).format(new Date(value));

export function ScreenHeading({
  title,
  detail,
  eyebrow = "HEADSHOT CONTROL PLANE",
}: {
  title: string;
  detail: string;
  eyebrow?: string;
}) {
  return (
    <header className="screen-heading">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
      </div>
      <p>{detail}</p>
    </header>
  );
}

export function Panel({
  title,
  meta,
  children,
  eyebrow = "AUTHORITATIVE VIEW",
}: {
  title: string;
  meta?: string;
  children: ReactNode;
  eyebrow?: string;
}) {
  return (
    <section className="panel">
      <header className="panel-header">
        <div>
          <p className="eyebrow">{eyebrow}</p>
          <h2>{title}</h2>
        </div>
        {meta && <span className="panel-meta mono">{meta}</span>}
      </header>
      <div className="panel-body">{children}</div>
    </section>
  );
}

export function MetricStrip({
  values,
  label = "Platform summary",
}: {
  values: MetricValue[];
  label?: string;
}) {
  return (
    <section className="metric-strip observability-metrics analytical-metrics" aria-label={label}>
      {values.map((metric) => (
        <div key={metric.label}>
          <span>{metric.label}</span>
          <strong className="mono">{metric.value}</strong>
          <small>{metric.note}</small>
        </div>
      ))}
    </section>
  );
}

export function DistributionBars({ rows }: { rows: DistributionRow[] }) {
  const maximum = Math.max(...rows.map((row) => row.value), 1);
  return (
    <div className="distribution-list">
      {rows.map((row) => (
        <div className="distribution-row" key={row.label}>
          <div>
            <span>{row.label}</span>
            <strong className="mono">{row.display ?? count(row.value)}</strong>
          </div>
          <div className="distribution-track" aria-hidden="true">
            <span
              className={row.tone ?? ""}
              style={{ width: row.value === 0 ? "0" : `${Math.max(2, (row.value / maximum) * 100)}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

export function TagMatrix({
  groups,
  empty = "No mapped values are recorded.",
}: {
  groups: Array<{ label: string; values: string[] }>;
  empty?: string;
}) {
  return (
    <div className="tag-matrix">
      {groups.map((group) => (
        <div className="tag-group" key={group.label}>
          <span>{group.label}</span>
          <div>
            {group.values.length > 0
              ? group.values.map((value) => <strong className="mono" key={value}>{value}</strong>)
              : <small>{empty}</small>}
          </div>
        </div>
      ))}
    </div>
  );
}

export function EvidenceGrid({
  values,
}: {
  values: Array<{ label: string; value: string; tone?: "success" | "failure" | "queued" }>;
}) {
  return (
    <dl className="evidence-grid">
      {values.map((item) => (
        <div key={item.label}>
          <dt>{item.label}</dt>
          <dd className={`mono ${item.tone ?? ""}`}>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Timeline({
  rows,
  empty = "No timeline records are available.",
}: {
  rows: Array<{ id: string; title: string; detail: string; at: string; tone?: "success" | "failure" | "queued" }>;
  empty?: string;
}) {
  if (rows.length === 0) return <p className="data-note">{empty}</p>;
  return (
    <div className="analytical-timeline">
      {rows.map((row) => (
        <article key={row.id}>
          <i className={row.tone ?? ""} />
          <div><strong>{row.title}</strong><span>{row.detail}</span></div>
          <time className="mono" dateTime={row.at}>{time(row.at)}</time>
        </article>
      ))}
    </div>
  );
}
