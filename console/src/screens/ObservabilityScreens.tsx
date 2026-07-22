import { useState } from "react";

import type { ApiClient } from "../api/client";
import type { ResourceResult } from "../api/contracts";
import { RESOURCE_PATHS } from "../api/paths";
import { decodeCosts, decodeTraces } from "../api/read-models";
import {
  count,
  DistributionBars,
  MetricStrip,
  money,
  Panel,
  percent,
  ScreenHeading,
  shortId,
  time,
} from "../components/Analytics";
import { ResourceView, StateNotice } from "../components/ResourceView";
import { useResource } from "../hooks/useResource";
import type { CostReadModel, TraceReadModel } from "../types";

const sum = (values: number[]) => values.reduce((total, value) => total + value, 0);

export const percentile = (values: number[], quantile: number): number => {
  if (values.length === 0) return 0;
  const ordered = [...values].sort((left, right) => left - right);
  const index = Math.min(ordered.length - 1, Math.max(0, Math.ceil(quantile * ordered.length) - 1));
  return ordered[index];
};

const compactMoney = (value: number) => `${value < 0 ? "−" : ""}$${Math.abs(value).toFixed(Math.abs(value) >= 0.1 ? 2 : 3)}`;

export const duration = (milliseconds: number) => {
  if (milliseconds < 1_000) return `${Math.round(milliseconds)} ms`;
  if (milliseconds < 60_000) return `${(milliseconds / 1_000).toFixed(2)} s`;
  return `${(milliseconds / 60_000).toFixed(1)} min`;
};

const bytes = (value: number) => {
  if (value < 1_024) return `${count(value)} B`;
  if (value < 1_048_576) return `${(value / 1_024).toFixed(1)} KB`;
  return `${(value / 1_048_576).toFixed(1)} MB`;
};

const physicalRequests = (traces: TraceReadModel[]) => {
  const durable = traces.filter((trace) => trace.request_id !== null);
  if (durable.length > 0) return durable;
  return traces.filter((trace) => trace.operation !== "campaign.run");
};

export interface TraceSummary {
  requestCount: number;
  averageLatencyMs: number;
  p95LatencyMs: number;
  totalCost: number;
  totalBytes: number;
  successRate: number;
  langfuseCoverage: number;
}

export const summarizeTraces = (traces: TraceReadModel[]): TraceSummary => {
  const requests = physicalRequests(traces);
  const latencies = requests.map((trace) => trace.duration_ms);
  const succeeded = requests.filter((trace) => trace.status === "succeeded").length;
  const exported = requests.filter((trace) => trace.langfuse_status === "exported").length;
  return {
    requestCount: requests.length,
    averageLatencyMs: requests.length ? sum(latencies) / requests.length : 0,
    p95LatencyMs: percentile(latencies, 0.95),
    totalCost: sum(requests.map((trace) => trace.measured_cost)),
    totalBytes: sum(requests.map((trace) => trace.request_bytes + (trace.response_bytes ?? 0))),
    successRate: requests.length ? succeeded / requests.length : 0,
    langfuseCoverage: requests.length ? exported / requests.length : 0,
  };
};

function LatencyChart({ traces }: { traces: TraceReadModel[] }) {
  const points = physicalRequests(traces).slice(0, 40).reverse();
  const maximum = Math.max(...points.map((trace) => trace.duration_ms), 1);
  const width = 760;
  const height = 190;
  const inset = 18;
  const usableWidth = width - inset * 2;
  const usableHeight = height - 38;
  const x = (index: number) => inset + (points.length <= 1 ? usableWidth / 2 : (index / (points.length - 1)) * usableWidth);
  const y = (value: number) => 10 + usableHeight - (value / maximum) * usableHeight;
  const line = points.map((trace, index) => `${x(index)},${y(trace.duration_ms)}`).join(" ");

  return (
    <div className="chart-wrap">
      <svg className="telemetry-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Target request latency over time">
        <title>Target request latency over time</title>
        {[0.25, 0.5, 0.75, 1].map((tick) => (
          <g key={tick}>
            <line x1={inset} x2={width - inset} y1={y(maximum * tick)} y2={y(maximum * tick)} className="chart-grid" />
            <text x={inset} y={y(maximum * tick) - 5} className="chart-label">{duration(maximum * tick)}</text>
          </g>
        ))}
        {points.length > 1 && <polyline points={line} className="chart-line" />}
        {points.map((trace, index) => (
          <circle
            key={trace.trace_id}
            cx={x(index)}
            cy={y(trace.duration_ms)}
            r="4"
            className={trace.status === "succeeded" ? "chart-point success" : "chart-point failure"}
          >
            <title>{`${trace.trace_id}: ${duration(trace.duration_ms)}`}</title>
          </circle>
        ))}
      </svg>
      <div className="chart-axis"><span>Older</span><span>Latest</span></div>
    </div>
  );
}

function TraceDetails({ trace }: { trace: TraceReadModel }) {
  const endpoint = trace.destination_host
    ? `${trace.method ?? "HTTP"} ${trace.destination_host}/${trace.relative_path ?? ""}`
    : "Historical trace — transport metadata was not recorded";
  return (
    <div className="trace-detail-stack">
      <div className="trace-detail-hero">
        <div>
          <span className="eyebrow">CORRELATED REQUEST</span>
          <strong className="mono">{trace.trace_id}</strong>
          <small>{endpoint}</small>
        </div>
        <span className={`telemetry-status ${trace.status === "succeeded" ? "success" : "failure"}`}>{trace.status}</span>
      </div>
      <dl className="detail-grid trace-detail-grid">
        <div><dt>Latency</dt><dd className="mono">{duration(trace.duration_ms)}</dd></div>
        <div><dt>HTTP status</dt><dd className="mono">{trace.status_code ?? "—"}</dd></div>
        <div><dt>Measured cost</dt><dd className="mono">{money(trace.measured_cost)}</dd></div>
        <div><dt>Request bytes</dt><dd className="mono">{bytes(trace.request_bytes)}</dd></div>
        <div><dt>Response bytes</dt><dd className="mono">{trace.response_bytes === null ? "—" : bytes(trace.response_bytes)}</dd></div>
        <div><dt>Langfuse</dt><dd className="mono">{trace.langfuse_status}</dd></div>
        <div><dt>Campaign</dt><dd className="mono" title={trace.campaign_id}>{shortId(trace.campaign_id)}</dd></div>
        <div><dt>Attempt</dt><dd className="mono" title={trace.attempt_id ?? undefined}>{shortId(trace.attempt_id)}</dd></div>
        <div><dt>Request</dt><dd className="mono" title={trace.request_id ?? undefined}>{shortId(trace.request_id)}</dd></div>
      </dl>
      <div className="correlation-chain" aria-label="Request correlation chain">
        <span>Campaign</span><i>→</i><span>Attempt</span><i>→</i><span>Request</span><i>→</i><span>Langfuse trace</span>
      </div>
      {trace.error_code && <StateNotice state="error" detail={`Transport error: ${trace.error_code}`} />}
    </div>
  );
}

function TraceDashboard({ traces }: { traces: TraceReadModel[] }) {
  const requests = physicalRequests(traces);
  const summary = summarizeTraces(traces);
  const [selectedId, setSelectedId] = useState<string | null>(requests[0]?.trace_id ?? null);
  const selected = requests.find((trace) => trace.trace_id === selectedId) ?? requests[0];
  const exported = requests.filter((trace) => trace.langfuse_status === "exported").length;
  const queued = requests.filter((trace) => trace.langfuse_status === "queued").length;
  const failed = requests.filter((trace) => trace.langfuse_status === "error").length;
  const disabled = requests.filter((trace) => trace.langfuse_status === "disabled").length;

  return (
    <>
      <MetricStrip label="Observability summary" values={[
        { label: "Physical requests", value: count(summary.requestCount), note: `${percent(summary.successRate)} transport success` },
        { label: "Average latency", value: duration(summary.averageLatencyMs), note: `p95 ${duration(summary.p95LatencyMs)}` },
        { label: "Measured request cost", value: money(summary.totalCost), note: `${bytes(summary.totalBytes)} transferred` },
        { label: "Langfuse export", value: percent(summary.langfuseCoverage), note: `${count(exported)} observations exported` },
      ]} />
      <div className="panel-grid observability-grid">
        <Panel title="Latency timeline" meta={`${count(requests.length)} target requests`} eyebrow="MEASURED TELEMETRY">
          <LatencyChart traces={requests} />
        </Panel>
        <Panel title="Langfuse delivery" meta="durable ledger reconciliation" eyebrow="MEASURED TELEMETRY">
          <DistributionBars rows={[
            { label: "Exported", value: exported, display: count(exported), tone: "success" },
            { label: "Queued", value: queued, display: count(queued), tone: "queued" },
            { label: "Export error", value: failed, display: count(failed), tone: "failure" },
            { label: "Not configured", value: disabled, display: count(disabled) },
          ]} />
          <p className="data-note">PostgreSQL remains authoritative; export status records whether the same sanitized observation reached Langfuse.</p>
        </Panel>
      </div>
      <div className="panel-grid trace-explorer-grid">
        <Panel title="Request ledger" meta="newest first" eyebrow="MEASURED TELEMETRY">
          <div className="trace-list" role="list" aria-label="Correlated target requests">
            {requests.map((trace) => (
              <button
                type="button"
                role="listitem"
                className={`trace-list-row ${selected?.trace_id === trace.trace_id ? "active" : ""}`}
                key={trace.trace_id}
                onClick={() => setSelectedId(trace.trace_id)}
              >
                <span className={`status-dot ${trace.status === "succeeded" ? "live" : "idle"}`} />
                <span><strong className="mono">{shortId(trace.trace_id)}</strong><small>{trace.operation} · {time(trace.started_at)}</small></span>
                <span className="mono">{duration(trace.duration_ms)}</span>
                <span className="mono">{compactMoney(trace.measured_cost)}</span>
              </button>
            ))}
          </div>
        </Panel>
        <Panel title="Request detail" meta={selected ? time(selected.started_at) : undefined} eyebrow="MEASURED TELEMETRY">
          {selected ? <TraceDetails trace={selected} /> : <StateNotice state="empty" detail="No physical request trace is available." />}
        </Panel>
      </div>
      <StateNotice
        state="empty"
        detail="Token usage is unavailable because the evaluated target is a black-box HTTP system and does not return provider usage counters. No token estimate is synthesized."
      />
    </>
  );
}

function CostBars({ costs }: { costs: CostReadModel[] }) {
  const maximum = Math.max(...costs.map((record) => record.budget_usd ?? record.measured_cost), 1);
  return (
    <div className="cost-bars">
      {costs.map((record) => (
        <div className="cost-bar-row" key={record.accounting_id}>
          <div className="cost-bar-label">
            <span className="mono" title={record.campaign_id}>{shortId(record.campaign_id)}</span>
            <strong className="mono">{money(record.measured_cost)}</strong>
          </div>
          <div className="cost-bar-track">
            <span className="cost-budget" style={{ width: `${((record.budget_usd ?? record.measured_cost) / maximum) * 100}%` }} />
            <span className="cost-spend" style={{ width: `${(record.measured_cost / maximum) * 100}%` }} />
          </div>
          <small>{record.budget_usd === null ? "No approved budget projection" : `${percent(record.budget_utilization ?? 0)} of ${money(record.budget_usd)} cap`}</small>
        </div>
      ))}
    </div>
  );
}

function CostTable({ costs }: { costs: CostReadModel[] }) {
  return (
    <div className="table-scroll" tabIndex={0}>
      <table className="record-table cost-table" aria-label="Campaign accounting records">
        <thead><tr><th>Campaign</th><th>Profile</th><th>Requests</th><th>Attempts</th><th>Cost / request</th><th>Total</th><th>Run time</th></tr></thead>
        <tbody>
          {costs.map((record) => (
            <tr key={record.accounting_id}>
              <td className="mono" title={record.campaign_id}>{shortId(record.campaign_id)}</td>
              <td>{record.execution_profile}</td>
              <td className="mono">{count(record.request_count)}</td>
              <td className="mono">{count(record.attempt_count)}</td>
              <td className="mono">{money(record.average_cost_per_request)}</td>
              <td className="mono">{money(record.measured_cost)}</td>
              <td className="mono">{duration(record.duration_ms)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function traceData(result: ResourceResult<TraceReadModel[]>) {
  return (result.state === "ready" || result.state === "stale" || result.state === "degraded") && result.data
    ? result.data
    : [];
}

function CostDashboard({ costs, traces, traceState }: { costs: CostReadModel[]; traces: TraceReadModel[]; traceState: string }) {
  const totalCost = sum(costs.map((record) => record.measured_cost));
  const totalRequests = sum(costs.map((record) => record.request_count));
  const totalBudget = sum(costs.flatMap((record) => record.budget_usd === null ? [] : [record.budget_usd]));
  const budgetedSpend = sum(costs.filter((record) => record.budget_usd !== null).map((record) => record.measured_cost));
  const requestLedger = physicalRequests(traces);
  const requestCost = sum(requestLedger.map((trace) => trace.measured_cost));
  const reconciliationDelta = totalCost - requestCost;

  return (
    <>
      <MetricStrip label="Cost summary" values={[
        { label: "Campaign spend", value: money(totalCost), note: `${count(costs.length)} recorded runs` },
        { label: "Requests accounted", value: count(totalRequests), note: `${money(totalRequests ? totalCost / totalRequests : 0)} average` },
        { label: "Approved budget used", value: totalBudget ? percent(budgetedSpend / totalBudget) : "—", note: totalBudget ? `${money(budgetedSpend)} of ${money(totalBudget)}` : "No budget projection available" },
        { label: "Request ledger cost", value: money(requestCost), note: `${count(requestLedger.length)} physical requests` },
      ]} />
      <div className="panel-grid observability-grid">
        <Panel title="Spend by campaign" meta="measured vs approved cap" eyebrow="MEASURED TELEMETRY">
          <CostBars costs={costs} />
          <div className="chart-legend"><span><i className="budget" />Approved cap</span><span><i className="spend" />Measured spend</span></div>
        </Panel>
        <Panel title="Ledger reconciliation" meta="campaign summary ↔ request ledger" eyebrow="MEASURED TELEMETRY">
          <div className="reconciliation-grid">
            <div><span>Campaign summaries</span><strong className="mono">{money(totalCost)}</strong></div>
            <div><span>Physical request ledger</span><strong className="mono">{money(requestCost)}</strong></div>
            <div><span>Non-request / historical variance</span><strong className="mono">{money(reconciliationDelta)}</strong></div>
            <div><span>Trace projection</span><strong className="mono">{traceState}</strong></div>
          </div>
          <p className="data-note">A variance is expected when campaign accounting includes historical or non-HTTP work. Values are reconciled, never force-balanced.</p>
        </Panel>
      </div>
      <Panel title="Campaign accounting" meta="authoritative PostgreSQL summaries" eyebrow="MEASURED TELEMETRY">
        <CostTable costs={costs} />
      </Panel>
      <StateNotice
        state="empty"
        detail="Langfuse reports explicit cost details for exported observations. Token counts remain unavailable from this black-box target, so Headshot displays measured monetary cost without a synthetic tokens × rate estimate."
      />
    </>
  );
}

export function TracesScreen({ client }: { client: ApiClient }) {
  const traces = useResource<TraceReadModel[]>(client, RESOURCE_PATHS.traces, decodeTraces);
  return (
    <div className="screen-stack">
      <ScreenHeading title="Traces" detail="Every physical target request is correlated across campaign, attempt, durable request ledger and Langfuse export." eyebrow="HEADSHOT OBSERVABILITY" />
      <ResourceView result={traces.result} emptyLabel="No physical request telemetry has been recorded yet.">
        {(data) => <TraceDashboard traces={data} />}
      </ResourceView>
    </div>
  );
}

export function CostsScreen({ client }: { client: ApiClient }) {
  const costs = useResource<CostReadModel[]>(client, RESOURCE_PATHS.costs, decodeCosts);
  const traces = useResource<TraceReadModel[]>(client, RESOURCE_PATHS.traces, decodeTraces);
  return (
    <div className="screen-stack">
      <ScreenHeading title="Costs" detail="Measured campaign spend, approved budget utilization, request economics and ledger reconciliation—without token-cost estimates." eyebrow="HEADSHOT OBSERVABILITY" />
      <ResourceView result={costs.result} emptyLabel="No measured campaign accounting records are available.">
        {(data) => <CostDashboard costs={data} traces={traceData(traces.result)} traceState={traces.result.state} />}
      </ResourceView>
    </div>
  );
}
