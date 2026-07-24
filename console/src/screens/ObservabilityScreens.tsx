import { useState } from "react";

import type { ApiClient } from "../api/client";
import type { ResourceResult } from "../api/contracts";
import { RESOURCE_PATHS } from "../api/paths";
import { decodeCosts, decodeTraces } from "../api/read-models";
import { AdversarialText } from "../components/AdversarialText";
import {
  count,
  DistributionBars,
  MetricStrip,
  money,
  Panel,
  percent,
  ScreenHeading,
  shortId,
  TagMatrix,
  time,
} from "../components/Analytics";
import { ResourceView, StateNotice } from "../components/ResourceView";
import {
  LIVE_RESOURCE_POLL_INTERVAL_MS,
  useResource,
} from "../hooks/useResource";
import type {
  AgentBudgetReadModel,
  CostReadModel,
  TraceReadModel,
} from "../types";

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
  return traces.filter((trace) => (
    trace.request_id !== null
    && trace.method !== null
    && trace.destination_host !== null
  ));
};

const agentObservations = (traces: TraceReadModel[]) =>
  traces.filter((trace) => trace.agent_role !== null);

const liveObservations = (traces: TraceReadModel[]) =>
  traces.filter((trace) => (
    trace.agent_role !== null
    || (trace.request_id !== null && trace.method !== null && trace.destination_host !== null)
  ));

const traceIdentity = (trace: TraceReadModel) =>
  trace.request_id ?? trace.execution_id ?? trace.trace_id;

const langfuseDeliveryLabel = (trace: TraceReadModel) => {
  if (trace.langfuse_verified_at !== null) {
    return `observed · ${time(trace.langfuse_verified_at)}`;
  }
  return trace.langfuse_status === "queued"
    ? "awaiting remote verification"
    : trace.langfuse_status.replaceAll("_", " ");
};

const traceCostValue = (trace: TraceReadModel) =>
  trace.accounting_status === "unavailable" ? "Unavailable" : money(trace.measured_cost);

const roleLatencyValue = (
  p50DurationMs: number | null,
  p95DurationMs: number | null,
) => (
  p50DurationMs === null || p95DurationMs === null
    ? "No completed execution yet"
    : `${duration(p50DurationMs)} / ${duration(p95DurationMs)}`
);

const costValue = (record: CostReadModel) => {
  if (record.accounting_status === "unavailable") return "Unavailable";
  if (record.accounting_status === "partial") return `${money(record.measured_cost)} known`;
  return money(record.measured_cost);
};

const budgetStateLabel = (budget: AgentBudgetReadModel) =>
  budget.status === "historical"
    ? "historical · closed"
    : budget.status.replaceAll("_", " ");

const roleBudgetValue = (
  record: CostReadModel,
  field: "role_usd_remaining" | "role_calls_remaining",
) => {
  const budget = record.provider_budget;
  if (budget === null || budget.status === "unavailable") return "Not available";
  const value = budget[field];
  if (value === null) return "Not available";
  const formatted = field === "role_usd_remaining"
    ? money(value)
    : count(value);
  return budget.status === "historical"
    ? `${formatted} unused at close`
    : formatted;
};

const costRoleLatencyValue = (
  record: CostReadModel,
  latency: "p50_duration_ms" | "p95_duration_ms",
) => {
  if (record.agent_role === null) return "Not applicable";
  const value = record[latency];
  return value === null ? "Unavailable" : duration(value);
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
  const latencies = requests.flatMap((trace) => (
    trace.duration_ms === null ? [] : [trace.duration_ms]
  ));
  const succeeded = requests.filter((trace) => trace.status === "succeeded").length;
  const verified = requests.filter((trace) => trace.langfuse_verified_at !== null).length;
  return {
    requestCount: requests.length,
    averageLatencyMs: requests.length ? sum(latencies) / requests.length : 0,
    p95LatencyMs: percentile(latencies, 0.95),
    totalCost: sum(requests.map((trace) => trace.measured_cost)),
    totalBytes: sum(requests.map((trace) => trace.request_bytes + (trace.response_bytes ?? 0))),
    successRate: requests.length ? succeeded / requests.length : 0,
    langfuseCoverage: requests.length ? verified / requests.length : 0,
  };
};

function LatencyChart({ traces }: { traces: TraceReadModel[] }) {
  const points = traces.filter((trace) => trace.duration_ms !== null).slice(0, 40).reverse();
  const maximum = Math.max(...points.map((trace) => trace.duration_ms ?? 0), 1);
  const width = 760;
  const height = 190;
  const inset = 18;
  const usableWidth = width - inset * 2;
  const usableHeight = height - 38;
  const x = (index: number) => inset + (points.length <= 1 ? usableWidth / 2 : (index / (points.length - 1)) * usableWidth);
  const y = (value: number) => 10 + usableHeight - (value / maximum) * usableHeight;
  const line = points.map((trace, index) => `${x(index)},${y(trace.duration_ms ?? 0)}`).join(" ");

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
            key={traceIdentity(trace)}
            cx={x(index)}
            cy={y(trace.duration_ms ?? 0)}
            r="4"
            className={trace.status === "succeeded" ? "chart-point success" : "chart-point failure"}
          >
            <title>{`${trace.trace_id}: ${duration(trace.duration_ms ?? 0)}`}</title>
          </circle>
        ))}
      </svg>
      <div className="chart-axis"><span>Older</span><span>Latest</span></div>
    </div>
  );
}

function TraceDetails({ trace }: { trace: TraceReadModel }) {
  const isAgent = trace.agent_role !== null;
  const endpoint = isAgent
    ? `${trace.agent_role?.replace("_", " ")} · ${trace.provider}`
    : trace.destination_host
      ? `${trace.method ?? "HTTP"} ${trace.destination_host}/${trace.relative_path ?? ""}`
      : "Historical trace — transport metadata was not recorded";
  return (
    <div className="trace-detail-stack">
      <div className="trace-detail-hero">
        <div>
          <span className="eyebrow">CORRELATED OBSERVATION</span>
          <strong className="mono">{trace.trace_id}</strong>
          <small>{endpoint}</small>
        </div>
        <span className={`telemetry-status ${trace.status === "succeeded" ? "success" : "failure"}`}>{trace.status}</span>
      </div>
      <dl className="detail-grid trace-detail-grid">
        <div><dt>Latency</dt><dd className="mono">{trace.duration_ms === null ? "Running" : duration(trace.duration_ms)}</dd></div>
        <div><dt>HTTP status</dt><dd className="mono">{isAgent ? "Not applicable" : trace.status_code ?? "—"}</dd></div>
        <div><dt>Measured cost</dt><dd className="mono">{traceCostValue(trace)}</dd></div>
        {isAgent && <div><dt>Requested model</dt><dd className="mono">{trace.provider}</dd></div>}
        {isAgent && <div><dt>Provider-served model</dt><dd className="mono">{trace.returned_model ?? "unavailable"}</dd></div>}
        {isAgent && <div><dt>Provider-served upstream</dt><dd className="mono">{trace.upstream_provider ?? "unavailable"}</dd></div>}
        {isAgent && <div><dt>Provider request</dt><dd className="mono">{trace.provider_request_id ?? "unavailable"}</dd></div>}
        {isAgent && (
          <div>
            <dt>Campaign role p50 / p95</dt>
            <dd className="mono">
              {roleLatencyValue(trace.p50_duration_ms, trace.p95_duration_ms)}
            </dd>
          </div>
        )}
        <div><dt>Request bytes</dt><dd className="mono">{isAgent ? "Not applicable" : bytes(trace.request_bytes)}</dd></div>
        <div><dt>Response bytes</dt><dd className="mono">{isAgent ? "Not applicable" : trace.response_bytes === null ? "—" : bytes(trace.response_bytes)}</dd></div>
        <div><dt>Langfuse delivery</dt><dd className="mono">{langfuseDeliveryLabel(trace)}</dd></div>
        <div><dt>Campaign</dt><dd className="mono" title={trace.campaign_id}>{shortId(trace.campaign_id)}</dd></div>
        <div><dt>Attempt</dt><dd className="mono" title={trace.attempt_id ?? undefined}>{shortId(trace.attempt_id)}</dd></div>
        <div><dt>Request</dt><dd className="mono" title={trace.request_id ?? undefined}>{shortId(trace.request_id)}</dd></div>
        {isAgent && <div><dt>Agent execution</dt><dd className="mono" title={trace.execution_id ?? undefined}>{shortId(trace.execution_id)}</dd></div>}
        {isAgent && <div><dt>Parent execution</dt><dd className="mono" title={trace.parent_execution_id ?? undefined}>{shortId(trace.parent_execution_id)}</dd></div>}
        {isAgent && <div><dt>Input / output / reasoning tokens</dt><dd className="mono">{trace.input_tokens === null && trace.output_tokens === null && trace.reasoning_tokens === null ? "Not reported by engine" : `${count(trace.input_tokens ?? 0)} / ${count(trace.output_tokens ?? 0)} / ${count(trace.reasoning_tokens ?? 0)}`}</dd></div>}
        {isAgent && <div><dt>Physical provider calls</dt><dd className="mono">{trace.physical_attempts === null ? "Unavailable" : count(trace.physical_attempts)}</dd></div>}
        {trace.agent_role === "judge" && <div><dt>Evaluator calibration</dt><dd className="mono">{trace.judge_calibration_state ?? "unavailable"}</dd></div>}
        {trace.agent_role === "judge" && <div><dt>LLM / oracle agreement</dt><dd className="mono">{trace.oracle_agreement === null ? "unavailable" : trace.oracle_agreement ? "agrees" : "disagrees"}</dd></div>}
        {trace.agent_role === "judge" && <div><dt>Decisive authority</dt><dd className="mono">{trace.decision_authority ?? "unavailable"}</dd></div>}
      </dl>
      <div className="correlation-chain" aria-label="Observation correlation chain">
        <span>Campaign</span><i>→</i><span>Attempt</span><i>→</i><span>{isAgent ? "Agent execution" : "Request"}</span><i>→</i><span>Langfuse delivery</span>
      </div>
      {(trace.inspection_flags.length > 0 || trace.inspection_owasp_mappings.length > 0) && (
        <TagMatrix groups={[
          { label: "Passive signals", values: trace.inspection_flags },
          { label: "Candidate mappings", values: trace.inspection_owasp_mappings },
        ]} />
      )}
      {(trace.request_preview !== null || trace.response_preview !== null) && (
        <div className="traffic-inspector">
          <div>
            <p className="field-label">Sanitized request · {shortId(trace.request_sha256)}</p>
            <AdversarialText>{trace.request_preview ?? "Request body unavailable"}</AdversarialText>
          </div>
          <div>
            <p className="field-label">Sanitized response · {shortId(trace.response_sha256)}</p>
            <AdversarialText>{trace.response_preview ?? "Response body unavailable"}</AdversarialText>
          </div>
          <p className="data-note">Inspector signals are advisory. They cannot create a finding or replace the independent Judge.</p>
        </div>
      )}
      {trace.error_code && <StateNotice state="error" detail={`Transport error: ${trace.error_code}`} />}
    </div>
  );
}

function TraceDashboard({ traces }: { traces: TraceReadModel[] }) {
  const requests = physicalRequests(traces);
  const agents = agentObservations(traces);
  const observations = liveObservations(traces);
  const summary = summarizeTraces(traces);
  const [selectedId, setSelectedId] = useState<string | null>(
    observations[0] ? traceIdentity(observations[0]) : null,
  );
  const selected = observations.find((trace) => traceIdentity(trace) === selectedId) ?? observations[0];
  const verified = observations.filter((trace) => trace.langfuse_verified_at !== null).length;
  const queued = observations.filter((trace) => trace.langfuse_status === "queued").length;
  const failed = observations.filter((trace) => trace.langfuse_status === "error").length;
  const disabled = observations.filter((trace) => trace.langfuse_status === "disabled").length;
  const notAttempted = observations.filter(
    (trace) => trace.langfuse_status === "not_attempted",
  ).length;
  const observationCost = sum(observations.map((trace) => trace.measured_cost));
  const unavailableAccounting = observations.filter(
    (trace) => trace.accounting_status === "unavailable",
  ).length;
  const observationLatencies = observations.flatMap((trace) => (
    trace.duration_ms === null ? [] : [trace.duration_ms]
  ));
  const verifiedCoverage = observations.length ? verified / observations.length : 0;

  return (
    <>
      <MetricStrip label="Observability summary" values={[
        { label: "Durable work", value: count(observations.length), note: `${count(requests.length)} requests · ${count(agents.length)} agent executions` },
        { label: "Execution latency", value: duration(observationLatencies.length ? sum(observationLatencies) / observationLatencies.length : 0), note: `p95 ${duration(percentile(observationLatencies, 0.95))}` },
        {
          label: "Known trace cost",
          value: unavailableAccounting > 0 ? `${money(observationCost)} known` : money(observationCost),
          note: unavailableAccounting > 0
            ? `${unavailableAccounting} observation(s) lack provider accounting`
            : `${bytes(summary.totalBytes)} target traffic`,
        },
        { label: "Langfuse observed", value: percent(verifiedCoverage), note: `${count(verified)} of ${count(observations.length)} query-back verified` },
      ]} />
      <div className="panel-grid observability-grid">
        <Panel title="Latency timeline" meta={`${count(observations.length)} requests + agents`} eyebrow="MEASURED TELEMETRY">
          <LatencyChart traces={observations} />
        </Panel>
        <Panel title="Langfuse delivery" meta="durable ledger reconciliation" eyebrow="MEASURED TELEMETRY">
          <DistributionBars rows={[
            { label: "Observed", value: verified, display: count(verified), tone: "success" },
            { label: "Awaiting remote verification", value: queued, display: count(queued), tone: "queued" },
            { label: "Export error", value: failed, display: count(failed), tone: "failure" },
            { label: "Not configured", value: disabled, display: count(disabled) },
            { label: "Not attempted", value: notAttempted, display: count(notAttempted) },
          ]} />
          <p className="data-note">PostgreSQL remains authoritative. Queued observations await exact remote query-back and do not assert remote acceptance. Observed means the live Langfuse query-back check found the exact remote record and atomically persisted its verified delivery state.</p>
        </Panel>
      </div>
      <div className="panel-grid trace-explorer-grid">
        <Panel title="Trace ledger" meta="newest first" eyebrow="MEASURED TELEMETRY">
          <div className="trace-list" role="list" aria-label="Correlated target requests and agent executions">
            {observations.map((trace) => (
              <button
                type="button"
                role="listitem"
                className={`trace-list-row ${selected && traceIdentity(selected) === traceIdentity(trace) ? "active" : ""}`}
                key={traceIdentity(trace)}
                onClick={() => setSelectedId(traceIdentity(trace))}
              >
                <span className={`status-dot ${trace.status === "succeeded" ? "live" : "idle"}`} />
                <span><strong className="mono">{shortId(trace.trace_id)}</strong><small>{trace.operation} · {time(trace.started_at)}</small></span>
                <span className="mono">{trace.duration_ms === null ? "running" : duration(trace.duration_ms)}</span>
                <span className="mono">{trace.accounting_status === "unavailable" ? "unavailable" : compactMoney(trace.measured_cost)}</span>
              </button>
            ))}
          </div>
        </Panel>
        <Panel title="Observation detail" meta={selected ? time(selected.started_at) : undefined} eyebrow="MEASURED TELEMETRY">
          {selected ? <TraceDetails trace={selected} /> : <StateNotice state="empty" detail="No request or agent observation is available." />}
        </Panel>
      </div>
      <StateNotice
        state="empty"
        detail="Black-box target requests do not synthesize token usage. Hosted agent generations report provider-measured usage and cost; deterministic agents report an observed zero-dollar execution."
      />
    </>
  );
}

function CostBars({ costs }: { costs: CostReadModel[] }) {
  const cap = (record: CostReadModel) => {
    const roleCap = record.provider_budget?.role_usd_cap;
    return roleCap === null || roleCap === undefined
      ? record.budget_usd ?? record.measured_cost
      : roleCap + (record.provider_budget?.role_usd_overrun ?? 0);
  };
  const knownSpend = (record: CostReadModel) =>
    record.provider_budget?.role_usd_spent
    ?? record.measured_cost;
  const unresolvedExposure = (record: CostReadModel) =>
    record.provider_budget?.role_unresolved_usd_exposure
    ?? 0;
  const maximum = Math.max(
    ...costs.map((record) => Math.max(
      cap(record),
      knownSpend(record) + unresolvedExposure(record),
    )),
    1,
  );
  const budgetDetail = (record: CostReadModel) => {
    const budget = record.provider_budget;
    if (budget === null) {
      return record.budget_usd === null
        ? "No approved budget projection"
        : `${percent(record.budget_utilization ?? 0)} of ${money(record.budget_usd)} cap`;
    }
    if (budget.status === "unavailable") return "No authorized hosted subcap";
    const remainingUsd = money(budget.role_usd_remaining ?? 0);
    const remainingCalls = count(budget.role_calls_remaining ?? 0);
    if (budget.status === "historical") {
      return `${remainingUsd} and ${remainingCalls} calls unused at close · historical authorization`;
    }
    if (budget.status === "staged_pending_authorization") {
      return `${remainingUsd} and ${remainingCalls} calls staged · not active`;
    }
    return `${remainingUsd} role budget remaining · ${remainingCalls} calls remaining`;
  };

  return (
    <div className="cost-bars">
      {costs.map((record) => {
        const known = knownSpend(record);
        const unresolved = unresolvedExposure(record);
        return (
          <div className="cost-bar-row" key={record.accounting_id}>
            <div className="cost-bar-label">
              <span className="mono" title={record.campaign_id}>{record.agent_role?.replace("_", " ") ?? shortId(record.campaign_id)}</span>
              <strong className="mono">
                {record.accounting_status === "unavailable"
                  ? "Known spend unavailable"
                  : `${money(known)} known`}
                {unresolved > 0 ? ` · ${money(unresolved)} unresolved` : ""}
              </strong>
            </div>
            <div className="cost-bar-track">
              <span
                className="cost-budget"
                style={{ width: `${(cap(record) / maximum) * 100}%` }}
              />
              <span
                className="cost-spend"
                style={{ width: `${(known / maximum) * 100}%` }}
              />
              {unresolved > 0 && (
                <span
                  className="cost-unresolved"
                  style={{
                    left: `${(known / maximum) * 100}%`,
                    width: `${(unresolved / maximum) * 100}%`,
                  }}
                />
              )}
            </div>
            <small>{budgetDetail(record)}</small>
          </div>
        );
      })}
    </div>
  );
}

function CostTable({ costs }: { costs: CostReadModel[] }) {
  return (
    <div className="table-scroll" tabIndex={0}>
      <table className="record-table cost-table" aria-label="Campaign and agent accounting records">
        <thead>
          <tr>
            <th>Campaign</th>
            <th>Source</th>
            <th>Profile</th>
            <th>Target requests</th>
            <th>Observed provider calls</th>
            <th>Executions</th>
            <th>Attempts</th>
            <th>Campaign findings</th>
            <th>Observed tokens</th>
            <th>Reasoning tokens</th>
            <th>Role USD remaining</th>
            <th>Role p50</th>
            <th>Role p95</th>
            <th>Cost / target request</th>
            <th>Cost / provider call</th>
            <th>Known total</th>
            <th>Run time</th>
            <th>Budget state</th>
            <th>Known role spend</th>
            <th>Unresolved USD exposure</th>
            <th>Unresolved provider calls</th>
            <th>Role calls remaining</th>
          </tr>
        </thead>
        <tbody>
          {costs.map((record) => (
            <tr key={record.accounting_id}>
              <td className="mono" title={record.campaign_id}>{shortId(record.campaign_id)}</td>
              <td>{record.agent_role?.replace("_", " ") ?? record.provider}</td>
              <td>{record.execution_profile}</td>
              <td className="mono">{record.agent_role ? "Not applicable" : count(record.request_count)}</td>
              <td className="mono">{record.agent_role ? count(record.physical_call_count) : "Not applicable"}</td>
              <td className="mono">{count(record.execution_count)}</td>
              <td className="mono">{count(record.attempt_count)}</td>
              <td className="mono">{record.agent_role ? "Not applicable" : count(record.confirmed_finding_count)}</td>
              <td className="mono">{record.token_observation_count > 0 ? count((record.input_tokens ?? 0) + (record.output_tokens ?? 0) + (record.reasoning_tokens ?? 0)) : "Not reported by engine"}</td>
              <td className="mono">{record.reasoning_tokens === null ? "Not reported" : count(record.reasoning_tokens)}</td>
              <td className="mono">{roleBudgetValue(record, "role_usd_remaining")}</td>
              <td className="mono">{costRoleLatencyValue(record, "p50_duration_ms")}</td>
              <td className="mono">{costRoleLatencyValue(record, "p95_duration_ms")}</td>
              <td className="mono">{record.agent_role ? "Not applicable" : money(record.average_cost_per_request)}</td>
              <td className="mono">{record.agent_role ? money(record.average_cost_per_request) : "Not applicable"}</td>
              <td className="mono">{costValue(record)}</td>
              <td className="mono">{duration(record.duration_ms)}</td>
              <td>{record.provider_budget ? budgetStateLabel(record.provider_budget) : "Not applicable"}</td>
              <td className="mono">{record.provider_budget === null ? "Not applicable" : record.accounting_status === "unavailable" ? "Unavailable" : money(record.provider_budget.role_usd_spent)}</td>
              <td className="mono">{record.provider_budget === null ? "Not applicable" : record.provider_budget.status === "unavailable" ? "Not available" : money(record.provider_budget.role_unresolved_usd_exposure)}</td>
              <td className="mono">{record.provider_budget === null ? "Not applicable" : record.provider_budget.status === "unavailable" ? "Not available" : count(record.provider_budget.role_unresolved_physical_calls)}</td>
              <td className="mono">{roleBudgetValue(record, "role_calls_remaining")}</td>
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
  const campaignCosts = costs.filter((record) => record.record_kind === "campaign");
  const campaignSpend = sum(campaignCosts.map((record) => record.measured_cost));
  const totalRequests = sum(campaignCosts.map((record) => record.request_count));
  const confirmedFindings = sum(
    campaignCosts.map((record) => record.confirmed_finding_count),
  );
  const campaignBudgets = new Map<string, number>();
  for (const record of costs) {
    if (record.budget_usd !== null) {
      campaignBudgets.set(
        record.campaign_id,
        Math.max(campaignBudgets.get(record.campaign_id) ?? 0, record.budget_usd),
      );
    }
  }
  const totalBudget = sum([...campaignBudgets.values()]);
  const budgetedSpend = sum(campaignCosts.filter((record) => record.budget_usd !== null).map((record) => record.measured_cost));
  const requestLedger = physicalRequests(traces);
  const agentCosts = costs.filter((record) => record.record_kind === "agent");
  const agentSpend = sum(agentCosts.map((record) => record.measured_cost));
  const unresolvedAgentExposure = sum(agentCosts.map(
    (record) => record.provider_budget?.role_unresolved_usd_exposure ?? 0,
  ));
  const unresolvedAgentCalls = sum(agentCosts.map(
    (record) => record.provider_budget?.role_unresolved_physical_calls ?? 0,
  ));
  const newestActiveCampaign = agentCosts
    .filter((record) => record.provider_budget?.status === "active")
    .sort((left, right) => right.recorded_at.localeCompare(left.recorded_at))[0]
    ?.campaign_id;
  const currentBudgetsByRole = new Map<string, NonNullable<CostReadModel["provider_budget"]>>();
  for (const record of agentCosts) {
    if (
      record.campaign_id === newestActiveCampaign
      && record.agent_role !== null
      && record.provider_budget?.status === "active"
    ) {
      currentBudgetsByRole.set(record.agent_role, record.provider_budget);
    }
  }
  const activeProviderBudgets = [...currentBudgetsByRole.values()];
  const roleBudgetRemaining = sum(activeProviderBudgets.map(
    (budget) => budget.role_usd_remaining ?? 0,
  ));
  const globalBudget = activeProviderBudgets[0] ?? null;
  const incompleteAgentAccounting = agentCosts.filter(
    (record) => ["partial", "unavailable"].includes(record.accounting_status),
  ).length;
  const requestCost = sum(requestLedger.map((trace) => trace.measured_cost));
  const reconciliationDelta = campaignSpend - requestCost;

  return (
    <>
      <MetricStrip label="Cost summary" values={[
        { label: "Known measured spend", value: incompleteAgentAccounting ? `${money(totalCost)} known` : money(totalCost), note: `${money(campaignSpend)} campaign + ${money(agentSpend)} agents` },
        { label: "Physical request spend", value: money(requestCost), note: `${count(totalRequests)} requests accounted` },
        { label: "Confirmed findings", value: count(confirmedFindings), note: "Campaign summary ledger" },
        {
          label: "Individual agent spend",
          value: incompleteAgentAccounting || unresolvedAgentExposure > 0
            ? `${money(agentSpend)} known`
            : money(agentSpend),
          note: unresolvedAgentExposure > 0 || unresolvedAgentCalls > 0
            ? `${money(unresolvedAgentExposure)} unresolved · ${count(unresolvedAgentCalls)} call(s)`
            : incompleteAgentAccounting
              ? `${incompleteAgentAccounting} record(s) have incomplete provider accounting`
              : `${count(agentCosts.length)} role-level records`,
        },
        {
          label: "Provider budget remaining",
          value: activeProviderBudgets.length > 0 ? money(roleBudgetRemaining) : "—",
          note: globalBudget
            ? `${money(globalBudget.global_usd_remaining ?? 0)} global · ${count(globalBudget.global_calls_remaining ?? 0)} calls · after unresolved exposure`
            : "No active hosted budget",
        },
        { label: "Approved budget used", value: totalBudget ? percent(budgetedSpend / totalBudget) : "—", note: totalBudget ? `${money(budgetedSpend)} of ${money(totalBudget)}` : "No budget projection available" },
      ]} />
      <div className="panel-grid observability-grid">
        <Panel title="Spend by campaign and agent" meta="measured vs approved cap" eyebrow="MEASURED TELEMETRY">
          <CostBars costs={costs} />
          <div className="chart-legend">
            <span><i className="budget" />Approved cap</span>
            <span><i className="spend" />Known spend</span>
            <span><i className="unresolved" />Unresolved exposure</span>
          </div>
        </Panel>
        <Panel title="Loaded trace sample" meta="summary ledger vs newest trace rows" eyebrow="MEASURED TELEMETRY">
          <div className="reconciliation-grid">
            <div><span>Campaign summaries</span><strong className="mono">{money(campaignSpend)}</strong></div>
            <div><span>Agent execution ledger</span><strong className="mono">{incompleteAgentAccounting ? `${money(agentSpend)} known` : money(agentSpend)}</strong></div>
            <div><span>Unresolved provider exposure</span><strong className="mono">{money(unresolvedAgentExposure)}</strong></div>
            <div><span>Unresolved provider calls</span><strong className="mono">{count(unresolvedAgentCalls)}</strong></div>
            <div><span>Loaded request traces</span><strong className="mono">{money(requestCost)}</strong></div>
            <div><span>Summary minus loaded sample</span><strong className="mono">{money(reconciliationDelta)}</strong></div>
            <div><span>Trace projection</span><strong className="mono">{traceState}</strong></div>
          </div>
          <p className="data-note">Campaign summaries are authoritative. The trace endpoint is a bounded drill-in window, so this delta is sample coverage—not an accounting variance.</p>
        </Panel>
      </div>
      <Panel title="Cost accounting" meta="authoritative PostgreSQL campaign and agent ledgers" eyebrow="MEASURED TELEMETRY">
        <CostTable costs={costs} />
      </Panel>
      <StateNotice
        state="empty"
        detail="Known spend comes from provider measurements. Unresolved exposure reserves conservative USD and call headroom until accounting resolves; remaining values already subtract both. Historical headroom is closed. No tokens × rate estimate is used."
      />
    </>
  );
}

export function TracesScreen({ client }: { client: ApiClient }) {
  const traces = useResource<TraceReadModel[]>(
    client,
    RESOURCE_PATHS.traces,
    decodeTraces,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  return (
    <div className="screen-stack">
      <ScreenHeading title="Traces" detail="A bounded newest-first drill-in of recent agent executions and physical target requests, correlated across campaign, attempt, durable ledger and Langfuse with PostgreSQL-backed canonical-role latency and spend." eyebrow="HEADSHOT OBSERVABILITY" />
      <ResourceView result={traces.result} emptyLabel="No request or agent telemetry has been recorded yet.">
        {(data) => <TraceDashboard traces={data} />}
      </ResourceView>
    </div>
  );
}

export function CostsScreen({ client }: { client: ApiClient }) {
  const costs = useResource<CostReadModel[]>(
    client,
    RESOURCE_PATHS.costs,
    decodeCosts,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  const traces = useResource<TraceReadModel[]>(
    client,
    RESOURCE_PATHS.traces,
    decodeTraces,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Costs"
        detail="Provider-measured spend, unresolved exposure, conservative remaining headroom, historical authorization state, and ledger reconciliation—without token-cost estimates."
        eyebrow="HEADSHOT OBSERVABILITY"
      />
      <ResourceView result={costs.result} emptyLabel="No measured campaign accounting records are available.">
        {(data) => <CostDashboard costs={data} traces={traceData(traces.result)} traceState={traces.result.state} />}
      </ResourceView>
    </div>
  );
}
