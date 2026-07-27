import { useState } from "react";

import type { ApiClient } from "../api/client";
import type { ResourceResult } from "../api/contracts";
import { RESOURCE_PATHS } from "../api/paths";
import { decodeCosts, decodeTraces } from "../api/read-models";
import { AdversarialText } from "../components/AdversarialText";
import { ExpandableEvidence } from "../components/ExpandableEvidence";
import {
  count,
  DistributionBars,
  EvidenceGrid,
  MetricStrip,
  money,
  Panel,
  percent,
  providerEventStatusLabel,
  ScreenHeading,
  servedModel,
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
const knownCost = (value: number | null) => value ?? 0;
const tokenCount = (value: number | null) => value === null ? "Unavailable" : count(value);
const observedTokenTotal = (record: CostReadModel) => {
  if (record.token_observation_count === 0) {
    return record.execution_mode === "hosted_advisory" && record.execution_count > 0
      ? "Unavailable · Partial"
      : "Not applicable";
  }
  const components = [
    record.input_tokens,
    record.output_tokens,
    record.reasoning_tokens,
  ];
  const known = components.filter((value): value is number => value !== null);
  if (known.length === 0) return "Unavailable · Partial";
  const total = count(sum(known));
  const partial = known.length < components.length
    || (
      record.execution_mode === "hosted_advisory"
      && record.token_observation_count < record.execution_count
    );
  return partial ? `${total} known · Partial` : total;
};
const providerCallCountValue = (record: CostReadModel) =>
  record.physical_call_count_state === "not_applicable"
    ? "Not applicable"
    : record.physical_call_count_state === "lower_bound"
    ? record.physical_call_count === 0
      ? "Unavailable—historical count incomplete"
      : `≥${count(record.physical_call_count)} known`
    : count(record.physical_call_count);
const remainingCallValue = (
  budget: NonNullable<CostReadModel["provider_budget"]>,
  scope: "role" | "global",
) => {
  const state = scope === "role"
    ? budget.role_call_count_state
    : budget.global_call_count_state;
  const remaining = scope === "role"
    ? budget.role_calls_remaining
    : budget.global_calls_remaining;
  const known = scope === "role"
    ? budget.role_physical_calls
    : budget.global_physical_calls;
  if (state === null) return "calls unavailable";
  const conservative = remaining === null
    ? "conservative headroom unavailable"
    : `${count(remaining)} conservative calls remaining`;
  if (state === "lower_bound") {
    return known === 0
      ? `${conservative} · historical count incomplete`
      : `${conservative} · ≥${count(known)} observed`;
  }
  return `${conservative} · exact observed count`;
};

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

const traceHasError = (trace: TraceReadModel) => (
  trace.error_code !== null
  || trace.status === "failed"
  || trace.status === "error"
  || (
    trace.provider_event_status !== null
    && !["succeeded", "model_mismatch"].includes(trace.provider_event_status)
  )
);

const traceFailureLabel = (trace: TraceReadModel) => {
  const codes = [
    trace.error_code,
    trace.provider_event_status !== null
      && !["succeeded", "model_mismatch"].includes(trace.provider_event_status)
      ? trace.provider_event_status
      : null,
  ].filter((value): value is string => value !== null);
  return [...new Set(codes)].join(" · ") || "unknown_execution_failure";
};

export const orderTracesForOperators = (
  traces: TraceReadModel[],
): TraceReadModel[] => [...traces].sort((left, right) => {
  const errorPriority = Number(traceHasError(right)) - Number(traceHasError(left));
  if (errorPriority !== 0) return errorPriority;
  return right.started_at.localeCompare(left.started_at);
});

const langfuseDeliveryLabel = (trace: TraceReadModel) => {
  if (trace.langfuse_verified_at !== null) {
    return `remotely query-back verified · ${time(trace.langfuse_verified_at)}`;
  }
  if (trace.langfuse_status === "exported") {
    return "exported · remote query-back not verified";
  }
  if (trace.langfuse_status === "queued") {
    return "queued for export or remote verification";
  }
  if (trace.langfuse_status === "error") return "export error";
  if (trace.langfuse_status === "disabled") return "delivery disabled";
  if (trace.langfuse_status === "not_attempted") return "delivery not attempted";
  return "historical · delivery not instrumented";
};

const traceCostValue = (trace: TraceReadModel) => {
  if (trace.accounting_status === "unavailable" || trace.measured_cost === null) {
    return "Unavailable";
  }
  if (trace.accounting_status === "partial") {
    return `${money(trace.measured_cost)} known · partial`;
  }
  return money(trace.measured_cost);
};

const compactTraceCostValue = (trace: TraceReadModel) => {
  if (trace.accounting_status === "unavailable" || trace.measured_cost === null) {
    return "unavailable";
  }
  if (trace.accounting_status === "partial") {
    return `${compactMoney(trace.measured_cost)} known · partial`;
  }
  return compactMoney(trace.measured_cost);
};

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
  if (record.measured_cost === null) return "Not applicable";
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
  const formatted = field === "role_usd_remaining"
    ? budget.role_usd_remaining === null
      ? `Conservative headroom unavailable · ≤ ${money(budget.role_usd_remaining_upper_bound ?? 0)} known-spend bound`
      : `${money(budget.role_usd_remaining)} conservative · ≤ ${money(budget.role_usd_remaining_upper_bound ?? 0)} known-spend bound`
    : remainingCallValue(budget, "role");
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
    totalCost: sum(requests.map((trace) => knownCost(trace.measured_cost))),
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
        {isAgent && <div><dt>Provider</dt><dd className="mono">{trace.provider}</dd></div>}
        {isAgent && <div><dt>Requested model</dt><dd className="mono">{trace.requested_model ?? trace.model ?? "unavailable"}</dd></div>}
        {isAgent && (
          <div>
            <dt>Provider-served model</dt>
            <dd className="mono">
              {trace.returned_model === null
                || trace.returned_model.startsWith("unsafe-provider-text-")
                ? `unavailable · ${providerEventStatusLabel(trace.provider_event_status)}`
                : trace.returned_model}
            </dd>
          </div>
        )}
        {isAgent && (
          <div>
            <dt>Requested → served</dt>
            <dd className="mono">
              {servedModel({
                model: trace.requested_model ?? "unavailable",
                returned_model: trace.returned_model,
                model_substituted: trace.model_substituted,
                execution_mode: trace.execution_mode ?? "deterministic",
                provider_event_status: trace.provider_event_status,
              })}
            </dd>
          </div>
        )}
        {isAgent && <div><dt>Provider-served upstream</dt><dd className="mono">{trace.upstream_provider ?? "unavailable"}</dd></div>}
        {isAgent && <div><dt>Provider request</dt><dd className="mono">{trace.provider_request_id ?? "unavailable"}</dd></div>}
        {isAgent && <div><dt>Provider event status</dt><dd className="mono">{providerEventStatusLabel(trace.provider_event_status)}</dd></div>}
        {isAgent && (
          <div>
            <dt>Provider event lineage</dt>
            <dd className="mono">
              {trace.provider_lineage_state === "historical_not_instrumented"
                ? "Historical—not instrumented"
                : trace.provider_lineage_state === "canonical_physical"
                  ? `${count(trace.provider_event_ids.length)} canonical event(s)`
                  : "Not applicable"}
            </dd>
          </div>
        )}
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
        {isAgent && <div><dt>Input / output / reasoning tokens</dt><dd className="mono">{`${tokenCount(trace.input_tokens)} / ${tokenCount(trace.output_tokens)} / ${tokenCount(trace.reasoning_tokens)}`}</dd></div>}
        {isAgent && <div><dt>Physical provider calls</dt><dd className="mono">{trace.physical_attempts === null ? "Unavailable" : count(trace.physical_attempts)}</dd></div>}
        {trace.agent_role === "judge" && <div><dt>Evaluator calibration</dt><dd className="mono">{trace.judge_calibration_state ?? "unavailable"}</dd></div>}
        {trace.agent_role === "judge" && <div><dt>LLM / oracle agreement</dt><dd className="mono">{trace.oracle_agreement === null ? "unavailable" : trace.oracle_agreement ? "agrees" : "disagrees"}</dd></div>}
        {trace.agent_role === "judge" && <div><dt>Decisive authority</dt><dd className="mono">{trace.decision_authority ?? "unavailable"}</dd></div>}
      </dl>
      <div className="correlation-chain" aria-label="Observation correlation chain">
        <span>Campaign</span><i>→</i><span>Attempt</span><i>→</i><span>{isAgent ? `${trace.agent_role?.replace("_", " ")} agent` : "Target request"}</span><i>→</i><span>Langfuse delivery</span>
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
      {trace.error_code && (
        <StateNotice
          state="error"
          detail={`${isAgent ? "Agent/provider" : "Target transport"} error: ${trace.error_code}`}
        />
      )}
    </div>
  );
}

function TraceLedger({
  traces,
  selected,
  onSelect,
  label,
}: {
  traces: TraceReadModel[];
  selected: TraceReadModel | undefined;
  onSelect?: (identity: string) => void;
  label: string;
}) {
  const visible = traces.slice(0, 25);
  return (
    <>
      <div className="trace-list" role="list" aria-label={label}>
        {visible.map((trace) => {
          const content = (
            <>
              <span className={`status-dot ${traceHasError(trace) ? "idle" : "live"}`} />
              <span>
                <strong className="mono">{shortId(trace.trace_id)}</strong>
                <small>
                  {traceHasError(trace)
                    ? `${traceFailureLabel(trace)} · `
                    : ""}
                  {trace.operation} · {trace.agent_role?.replace("_", " ") ?? "target"} · {time(trace.started_at)}
                </small>
              </span>
              <span className="mono">{trace.duration_ms === null ? "running" : duration(trace.duration_ms)}</span>
              <span className="mono">{compactTraceCostValue(trace)}</span>
            </>
          );
          const className = `trace-list-row ${selected && traceIdentity(selected) === traceIdentity(trace) ? "active" : ""}`;
          return onSelect ? (
            <button
              type="button"
              role="listitem"
              className={className}
              key={traceIdentity(trace)}
              onClick={() => onSelect(traceIdentity(trace))}
            >
              {content}
            </button>
          ) : (
            <div role="listitem" className={className} key={traceIdentity(trace)}>
              {content}
            </div>
          );
        })}
      </div>
      {traces.length > visible.length && (
        <p className="data-note">
          Showing the first {count(visible.length)} error-prioritized observations of {count(traces.length)}.
        </p>
      )}
    </>
  );
}

function TraceFailureSummary({ trace }: { trace: TraceReadModel }) {
  const errorCode = traceFailureLabel(trace);
  return (
    <Panel
      title="Execution failure"
      meta={time(trace.started_at)}
      eyebrow="ACTIONABLE ERROR"
    >
      <StateNotice
        state="error"
        detail={`${trace.agent_role?.replace("_", " ") ?? "Target request"} failed with ${errorCode.replaceAll("_", " ")}.`}
      />
      <EvidenceGrid values={[
        {
          label: "Error code",
          value: trace.error_code ?? "Unavailable",
          tone: "failure",
        },
        {
          label: "Provider event",
          value: providerEventStatusLabel(trace.provider_event_status),
          tone: traceHasError(trace) ? "failure" : undefined,
        },
        {
          label: "Provider",
          value: trace.agent_role === null ? "Not applicable" : trace.provider,
        },
        {
          label: "Model",
          value: trace.agent_role === null
            ? "Not applicable"
            : trace.requested_model ?? trace.model ?? "Unavailable",
        },
        {
          label: "Attempt",
          value: shortId(trace.attempt_id),
        },
      ]} />
    </Panel>
  );
}

function TraceDashboard({
  traces,
  campaignId,
}: {
  traces: TraceReadModel[];
  campaignId?: string;
}) {
  const allObservations = liveObservations(traces);
  const newestObservation = [...allObservations].sort(
    (left, right) => right.started_at.localeCompare(left.started_at),
  )[0];
  const selectedCampaignId = campaignId ?? newestObservation?.campaign_id ?? null;
  const observations = orderTracesForOperators(allObservations.filter(
    (trace) => trace.campaign_id === selectedCampaignId,
  ));
  const globalHistory = orderTracesForOperators(allObservations.filter(
    (trace) => trace.campaign_id !== selectedCampaignId,
  ));
  const requests = physicalRequests(observations);
  const agents = agentObservations(observations);
  const summary = summarizeTraces(observations);
  const [selectedId, setSelectedId] = useState<string | null>(
    observations[0] ? traceIdentity(observations[0]) : null,
  );
  const selected = observations.find((trace) => traceIdentity(trace) === selectedId) ?? observations[0];
  const latestFailure = observations.find(traceHasError);
  const verified = observations.filter((trace) => trace.langfuse_verified_at !== null).length;
  const exported = observations.filter(
    (trace) => trace.langfuse_status === "exported" && trace.langfuse_verified_at === null,
  ).length;
  const queued = observations.filter(
    (trace) => trace.langfuse_status === "queued" && trace.langfuse_verified_at === null,
  ).length;
  const failed = observations.filter(
    (trace) => trace.langfuse_status === "error" && trace.langfuse_verified_at === null,
  ).length;
  const disabled = observations.filter(
    (trace) => trace.langfuse_status === "disabled" && trace.langfuse_verified_at === null,
  ).length;
  const notAttempted = observations.filter(
    (trace) => trace.langfuse_status === "not_attempted" && trace.langfuse_verified_at === null,
  ).length;
  const historical = observations.filter(
    (trace) => trace.langfuse_status === "historical_not_instrumented"
      && trace.langfuse_verified_at === null,
  ).length;
  const observationSpend = aggregateSpend(observations);
  const incompleteAccounting = observations.filter(
    (trace) => (
      ["partial", "unavailable"].includes(trace.accounting_status)
      || trace.measured_cost === null
    ),
  ).length;
  const observationLatencies = observations.flatMap((trace) => (
    trace.duration_ms === null ? [] : [trace.duration_ms]
  ));
  const verifiedCoverage = observations.length ? verified / observations.length : 0;

  if (observations.length === 0) {
    return (
      <>
        <StateNotice
          state="empty"
          detail={selectedCampaignId
            ? `No agent or target-request observations are available for campaign ${shortId(selectedCampaignId)}.`
            : "No agent or target-request observations are available."}
        />
        {globalHistory.length > 0 && (
          <ExpandableEvidence
            title="Global trace history"
            meta={`${count(globalHistory.length)} observations outside this campaign`}
          >
            <TraceLedger
              traces={globalHistory}
              selected={undefined}
              label="Global correlated target requests and agent executions"
            />
          </ExpandableEvidence>
        )}
      </>
    );
  }

  return (
    <>
      {latestFailure && <TraceFailureSummary trace={latestFailure} />}
      <MetricStrip label="Campaign observability summary" values={[
        { label: "Campaign", value: shortId(selectedCampaignId), note: "Current trace scope" },
        { label: "Durable work", value: count(observations.length), note: `${count(requests.length)} target requests · ${count(agents.length)} agent executions` },
        { label: "Execution latency", value: observationLatencies.length ? duration(sum(observationLatencies) / observationLatencies.length) : "Unavailable", note: observationLatencies.length ? `p95 ${duration(percentile(observationLatencies, 0.95))}` : "No completed observation" },
        {
          label: "Known trace cost",
          value: spendLabel(observationSpend),
          note: incompleteAccounting > 0
            ? `${incompleteAccounting} observation(s) have partial or unavailable provider accounting`
            : `${bytes(summary.totalBytes)} target traffic`,
        },
        { label: "Langfuse query-back", value: percent(verifiedCoverage), note: `${count(verified)} of ${count(observations.length)} remotely verified` },
      ]} />
      <div className="panel-grid observability-grid">
        <Panel title="Langfuse delivery" meta="campaign-scoped durable ledger" eyebrow="MEASURED TELEMETRY">
          <DistributionBars rows={[
            { label: "Remotely query-back verified", value: verified, display: count(verified), tone: "success" },
            { label: "Exported · query-back unverified", value: exported, display: count(exported), tone: "queued" },
            { label: "Queued", value: queued, display: count(queued), tone: "queued" },
            { label: "Export error", value: failed, display: count(failed), tone: "failure" },
            { label: "Disabled", value: disabled, display: count(disabled) },
            { label: "Not attempted", value: notAttempted, display: count(notAttempted) },
            { label: "Historical · not instrumented", value: historical, display: count(historical) },
          ]} />
          <p className="data-note">PostgreSQL remains authoritative. Exported and queued states do not assert remote acceptance. Only exact remote query-back verification proves that Langfuse has the observation; this view makes no claim about Langfuse authentication state.</p>
        </Panel>
        <Panel title="Correlation" meta="selected observation" eyebrow="MEASURED TELEMETRY">
          {selected ? (
            <div className="correlation-chain" aria-label="Selected observation hierarchy">
              <span>Campaign</span><i>→</i><span>Attempt</span><i>→</i>
              <span>{selected.agent_role ? `${selected.agent_role.replace("_", " ")} agent` : "Target request"}</span>
            </div>
          ) : (
            <StateNotice state="empty" detail="Select an observation to inspect its correlation path." />
          )}
        </Panel>
      </div>
      <div className="panel-grid trace-explorer-grid">
        <Panel title="Campaign trace ledger" meta="errors first · newest within state" eyebrow="MEASURED TELEMETRY">
          <TraceLedger
            traces={observations}
            selected={selected}
            onSelect={setSelectedId}
            label="Campaign-correlated target requests and agent executions"
          />
        </Panel>
        <Panel title="Observation detail" meta={selected ? time(selected.started_at) : undefined} eyebrow="MEASURED TELEMETRY">
          {selected ? <TraceDetails trace={selected} /> : <StateNotice state="empty" detail="No request or agent observation is available." />}
        </Panel>
      </div>
      <ExpandableEvidence
        title="Latency timeline"
        meta={`${count(observations.length)} campaign observations`}
      >
        <LatencyChart traces={observations} />
      </ExpandableEvidence>
      {globalHistory.length > 0 && (
        <ExpandableEvidence
          title="Global trace history"
          meta={`${count(globalHistory.length)} observations outside this campaign`}
        >
          <TraceLedger
            traces={globalHistory}
            selected={undefined}
            label="Global correlated target requests and agent executions"
          />
        </ExpandableEvidence>
      )}
      <p className="data-note">
        Black-box target requests do not synthesize token usage. Runtime roles report provider-measured hosted usage and cost; target and infrastructure spans remain separately accounted.
      </p>
    </>
  );
}

function CostBars({ costs }: { costs: CostReadModel[] }) {
  const cap = (record: CostReadModel) => {
    const roleCap = record.provider_budget?.role_usd_cap;
    return roleCap === null || roleCap === undefined
      ? record.budget_usd ?? knownCost(record.measured_cost)
      : roleCap + (record.provider_budget?.role_usd_overrun ?? 0);
  };
  const knownSpend = (record: CostReadModel) =>
    record.provider_budget?.role_usd_spent
    ?? knownCost(record.measured_cost);
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
      if (record.budget_usd === null) return "No approved budget projection";
      if (record.budget_utilization === null) {
        return `${record.accounting_status === "partial" ? "Partial" : "Unavailable"} · ${money(record.budget_usd)} cap`;
      }
      return `${percent(record.budget_utilization)} of ${money(record.budget_usd)} cap`;
    }
    if (budget.status === "unavailable") return "No authorized hosted subcap";
    const remainingUsd = budget.role_usd_remaining === null
      ? `conservative headroom unavailable · ≤ ${money(budget.role_usd_remaining_upper_bound ?? 0)} known-spend bound`
      : `${money(budget.role_usd_remaining)} conservative · ≤ ${money(budget.role_usd_remaining_upper_bound ?? 0)} known-spend bound`;
    const remainingCalls = remainingCallValue(budget, "role");
    if (budget.status === "historical") {
      return `${remainingUsd} at close · ${remainingCalls} · historical authorization`;
    }
    if (budget.status === "staged_pending_authorization") {
      return `${remainingUsd} staged · ${remainingCalls} · not active`;
    }
    return `${remainingUsd} · ${remainingCalls}`;
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
              <td className="mono">{record.agent_role ? providerCallCountValue(record) : "Not applicable"}</td>
              <td className="mono">{count(record.execution_count)}</td>
              <td className="mono">{count(record.attempt_count)}</td>
              <td className="mono">{record.agent_role ? "Not applicable" : count(record.confirmed_finding_count)}</td>
              <td className="mono">{observedTokenTotal(record)}</td>
              <td className="mono">{tokenCount(record.reasoning_tokens)}</td>
              <td className="mono">{roleBudgetValue(record, "role_usd_remaining")}</td>
              <td className="mono">{costRoleLatencyValue(record, "p50_duration_ms")}</td>
              <td className="mono">{costRoleLatencyValue(record, "p95_duration_ms")}</td>
              <td className="mono">{record.agent_role
                ? "Not applicable"
                : record.average_cost_per_request === null
                  ? "Unavailable"
                  : money(record.average_cost_per_request)}</td>
              <td className="mono">{record.agent_role
                ? record.average_cost_per_request === null
                  ? record.physical_call_count_state === "lower_bound"
                    ? "Unavailable—historical count incomplete"
                    : record.physical_call_count === 0
                      ? "Not applicable"
                      : "Unavailable"
                  : money(record.average_cost_per_request)
                : "Not applicable"}</td>
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

interface SpendAggregate {
  known: number | null;
  complete: boolean;
}

interface SpendRecord {
  measured_cost: number | null;
  accounting_status: "not_applicable" | "measured" | "partial" | "unavailable";
}

const aggregateSpend = (records: SpendRecord[]): SpendAggregate => {
  if (records.length === 0) return { known: null, complete: false };
  const knownRecords = records.filter((record) => (
    record.measured_cost !== null && record.accounting_status !== "unavailable"
  ));
  return {
    known: knownRecords.length === 0
      ? null
      : sum(knownRecords.map((record) => record.measured_cost ?? 0)),
    complete: knownRecords.length === records.length
      && records.every((record) => !["partial", "unavailable"].includes(record.accounting_status)),
  };
};

const spendLabel = (aggregate: SpendAggregate) => {
  if (aggregate.known === null) return "Unavailable";
  return aggregate.complete ? money(aggregate.known) : `${money(aggregate.known)} known`;
};

export interface CampaignCostSummary {
  campaignId: string;
  providerSpend: SpendAggregate;
  targetSpend: SpendAggregate;
  totalSpend: SpendAggregate;
  providerCalls: number | null;
  providerCallCountState: "exact" | "lower_bound" | "unavailable";
  targetRequests: number | null;
  attempts: number | null;
  confirmedFindings: number | null;
}

export const summarizeCampaignCosts = (
  costs: CostReadModel[],
  campaignId: string,
): CampaignCostSummary => {
  const selected = costs.filter((record) => record.campaign_id === campaignId);
  const agentCosts = selected.filter((record) => record.record_kind === "agent");
  const campaignCosts = selected.filter((record) => record.record_kind === "campaign");
  const providerSpend = aggregateSpend(agentCosts);
  const targetSpend = aggregateSpend(campaignCosts);
  const knownParts = [providerSpend.known, targetSpend.known].filter(
    (value): value is number => value !== null,
  );
  const providerCallRecords = agentCosts.filter(
    (record) => record.physical_call_count_state !== "not_applicable",
  );
  return {
    campaignId,
    providerSpend,
    targetSpend,
    totalSpend: {
      known: knownParts.length === 0 ? null : sum(knownParts),
      complete: providerSpend.complete && targetSpend.complete,
    },
    providerCalls: providerCallRecords.length === 0
      ? null
      : sum(providerCallRecords.map((record) => record.physical_call_count)),
    providerCallCountState: providerCallRecords.length === 0
      ? "unavailable"
      : providerCallRecords.every((record) => record.physical_call_count_state === "exact")
        ? "exact"
        : "lower_bound",
    targetRequests: campaignCosts.length === 0
      ? null
      : sum(campaignCosts.map((record) => record.request_count)),
    attempts: selected.length === 0
      ? null
      : Math.max(...selected.map((record) => record.attempt_count)),
    confirmedFindings: campaignCosts.length === 0
      ? null
      : Math.max(...campaignCosts.map((record) => record.confirmed_finding_count)),
  };
};

const callCountLabel = (summary: CampaignCostSummary) => {
  if (summary.providerCalls === null) return "Unavailable";
  return summary.providerCallCountState === "lower_bound"
    ? `≥${count(summary.providerCalls)}`
    : count(summary.providerCalls);
};

function CostDashboard({
  costs,
  traces,
  traceState,
  campaignId,
}: {
  costs: CostReadModel[];
  traces: TraceReadModel[];
  traceState: string;
  campaignId?: string;
}) {
  const newestRecord = [...costs].sort(
    (left, right) => right.recorded_at.localeCompare(left.recorded_at),
  )[0];
  const selectedCampaignId = campaignId ?? newestRecord?.campaign_id ?? null;
  const selectedCosts = costs.filter(
    (record) => record.campaign_id === selectedCampaignId,
  );
  const globalHistory = costs
    .filter((record) => record.campaign_id !== selectedCampaignId)
    .sort((left, right) => right.recorded_at.localeCompare(left.recorded_at));

  if (selectedCampaignId === null || selectedCosts.length === 0) {
    return (
      <>
        <StateNotice
          state="empty"
          detail={selectedCampaignId
            ? `No accounting records are available for campaign ${shortId(selectedCampaignId)}.`
            : "No campaign accounting records are available."}
        />
        {globalHistory.length > 0 && (
          <ExpandableEvidence title="Global cost history" meta={`${count(globalHistory.length)} records`}>
            <CostTable costs={globalHistory.slice(0, 50)} />
          </ExpandableEvidence>
        )}
      </>
    );
  }

  const summary = summarizeCampaignCosts(selectedCosts, selectedCampaignId);
  const selectedAgents = selectedCosts.filter((record) => record.record_kind === "agent");
  const selectedCampaigns = selectedCosts.filter((record) => record.record_kind === "campaign");
  const selectedRequestTraces = physicalRequests(traces).filter(
    (trace) => trace.campaign_id === selectedCampaignId,
  );
  const traceSpend = aggregateSpend(selectedRequestTraces);
  const latestAgentBudget = [...selectedAgents]
    .filter((record) => record.provider_budget !== null)
    .sort((left, right) => right.recorded_at.localeCompare(left.recorded_at))[0]
    ?.provider_budget ?? null;
  const budgetRemaining = latestAgentBudget?.status === "active"
    ? latestAgentBudget.global_usd_remaining
    : null;
  const budgetUpperBound = latestAgentBudget?.global_usd_remaining_upper_bound ?? null;
  const budgetNote = latestAgentBudget === null || latestAgentBudget.status !== "active"
    ? "No active hosted budget"
    : budgetUpperBound === null
      ? "Known-spend bound unavailable"
      : `≤ ${money(budgetUpperBound)} known-spend bound`;
  const physicalWork = summary.targetRequests === null
    ? "Target requests unavailable"
    : `${count(summary.targetRequests)} target request${summary.targetRequests === 1 ? "" : "s"}`;
  const providerWork = summary.providerCalls === null
    ? "Provider calls unavailable"
    : `${callCountLabel(summary)} provider call${summary.providerCalls === 1 ? "" : "s"}`;

  return (
    <>
      <MetricStrip label="Campaign cost summary" values={[
        {
          label: "Known measured spend",
          value: spendLabel(summary.totalSpend),
          note: `Selected campaign total · ${shortId(selectedCampaignId)}`,
        },
        {
          label: "Provider agent spend",
          value: spendLabel(summary.providerSpend),
          note: `${providerWork} · ${count(selectedAgents.length)} role ledgers`,
        },
        {
          label: "Target request spend",
          value: spendLabel(summary.targetSpend),
          note: physicalWork,
        },
        {
          label: "Attempts",
          value: summary.attempts === null ? "Unavailable" : count(summary.attempts),
          note: `${summary.confirmedFindings === null ? "Findings unavailable" : `${count(summary.confirmedFindings)} confirmed findings`}`,
        },
        {
          label: "Provider budget remaining",
          value: budgetRemaining === null ? "Unavailable" : money(budgetRemaining),
          note: budgetNote,
        },
      ]} />
      <div className="panel-grid observability-grid">
        <Panel title="Selected campaign spend" meta={shortId(selectedCampaignId)} eyebrow="MEASURED TELEMETRY">
          <CostBars costs={selectedCosts} />
          <div className="chart-legend">
            <span><i className="budget" />Approved cap</span>
            <span><i className="spend" />Known spend</span>
            <span><i className="unresolved" />Unresolved exposure</span>
          </div>
        </Panel>
        <Panel title="Campaign accounting scope" meta="one campaign · no portfolio mixing" eyebrow="AUTHORITATIVE VIEW">
          <EvidenceGrid values={[
            { label: "Campaign", value: shortId(selectedCampaignId) },
            { label: "Provider agents", value: count(selectedAgents.length) },
            { label: "Campaign ledgers", value: count(selectedCampaigns.length) },
            { label: "Target requests", value: summary.targetRequests === null ? "Unavailable" : count(summary.targetRequests) },
            { label: "Provider calls", value: callCountLabel(summary) },
            { label: "Total", value: spendLabel(summary.totalSpend) },
          ]} />
        </Panel>
      </div>
      <ExpandableEvidence
        title="Full campaign accounting ledger"
        meta={`${count(selectedCosts.length)} authoritative records`}
      >
        <CostTable costs={selectedCosts} />
      </ExpandableEvidence>
      <ExpandableEvidence
        title="Loaded target trace evidence"
        meta={`${count(selectedRequestTraces.length)} bounded trace rows`}
      >
        <div className="reconciliation-grid">
          <div><span>Target-request summary</span><strong className="mono">{spendLabel(summary.targetSpend)}</strong></div>
          <div><span>Loaded target traces</span><strong className="mono">{spendLabel(traceSpend)}</strong></div>
          <div><span>Trace projection</span><strong className="mono">{traceState}</strong></div>
        </div>
        <p className="data-note">Campaign accounting is authoritative. The trace endpoint is a bounded drill-in window and is shown as evidence coverage, never subtracted from the campaign ledger.</p>
      </ExpandableEvidence>
      {globalHistory.length > 0 && (
        <ExpandableEvidence
          title="Global cost history"
          meta={`${count(globalHistory.length)} records outside this campaign`}
        >
          <CostTable costs={globalHistory.slice(0, 50)} />
          {globalHistory.length > 50 && (
            <p className="data-note">Showing the newest 50 global records. Narrow scope to inspect another campaign.</p>
          )}
        </ExpandableEvidence>
      )}
      <p className="data-note">
        Known spend comes from provider measurements. Unresolved exposure reserves conservative USD and call headroom until accounting resolves; remaining values already subtract both. Historical headroom is closed. No tokens × rate estimate is used.
      </p>
    </>
  );
}

export function TracesScreen({
  client,
  campaignId,
}: {
  client: ApiClient;
  campaignId?: string;
}) {
  const traces = useResource<TraceReadModel[]>(
    client,
    campaignId
      ? RESOURCE_PATHS.campaignTraces(campaignId)
      : RESOURCE_PATHS.traces,
    decodeTraces,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  return (
    <div className="screen-stack">
      <ScreenHeading title="Traces" detail="Campaign-scoped failures, agent executions and physical target requests, ordered for incident response and correlated to the durable ledger and Langfuse delivery evidence." eyebrow="HEADSHOT OBSERVABILITY" />
      <ResourceView result={traces.result} emptyLabel="No request or agent telemetry has been recorded yet.">
        {(data) => <TraceDashboard traces={data} campaignId={campaignId} />}
      </ResourceView>
    </div>
  );
}

export function CostsScreen({
  client,
  campaignId,
}: {
  client: ApiClient;
  campaignId?: string;
}) {
  const costs = useResource<CostReadModel[]>(
    client,
    campaignId
      ? RESOURCE_PATHS.campaignCosts(campaignId)
      : RESOURCE_PATHS.costs,
    decodeCosts,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  const traces = useResource<TraceReadModel[]>(
    client,
    campaignId
      ? RESOURCE_PATHS.campaignTraces(campaignId)
      : RESOURCE_PATHS.traces,
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
        {(data) => (
          <CostDashboard
            costs={data}
            traces={traceData(traces.result)}
            traceState={traces.result.state}
            campaignId={campaignId}
          />
        )}
      </ResourceView>
    </div>
  );
}
