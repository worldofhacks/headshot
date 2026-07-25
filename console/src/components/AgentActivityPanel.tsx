import type { ApiClient } from "../api/client";
import { RESOURCE_PATHS } from "../api/paths";
import { decodeAgentActivity } from "../api/read-models";
import {
  LIVE_RESOURCE_POLL_INTERVAL_MS,
  useResource,
} from "../hooks/useResource";
import type { AgentActivityReadModel } from "../types";
import {
  count,
  money,
  Panel,
  servedModel,
  shortId,
  Timeline,
} from "./Analytics";
import { ResourceView, StateNotice } from "./ResourceView";

const activityTone = (
  status: AgentActivityReadModel["status"],
): "success" | "failure" | "queued" =>
  status === "failed" ? "failure" : status === "running" ? "queued" : "success";

const evaluatorState = (row: AgentActivityReadModel): string => {
  if (row.agent_role !== "judge") return "";
  const agreement = row.oracle_agreement === null
    ? "oracle comparison unavailable"
    : row.oracle_agreement
      ? "agrees with oracle"
      : "disagrees with oracle";
  const authority = row.decision_authority
    ? `${row.decision_authority} decisive`
    : "authority unavailable";
  return ` · calibration ${row.judge_calibration_state ?? "unavailable"} · ${agreement} · ${authority}`;
};

const accountingValue = (records: AgentActivityReadModel[]): string => {
  const known = records.filter(
    (row) => row.accounting_status !== "unavailable" && row.measured_cost !== null,
  );
  if (known.length === 0) return "Unavailable";
  const measured = known.reduce((total, row) => total + (row.measured_cost ?? 0), 0);
  return known.length === records.length
    && known.every((row) => row.accounting_status === "measured")
    ? money(measured)
    : `${money(measured)} known`;
};

const tokenValue = (records: AgentActivityReadModel[]): string => {
  const observed = records.filter((row) =>
    row.input_tokens !== null
    || row.output_tokens !== null
    || row.reasoning_tokens !== null
  );
  if (observed.length === 0) return "Not reported";
  const totals = observed.reduce(
    (result, row) => ({
      input: result.input + (row.input_tokens ?? 0),
      output: result.output + (row.output_tokens ?? 0),
      reasoning: result.reasoning + (row.reasoning_tokens ?? 0),
    }),
    { input: 0, output: 0, reasoning: 0 },
  );
  return `${count(totals.input)} in · ${count(totals.output)} out · ${count(totals.reasoning)} reasoning`;
};

const rowAccountingValue = (row: AgentActivityReadModel): string =>
  row.accounting_status === "unavailable"
    ? "cost unavailable"
    : row.measured_cost === null
      ? "cost unavailable"
    : row.accounting_status === "partial"
      ? `${money(row.measured_cost)} known cost`
      : money(row.measured_cost);

const providerLineageValue = (row: AgentActivityReadModel): string =>
  row.provider_lineage_state === "historical_not_instrumented"
    ? "provider events historical—not instrumented"
    : row.provider_lineage_state === "canonical_physical"
      ? `${count(row.provider_event_ids.length)} canonical provider event(s)`
      : "provider events not applicable";

export function AgentActivityPanel({
  client,
  campaignRunId,
  title = "Live agent activity",
}: {
  client: ApiClient;
  campaignRunId?: string | null;
  title?: string;
}) {
  const activity = useResource<AgentActivityReadModel[]>(
    client,
    RESOURCE_PATHS.agentActivity,
    decodeAgentActivity,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  const allRecords = activity.result.data ?? [];
  const records = campaignRunId
    ? allRecords.filter((row) => row.campaign_run_id === campaignRunId)
    : allRecords;
  const providerCalls = records.reduce(
    (total, row) => total + (row.physical_attempts ?? 0),
    0,
  );
  const hostedRecords = records.filter((row) => row.execution_mode === "hosted_advisory");
  const providerCallValue = hostedRecords.length === 0
    ? "Not applicable"
    : hostedRecords.some(
        (row) => row.provider_lineage_state === "historical_not_instrumented",
      )
      ? providerCalls === 0
        ? "Unavailable—historical count incomplete"
        : `≥${count(providerCalls)} known`
      : count(providerCalls);
  const verifiedTraces = records.filter(
    (row) => row.langfuse_status === "exported" && row.langfuse_verified_at !== null,
  ).length;
  const pendingTraces = records.filter((row) => row.langfuse_status === "queued").length;
  const failedTraces = records.filter((row) => row.langfuse_status === "error").length;

  return (
    <Panel
      title={title}
      meta={campaignRunId ? shortId(campaignRunId) : "newest durable executions"}
      eyebrow="AGENT EXECUTION LEDGER"
    >
      {records.length > 0 ? (
        <>
          <div className="reconciliation-grid">
            <div><span>Executions</span><strong className="mono">{count(records.length)}</strong></div>
            <div><span>Provider calls</span><strong className="mono">{providerCallValue}</strong></div>
            <div><span>Provider spend</span><strong className="mono">{accountingValue(records)}</strong></div>
            <div><span>Observed tokens</span><strong className="mono">{tokenValue(records)}</strong></div>
            <div>
              <span>Langfuse query-back</span>
              <strong className="mono">{count(verifiedTraces)} / {count(records.length)}</strong>
              <small>{count(pendingTraces)} queued · {count(failedTraces)} error</small>
            </div>
          </div>
          <Timeline rows={records.slice(0, 12).map((row) => ({
            id: row.execution_id,
            title: `${row.agent_role.replace("_", " ")} · ${row.status}`,
            detail: `${servedModel(row)} · ${shortId(row.trace_id)} · ${rowAccountingValue(row)} · ${providerLineageValue(row)} · Langfuse ${row.langfuse_status.replaceAll("_", " ")}${evaluatorState(row)}`,
            at: row.started_at,
            tone: activityTone(row.status),
          }))} />
        </>
      ) : (
        <ResourceView
          result={activity.result}
          emptyLabel="No durable agent executions are recorded for this scope."
        >
          {() => (
            <StateNotice
              state="empty"
              detail="No durable agent executions are recorded for this scope."
            />
          )}
        </ResourceView>
      )}
    </Panel>
  );
}
