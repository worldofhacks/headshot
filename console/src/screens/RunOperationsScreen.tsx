import { useState } from "react";

import type { ApiClient } from "../api/client";
import type { Principal, ResourceResult } from "../api/contracts";
import {
  decodeAgentActivity,
  decodeAgentPromptSnapshot,
  decodeAttempts,
  decodeCampaignOperations,
  decodeCampaigns,
} from "../api/read-models";
import { COMMAND_PATHS, RESOURCE_PATHS } from "../api/paths";
import {
  ExpandableEvidence,
  PromptTranscript,
} from "../components/ExpandableEvidence";
import {
  DistributionBars,
  EvidenceGrid,
  MetricStrip,
  Panel,
  ScreenHeading,
  count,
  money,
  shortId,
  time,
} from "../components/Analytics";
import { CommandButton } from "../components/CommandButton";
import { ResourceView, StateNotice } from "../components/ResourceView";
import { RunFailurePanel } from "../components/RunFailurePanel";
import {
  LIVE_RESOURCE_POLL_INTERVAL_MS,
  useResource,
  type ResourceController,
} from "../hooks/useResource";
import type {
  AgentActivityReadModel,
  AgentPromptSnapshotReadModel,
  AttemptReadModel,
  CampaignOperationsReadModel,
  CampaignReadModel,
} from "../types";
import { PERMISSIONS } from "../types";

export interface RunOperationsScreenProps {
  client: ApiClient;
  principal: Principal;
  campaignId?: string | null;
  expandedAttemptId?: string | null;
  onCampaignSelect?: (campaignId: string) => void;
  onAttemptSelect?: (attemptId: string) => void;
}

const latestFirst = (left: CampaignReadModel, right: CampaignReadModel) =>
  Date.parse(right.created_at) - Date.parse(left.created_at);

export function selectOperationsCampaign(
  campaigns: CampaignReadModel[],
  requestedCampaignId: string | null | undefined,
): CampaignReadModel | null {
  if (requestedCampaignId) {
    return campaigns.find((campaign) => campaign.run_id === requestedCampaignId) ?? null;
  }
  const active = campaigns
    .filter((campaign) => campaign.state === "running" || campaign.state === "queued")
    .sort(latestFirst);
  return active[0] ?? [...campaigns].sort(latestFirst)[0] ?? null;
}

const optionalCount = (value: number | null) =>
  value === null ? "Unavailable" : count(value);

const optionalMoney = (value: number | null) =>
  value === null ? "Unavailable" : money(value);

const measuredMoney = (
  value: number | null,
  state: "measured" | "partial" | "unavailable",
) => {
  if (value === null || state === "unavailable") return "Unavailable";
  return state === "partial" ? `${money(value)} known · Partial` : money(value);
};

const progressSummary = (operations: CampaignOperationsReadModel) => {
  const completed = count(operations.progress.completed);
  return operations.progress.planned === null
    ? `${completed} completed`
    : `${completed}/${count(operations.progress.planned)} completed`;
};

const currentWorkSummary = (operations: CampaignOperationsReadModel) => {
  if (operations.current_work === null) {
    return operations.state === "complete"
      ? "Run complete"
      : operations.state === "failed"
        ? "Stopped at failure"
        : operations.state === "aborted"
          ? "Run aborted"
          : "Awaiting assignment";
  }
  const owner = operations.current_work.agent_role?.replace("_", " ")
    ?? "target dispatch";
  return `${owner} · ${operations.current_work.stage}`;
};

export function runNextAction(operations: CampaignOperationsReadModel): string {
  switch (operations.state) {
    case "queued":
      return "Monitor the governed queue while the authorized campaign awaits execution.";
    case "running":
      return "Monitor live case progress. Use the existing governed abort control only if intervention is required.";
    case "complete":
      return "Review verdicts and expand an attempt to inspect its preserved evidence.";
    case "aborted":
      return "To run again, submit a new campaign authorization request for the exact target and governed safety scope.";
    case "failed":
      return "Review the typed failure. To run again, submit a new campaign authorization request; the Policy Gateway must approve the exact target, synthetic-data, budget, rate, and abort scope.";
  }
}

function FreshnessSummary({
  operations,
  freshness,
}: {
  operations: CampaignOperationsReadModel;
  freshness: ResourceController<CampaignOperationsReadModel>["freshness"];
}) {
  const state = freshness.state === "snapshot"
    ? "Server snapshot"
    : freshness.state.charAt(0).toUpperCase() + freshness.state.slice(1);
  return (
    <span
      className={`connection-chip connection-${freshness.stale ? "degraded" : "operational"}`}
      role="status"
      aria-live="polite"
    >
      <span className={`status-dot ${freshness.stale ? "idle" : "live"}`} />
      {state} · as of {time(operations.as_of)} · cursor {count(operations.cursor)}
    </span>
  );
}

function PromptSnapshotResource({
  client,
  execution,
}: {
  client: ApiClient;
  execution: AgentActivityReadModel;
}) {
  const snapshot = useResource<AgentPromptSnapshotReadModel>(
    client,
    RESOURCE_PATHS.agentPromptSnapshot(execution.execution_id),
    decodeAgentPromptSnapshot,
  );
  return (
    <ResourceView
      result={snapshot.result}
      emptyLabel="No immutable prompt snapshot is available for this execution."
    >
      {(data) => {
        if (
          data.execution_id !== execution.execution_id
          || data.campaign_run_id !== execution.campaign_run_id
          || data.attempt_id !== execution.attempt_id
          || data.agent_role !== execution.agent_role
        ) {
          return (
            <StateNotice
              state="error"
              detail="The prompt snapshot identity does not match the selected execution."
            />
          );
        }
        return (
          <PromptTranscript
            promptVersion={data.system_prompt_version}
            promptSha256={data.system_prompt_sha256}
            transcriptSha256={data.transcript_sha256}
            systemPrompt={data.system_prompt_content}
            messages={data.provider_messages}
            redactions={data.redactions}
          />
        );
      }}
    </ResourceView>
  );
}

export function ExecutionPromptEvidence({
  client,
  execution,
  canReadEvidence,
}: {
  client: ApiClient;
  execution: AgentActivityReadModel;
  canReadEvidence: boolean;
}) {
  const [requested, setRequested] = useState(false);
  if (!canReadEvidence) {
    return (
      <StateNotice
        state="unavailable"
        detail="Exact prompt contents require the org:evidence:read permission."
      />
    );
  }
  return (
    <ExpandableEvidence
      title="Immutable prompt snapshot"
      meta="permission-gated"
      onToggle={(open) => {
        if (open) setRequested(true);
      }}
    >
      {requested
        ? <PromptSnapshotResource client={client} execution={execution} />
        : (
          <p className="data-note">
            Expand to request the exact immutable prompt transcript.
          </p>
        )}
    </ExpandableEvidence>
  );
}

const availableActivity = (
  result: ResourceResult<AgentActivityReadModel[]>,
): AgentActivityReadModel[] => (
  ["ready", "stale", "degraded"].includes(result.state) && result.data !== null
    ? result.data
    : []
);

function ExecutionEvidence({
  client,
  execution,
  canReadEvidence,
}: {
  client: ApiClient;
  execution: AgentActivityReadModel;
  canReadEvidence: boolean;
}) {
  const statusTone = execution.status === "failed" ? "failure" : undefined;
  return (
    <ExpandableEvidence
      title={`${execution.agent_role.replace("_", " ")} execution`}
      meta={`${execution.status} · ${execution.provider} · ${execution.model}`}
    >
      <EvidenceGrid
        values={[
          { label: "Status", value: execution.status, tone: statusTone },
          { label: "Provider", value: execution.provider },
          { label: "Model", value: execution.model },
          {
            label: "Physical provider calls",
            value: execution.physical_attempts === null
              ? "Unavailable"
              : count(execution.physical_attempts),
          },
          {
            label: "Measured provider cost",
            value: execution.measured_cost === null
              ? "Unavailable"
              : money(execution.measured_cost),
          },
          {
            label: "Cost state",
            value: execution.accounting_status,
          },
          {
            label: "Started",
            value: time(execution.started_at),
          },
          {
            label: "Finished",
            value: execution.finished_at === null
              ? "Running"
              : time(execution.finished_at),
          },
          {
            label: "Failure",
            value: execution.error_code ?? "None recorded",
            tone: execution.error_code === null ? undefined : "failure",
          },
        ]}
      />
      <ExecutionPromptEvidence
        client={client}
        execution={execution}
        canReadEvidence={canReadEvidence}
      />
    </ExpandableEvidence>
  );
}

function AttemptEvidenceList({
  client,
  attempts,
  activity,
  canReadEvidence,
  expandedAttemptId,
  onAttemptSelect,
}: {
  client: ApiClient;
  attempts: AttemptReadModel[];
  activity: AgentActivityReadModel[];
  canReadEvidence: boolean;
  expandedAttemptId?: string | null;
  onAttemptSelect?: (attemptId: string) => void;
}) {
  return (
    <div className="event-stack">
      {attempts.map((attempt) => {
        const executions = activity
          .filter((execution) => execution.attempt_id === attempt.attempt_id)
          .sort((left, right) => left.started_at.localeCompare(right.started_at));
        return (
          <ExpandableEvidence
            key={attempt.attempt_id}
            title={`Attempt ${count(attempt.ordinal)}`}
            meta={`${attempt.verdict ?? "Verdict unavailable"} · case ${shortId(attempt.case_id)}`}
            defaultOpen={expandedAttemptId === attempt.attempt_id}
            onToggle={(open) => {
              if (open) onAttemptSelect?.(attempt.attempt_id);
            }}
          >
            <EvidenceGrid
              values={[
                { label: "Case", value: shortId(attempt.case_id) },
                { label: "Verdict", value: attempt.verdict ?? "Unavailable" },
                {
                  label: "Executed",
                  value: attempt.executed_at === null ? "Unavailable" : time(attempt.executed_at),
                },
                { label: "Profile", value: attempt.execution_profile ?? "Unavailable" },
                { label: "Provenance", value: attempt.evidence_provenance ?? "Unavailable" },
              ]}
            />
            {executions.length === 0
              ? (
                <StateNotice
                  state="empty"
                  detail="No agent executions are correlated to this attempt."
                />
              )
              : executions.map((execution) => (
                <ExecutionEvidence
                  key={execution.execution_id}
                  client={client}
                  execution={execution}
                  canReadEvidence={canReadEvidence}
                />
              ))}
          </ExpandableEvidence>
        );
      })}
    </div>
  );
}

function AttemptList({
  client,
  principal,
  campaignId,
  expandedAttemptId,
  onAttemptSelect,
}: {
  client: ApiClient;
  principal: Principal;
  campaignId: string;
  expandedAttemptId?: string | null;
  onAttemptSelect?: (attemptId: string) => void;
}) {
  const attempts = useResource<AttemptReadModel[]>(
    client,
    RESOURCE_PATHS.attempts(campaignId),
    decodeAttempts,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  const activity = useResource<AgentActivityReadModel[]>(
    client,
    RESOURCE_PATHS.campaignAgentActivity(campaignId),
    decodeAgentActivity,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  const activityData = availableActivity(activity.result);
  const activityNotice = activity.result.state === "loading"
    ? <StateNotice state="loading" detail="Loading campaign execution lineage." />
    : activity.result.state === "empty"
      ? <StateNotice state="empty" detail="No agent execution lineage is available yet." />
      : ["unavailable", "error"].includes(activity.result.state)
        ? (
          <StateNotice
            state={activity.result.state}
            reason={activity.result.reason_code}
            detail={activity.result.detail}
          />
        )
        : ["stale", "degraded"].includes(activity.result.state)
          ? (
            <StateNotice
              state={activity.result.state}
              reason={activity.result.reason_code}
              detail={activity.result.detail}
            />
          )
          : null;
  return (
    <Panel
      title="Attempts and execution evidence"
      meta="collapsed by default"
      eyebrow="EXECUTION EVIDENCE"
    >
      {activityNotice}
      <ResourceView
        result={attempts.result}
        emptyLabel="No attempts have been persisted for this campaign."
      >
        {(data) => (
          <AttemptEvidenceList
            client={client}
            attempts={data}
            activity={activityData}
            canReadEvidence={principal.organization_permissions.includes(PERMISSIONS.evidenceRead)}
            expandedAttemptId={expandedAttemptId}
            onAttemptSelect={onAttemptSelect}
          />
        )}
      </ResourceView>
    </Panel>
  );
}

export function RunOperationsView({
  operations,
  freshness,
}: {
  operations: CampaignOperationsReadModel;
  freshness: ResourceController<CampaignOperationsReadModel>["freshness"];
}) {
  const progress = operations.progress;
  const execution = operations.executions;
  const limits = operations.limits;
  const queue = operations.queue;
  const verdictRows = Object.entries(operations.verdict_distribution)
    .map(([label, value]) => ({ label, value }))
    .sort((left, right) => right.value - left.value || left.label.localeCompare(right.label));
  const current = operations.current_work;

  return (
    <>
      <MetricStrip
        label="Current run status"
        values={[
          {
            label: "Status",
            value: operations.state.toUpperCase(),
            note: `Created ${time(operations.created_at)}`,
          },
          {
            label: "Case progress",
            value: progressSummary(operations),
            note: progress.remaining === null
              ? "Remaining count unavailable"
              : `${count(progress.remaining)} remaining`,
          },
          {
            label: "Current work",
            value: currentWorkSummary(operations),
            note: current === null
              ? "No active execution"
              : `Started ${time(current.started_at)}`,
          },
          {
            label: "Measured total",
            value: measuredMoney(
              operations.costs.total_measured_usd,
              operations.costs.measurement_state,
            ),
            note: `${operations.costs.measurement_state} · ${operations.costs.currency}`,
          },
        ]}
      />

      {operations.state === "failed" && operations.terminal_failure !== null && (
        <RunFailurePanel failure={operations.terminal_failure} />
      )}

      <div className="state-notice" role="status">
        <span className="state-kicker mono">NEXT ACTION</span>
        <span>{runNextAction(operations)}</span>
      </div>

      <div className="panel-grid">
        <Panel title="Case progress" meta={shortId(operations.campaign_id)} eyebrow="AUTHORITATIVE CASE COUNTS">
          <EvidenceGrid
            values={[
              { label: "Planned", value: optionalCount(progress.planned) },
              { label: "Started", value: count(progress.started) },
              { label: "Running", value: count(progress.running), tone: progress.running > 0 ? "queued" : undefined },
              { label: "Completed", value: count(progress.completed), tone: "success" },
              { label: "Failed", value: count(progress.failed), tone: progress.failed > 0 ? "failure" : undefined },
              { label: "Skipped", value: optionalCount(progress.skipped) },
              { label: "Remaining", value: optionalCount(progress.remaining) },
            ]}
          />
        </Panel>

        <Panel title="Execution accounting" eyebrow="DISTINCT EXECUTION UNITS">
          <EvidenceGrid
            values={[
              { label: "Logical attempts", value: count(execution.logical_attempts) },
              { label: "Physical target requests", value: count(execution.physical_target_requests) },
              { label: "Provider calls", value: count(execution.provider_calls) },
            ]}
          />
          <p className="data-note">
            Logical cases, target dispatches, and provider calls are intentionally not combined.
          </p>
        </Panel>

        <Panel title="Measured cost" meta={operations.costs.measurement_state} eyebrow="RECONCILED SPEND">
          <EvidenceGrid
            values={[
              {
                label: "Provider",
                value: measuredMoney(
                  operations.costs.provider_measured_usd,
                  operations.costs.provider_measurement_state,
                ),
              },
              {
                label: "Target",
                value: measuredMoney(
                  operations.costs.target_measured_usd,
                  operations.costs.target_measurement_state,
                ),
              },
              {
                label: "Total",
                value: measuredMoney(
                  operations.costs.total_measured_usd,
                  operations.costs.measurement_state,
                ),
              },
              { label: "Provider cap", value: optionalMoney(limits.provider_budget_usd) },
              { label: "Provider remaining", value: optionalMoney(limits.provider_budget_remaining_usd) },
              { label: "Target cap", value: optionalMoney(limits.target_budget_usd) },
              { label: "Target remaining", value: optionalMoney(limits.target_budget_remaining_usd) },
            ]}
          />
        </Panel>

        <Panel title="Queue and limits" eyebrow="GOVERNED CAPACITY">
          <EvidenceGrid
            values={[
              { label: "Queued jobs", value: count(queue.queued_jobs), tone: queue.queued_jobs > 0 ? "queued" : undefined },
              { label: "Leased jobs", value: count(queue.leased_jobs) },
              { label: "Dead letter", value: count(queue.dead_lettered_jobs), tone: queue.dead_lettered_jobs > 0 ? "failure" : undefined },
              {
                label: "Rate limit",
                value: queue.rate_limit_active === null
                  ? "Unavailable"
                  : queue.rate_limit_active
                    ? "Active"
                    : "Clear",
              },
              { label: "Requests / second", value: limits.target_requests_per_second === null ? "Unavailable" : String(limits.target_requests_per_second) },
              { label: "Logical case cap", value: optionalCount(limits.logical_case_limit) },
              { label: "Max attempts / run", value: optionalCount(limits.max_attempts_per_run) },
              { label: "Request cap", value: optionalCount(limits.physical_request_limit) },
              { label: "Requests remaining", value: optionalCount(limits.physical_requests_remaining) },
              { label: "Target retries / turn", value: optionalCount(limits.target_retries_per_turn) },
              { label: "Provider call cap", value: optionalCount(limits.provider_call_limit) },
              { label: "Provider calls remaining", value: optionalCount(limits.provider_calls_remaining) },
              { label: "Provider max retries", value: optionalCount(limits.provider_max_retries) },
              { label: "Provider concurrency", value: optionalCount(limits.provider_max_concurrency) },
              { label: "Provider timeout", value: limits.provider_timeout_seconds === null ? "Unavailable" : `${count(limits.provider_timeout_seconds)}s` },
              { label: "Run timeout", value: limits.run_timeout_seconds === null ? "Unavailable" : `${count(limits.run_timeout_seconds)}s` },
            ]}
          />
        </Panel>
      </div>

      <div className="panel-grid">
        <Panel title="Verdict distribution" eyebrow="RECORDED OUTCOMES">
          {verdictRows.length === 0
            ? <StateNotice state="empty" detail="No verdicts have been recorded for this campaign." />
            : <DistributionBars rows={verdictRows} />}
        </Panel>

        <Panel
          title="Current execution"
          meta={current?.execution_id ? shortId(current.execution_id) : undefined}
          eyebrow="LIVE AGENT WORK"
        >
          {current === null
            ? (
              <StateNotice
                state="empty"
                detail="The authoritative projection reports no active agent execution."
              />
            )
            : (
              <EvidenceGrid
                values={[
                  { label: "Agent", value: current.agent_role?.replace("_", " ") ?? "Unavailable" },
                  { label: "Stage", value: current.stage },
                  { label: "Execution", value: current.execution_id === null ? "Unavailable" : shortId(current.execution_id) },
                  { label: "Attempt", value: current.attempt_id === null ? "Unavailable" : shortId(current.attempt_id) },
                  { label: "Started", value: time(current.started_at) },
                ]}
              />
            )}
        </Panel>
      </div>

      <FreshnessSummary operations={operations} freshness={freshness} />
    </>
  );
}

function GovernedCampaignControls({
  client,
  principal,
  operations,
  refresh,
}: {
  client: ApiClient;
  principal: Principal;
  operations: CampaignOperationsReadModel;
  refresh: () => void;
}) {
  if (operations.state !== "queued" && operations.state !== "running") return null;
  return (
    <div className="command-row" aria-label="Governed campaign controls">
      <CommandButton
        client={client}
        path={COMMAND_PATHS.abortCampaign(operations.campaign_id)}
        payload={{ reason: "operator_abort" }}
        label="Abort selected campaign"
        allowed={principal.organization_permissions.includes(PERMISSIONS.campaignAbort)}
        unavailableReason={PERMISSIONS.campaignAbort}
        destructive
        onAcknowledged={refresh}
      />
    </div>
  );
}

function SelectedRunOperations({
  client,
  principal,
  campaignId,
  expandedAttemptId,
  onAttemptSelect,
}: {
  client: ApiClient;
  principal: Principal;
  campaignId: string;
  expandedAttemptId?: string | null;
  onAttemptSelect?: (attemptId: string) => void;
}) {
  const operations = useResource<CampaignOperationsReadModel>(
    client,
    RESOURCE_PATHS.campaignOperations(campaignId),
    decodeCampaignOperations,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  return (
    <>
      <ResourceView
        result={operations.result}
        emptyLabel="No operational projection is available for this campaign."
      >
        {(data) => (
          <>
            <RunOperationsView operations={data} freshness={operations.freshness} />
            <GovernedCampaignControls
              client={client}
              principal={principal}
              operations={data}
              refresh={operations.refresh}
            />
          </>
        )}
      </ResourceView>
      <AttemptList
        client={client}
        principal={principal}
        campaignId={campaignId}
        expandedAttemptId={expandedAttemptId}
        onAttemptSelect={onAttemptSelect}
      />
    </>
  );
}

export function RunOperationsScreen({
  client,
  principal,
  campaignId = null,
  expandedAttemptId = null,
  onCampaignSelect,
  onAttemptSelect,
}: RunOperationsScreenProps) {
  const [localCampaignId, setLocalCampaignId] = useState<string | null>(null);
  const campaigns = useResource<CampaignReadModel[]>(
    client,
    RESOURCE_PATHS.campaigns,
    decodeCampaigns,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  const campaignRecords = campaigns.result.data ?? [];
  const requestedCampaignId = campaignId ?? localCampaignId;
  const selectedCampaign = selectOperationsCampaign(campaignRecords, requestedCampaignId);
  const selectedCampaignId = requestedCampaignId ?? selectedCampaign?.run_id ?? null;
  const selectedMetadata = selectedCampaignId === null
    ? null
    : campaignRecords.find((campaign) => campaign.run_id === selectedCampaignId) ?? null;
  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Run operations"
        detail="Authoritative campaign progress, current agent work, measured spend, queue state, and typed failures."
        eyebrow="LIVE OPERATIONS"
      />
      {selectedCampaignId === null
        ? (
          <ResourceView
            result={campaigns.result}
            emptyLabel="No campaigns have been persisted."
          >
            {() => <StateNotice state="empty" detail="No campaign can be selected." />}
          </ResourceView>
        )
        : (
          <>
            <label className="form-field scope-picker">
              Campaign scope
              <select
                value={selectedCampaignId}
                onChange={(event) => {
                  setLocalCampaignId(event.target.value);
                  onCampaignSelect?.(event.target.value);
                }}
              >
                {selectedMetadata === null && (
                  <option value={selectedCampaignId}>
                    {shortId(selectedCampaignId)} · metadata unavailable
                  </option>
                )}
                {[...campaignRecords].sort(latestFirst).map((campaign) => (
                  <option key={campaign.run_id} value={campaign.run_id}>
                    {campaign.target_version} · {campaign.state} · {time(campaign.created_at)}
                  </option>
                ))}
              </select>
            </label>
            {selectedMetadata === null && (
              <StateNotice
                state="unavailable"
                detail="Selected campaign metadata is unavailable in the bounded campaign list. Loading the exact campaign-scoped operations projection."
              />
            )}
            <SelectedRunOperations
              client={client}
              principal={principal}
              campaignId={selectedCampaignId}
              expandedAttemptId={expandedAttemptId}
              onAttemptSelect={onAttemptSelect}
            />
          </>
        )}
    </div>
  );
}
