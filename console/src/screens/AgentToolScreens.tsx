import { useMemo, useState } from "react";

import type { ApiClient } from "../api/client";
import type { Principal } from "../api/contracts";
import { RESOURCE_PATHS } from "../api/paths";
import {
  decodeAgentActivity,
  decodeAgentPrompt,
  decodeAgents,
  decodeTooling,
} from "../api/read-models";
import { AdversarialText } from "../components/AdversarialText";
import {
  count,
  MetricStrip,
  money,
  Panel,
  percent,
  ScreenHeading,
  servedModel,
  shortId,
  TagMatrix,
  time,
  Timeline,
} from "../components/Analytics";
import { RecordTable, ResourceView, StateNotice } from "../components/ResourceView";
import {
  LIVE_RESOURCE_POLL_INTERVAL_MS,
  useResource,
} from "../hooks/useResource";
import { navigateTo } from "../router";
import {
  PERMISSIONS,
  type AgentActivityReadModel,
  type AgentPromptReadModel,
  type AgentReadModel,
  type ToolScopeReadModel,
} from "../types";

type AgentRole = AgentReadModel["role"];

type PromptAssignmentIdentity = Pick<
  AgentReadModel["active_assignment"],
  "prompt_version" | "prompt_sha256" | "configuration_sha256"
>;

export interface AgentPromptSelection {
  source: "active" | "staged";
  version: string;
  sha256: string;
  configurationSha256: string;
}

export const selectAgentPromptIdentity = (
  agent: {
    active_assignment: PromptAssignmentIdentity;
    staged_assignment: PromptAssignmentIdentity | null;
  } | null,
): AgentPromptSelection | null => {
  const candidates = [
    ["active", agent?.active_assignment],
    ["staged", agent?.staged_assignment],
  ] as const;
  for (const [source, assignment] of candidates) {
    if (assignment?.prompt_version && assignment.prompt_sha256) {
      return {
        source,
        version: assignment.prompt_version,
        sha256: assignment.prompt_sha256,
        configurationSha256: assignment.configuration_sha256,
      };
    }
  }
  return null;
};

const roleDisplayOrder: AgentRole[] = ["orchestrator", "red_team", "judge", "documentation"];

const statusTone = (status: string): "success" | "failure" | "queued" =>
  status === "failed" ? "failure" : status === "running" ? "queued" : "success";

const langfuseDelivery = (agent: AgentReadModel): string => {
  if (agent.execution_count === 0) return "no executions";
  const states = [
    ["observed", agent.langfuse_verified_count],
    ["awaiting remote verification", agent.langfuse_queued_count],
    ["error", agent.langfuse_error_count],
    ["disabled", agent.langfuse_disabled_count],
    ["not attempted", agent.langfuse_not_attempted_count],
  ] as const;
  return states
    .filter(([, value]) => value > 0)
    .map(([label, value]) => `${value} ${label}`)
    .join(" · ");
};

const langfuseDeliveryState = (activity: AgentActivityReadModel) => {
  if (activity.langfuse_verified_at !== null) {
    return `observed · ${time(activity.langfuse_verified_at)}`;
  }
  return activity.langfuse_status === "queued"
    ? "awaiting remote verification"
    : activity.langfuse_status.replaceAll("_", " ");
};

const accountingValue = (agent: AgentReadModel) => {
  if (
    agent.accounting_status === "unavailable"
    || agent.accounting_status === "not_applicable"
    || agent.measured_cost === null
  ) return agent.accounting_status.replaceAll("_", " ");
  if (agent.accounting_status === "partial") return `${money(agent.measured_cost)} known · partial`;
  return money(agent.measured_cost);
};

const activityAccountingValue = (activity: AgentActivityReadModel) => {
  if (activity.accounting_status === "unavailable" || activity.measured_cost === null) {
    return "unavailable";
  }
  if (activity.accounting_status === "partial") {
    return `${money(activity.measured_cost)} known · partial`;
  }
  return money(activity.measured_cost);
};

const activityProviderLineageValue = (activity: AgentActivityReadModel) => {
  if (activity.provider_lineage_state === "historical_not_instrumented") {
    return "Historical—not instrumented";
  }
  if (activity.provider_lineage_state === "canonical_physical") {
    return `${count(activity.provider_event_ids.length)} canonical event(s)`;
  }
  return "Not applicable";
};

const budgetRemainingValue = (
  remaining: number | null,
  upperBound: number | null,
  cap: number | null,
) => {
  if (cap === null || upperBound === null) return "unavailable";
  if (remaining === null) {
    return `Conservative headroom unavailable / ${money(cap)} · ≤ ${money(upperBound)} known-spend bound`;
  }
  return `${money(remaining)} conservative / ${money(cap)} · ≤ ${money(upperBound)} known-spend bound`;
};

const callRemainingValue = (
  state: "exact" | "lower_bound" | null,
  remaining: number | null,
  knownCalls: number,
  cap: number | null,
) => {
  if (state === null || cap === null) return "unavailable";
  const conservative = remaining === null
    ? `Conservative headroom unavailable / ${count(cap)}`
    : `${count(remaining)} conservative / ${count(cap)}`;
  if (state === "lower_bound") {
    return `${conservative} · ${knownCalls === 0
      ? "historical count incomplete"
      : `≥${count(knownCalls)} observed`}`;
  }
  return `${conservative} · exact observed count`;
};

const physicalCallValue = (agent: AgentReadModel) => {
  if (agent.physical_call_count_state === "not_applicable") return "Not applicable";
  if (agent.physical_call_count_state === "lower_bound") {
    return agent.physical_call_count === 0
      ? "Unavailable—historical count incomplete"
      : `≥${count(agent.physical_call_count)} known`;
  }
  return count(agent.physical_call_count);
};

function AgentPromptPanel({
  client,
  role,
  version,
  sha256,
  configurationSha256,
  source,
}: {
  client: ApiClient;
  role: AgentRole;
  version: string;
  sha256: string;
  configurationSha256: string;
  source: AgentPromptSelection["source"];
}) {
  const prompt = useResource<AgentPromptReadModel>(
    client,
    RESOURCE_PATHS.agentPrompt(role, version, sha256, configurationSha256),
    decodeAgentPrompt,
  );

  return (
    <Panel
      title={`${source === "active" ? "Active" : "Staged"} system prompt`}
      meta={source === "active" ? "ACTIVE CONFIGURATION" : "PENDING AUTHORIZATION"}
      eyebrow="SERVER-OWNED PROMPT · CONFIG_MANAGE ONLY"
    >
      <ResourceView
        result={prompt.result}
        emptyLabel="No server-owned prompt is registered for this role."
      >
        {(data) => (
          <>
            <dl className="agent-ledger-summary">
              <div><dt>Version</dt><dd className="mono">{data.prompt_version}</dd></div>
              <div><dt>SHA-256</dt><dd className="mono">{data.prompt_sha256}</dd></div>
            </dl>
            <AdversarialText>{data.system_prompt}</AdversarialText>
          </>
        )}
      </ResourceView>
    </Panel>
  );
}

export function AgentsScreen({
  client,
  principal,
}: {
  client: ApiClient;
  principal: Principal;
}) {
  const agents = useResource<AgentReadModel[]>(
    client,
    RESOURCE_PATHS.agents,
    decodeAgents,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  const activity = useResource<AgentActivityReadModel[]>(
    client,
    RESOURCE_PATHS.agentActivity,
    decodeAgentActivity,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  const [selectedRole, setSelectedRole] = useState<AgentRole>("orchestrator");
  const selected = agents.result.data?.find((agent) => agent.role === selectedRole) ?? null;
  const promptIdentity = selectAgentPromptIdentity(selected);

  const records = agents.result.data ?? [];
  const activities = activity.result.data ?? [];
  const totals = useMemo(() => ({
    executions: records.reduce((sum, agent) => sum + agent.execution_count, 0),
    running: records.reduce((sum, agent) => sum + agent.running_count, 0),
    cost: records.reduce((sum, agent) => sum + (agent.measured_cost ?? 0), 0),
    observedTokens: records.reduce(
      (sum, agent) =>
        sum
        + (agent.input_tokens ?? 0)
        + (agent.output_tokens ?? 0)
        + (agent.reasoning_tokens ?? 0),
      0,
    ),
    physicalCalls: records.reduce((sum, agent) => sum + agent.physical_call_count, 0),
    unresolvedUsdExposure: records.reduce(
      (sum, agent) => sum + agent.provider_budget.role_unresolved_usd_exposure,
      0,
    ),
    unresolvedPhysicalCalls: records.reduce(
      (sum, agent) => sum + agent.provider_budget.role_unresolved_physical_calls,
      0,
    ),
    incompleteCallCounts: records.filter(
      (agent) => agent.physical_call_count_state === "lower_bound",
    ).length,
    tokenObservations: records.reduce((sum, agent) => sum + agent.token_observation_count, 0),
    incompleteAccounting: records.filter(
      (agent) => ["partial", "unavailable"].includes(agent.accounting_status),
    ).length,
  }), [records]);
  const selectedActivity = activities.filter((row) => row.agent_role === selectedRole);
  const canConfigure = principal.organization_permissions.includes(PERMISSIONS.configManage);
  const hostedSetAvailable = records.some(
    (agent) =>
      agent.staged_assignment !== null
      || agent.active_assignment.execution_mode === "hosted_advisory",
  );

  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Agent operations"
        eyebrow="MULTI-AGENT CONTROL"
        detail="Four separated roles coordinate through typed handoffs. Every invocation below comes from the durable execution ledger."
      />
      <ResourceView result={agents.result} emptyLabel="No agent role definitions are available.">
        {() => (
          <MetricStrip label="Agent execution summary" values={[
            { label: "Role boundaries", value: `${records.length}/4`, note: "Orchestrator · Red Team · Judge · Documentation" },
            { label: "Real executions", value: count(totals.executions), note: `${totals.running} currently running` },
            {
              label: "Known agent cost",
              value: totals.incompleteAccounting > 0 ? `${money(totals.cost)} known` : money(totals.cost),
              note: totals.incompleteAccounting > 0
                ? `${totals.incompleteAccounting} role(s) have incomplete provider accounting`
                : totals.unresolvedUsdExposure > 0 || totals.unresolvedPhysicalCalls > 0
                  ? `${money(totals.unresolvedUsdExposure)} and ${count(totals.unresolvedPhysicalCalls)} call(s) unresolved`
                : totals.incompleteCallCounts > 0
                  ? `${totals.physicalCalls} provider call(s) known · historical count incomplete`
                  : `${totals.physicalCalls} provider call(s) with complete accounting`,
            },
            {
              label: "Token observations",
              value: count(totals.observedTokens),
              note: totals.tokenObservations > 0
                ? `${totals.tokenObservations} hosted observations · ${totals.physicalCalls} provider calls${totals.incompleteCallCounts > 0 ? " known (lower bound)" : ""}`
                : "No hosted provider token observations yet",
            },
          ]} />
        )}
      </ResourceView>

      <Panel title="Role boundaries" meta="select a role to inspect" eyebrow="LIVE ROLE REGISTRY">
        <ResourceView result={agents.result} emptyLabel="No agent role definitions are available.">
          {(data) => (
            <div className="agent-flow" role="list" aria-label="Independent agent role boundaries">
              {roleDisplayOrder.map((role) => {
                const agent = data.find((row) => row.role === role);
                if (!agent) return null;
                const state = agent.running_count > 0
                  ? "running"
                  : agent.failed_count > 0 && agent.last_status === "failed"
                    ? "failed"
                    : "ready";
                return (
                  <div className="agent-flow-step" key={role}>
                    <button
                      type="button"
                      className={`agent-node state-${state} ${selectedRole === role ? "selected" : ""}`}
                      onClick={() => setSelectedRole(role)}
                      aria-pressed={selectedRole === role}
                    >
                      <span className="agent-node-head">
                        <i />
                        <strong>{agent.display_name}</strong>
                        <small className="mono">{state}</small>
                      </span>
                      <span>
                        {agent.latest_acceptance_execution
                          ? `${agent.latest_acceptance_execution.returned_model} · acceptance exercised`
                          : `${agent.active_assignment.model} · configured`}
                      </span>
                      <small>{count(agent.execution_count)} executions · {agent.trust_level}</small>
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </ResourceView>
        <p className="data-note">
          This registry layout is not execution order. Birdseye derives actual parent-linked activity
          from the execution ledger. The Red Team can propose only authorized corpus work; the Judge
          cannot generate attacks; Documentation remains draft-only.
        </p>
      </Panel>

      <div className="panel-grid agent-detail-grid">
        <Panel
          title={selected?.display_name ?? "Agent detail"}
          meta={selected?.active_assignment.activation_state ?? agents.result.state}
          eyebrow="ROLE BOUNDARY"
        >
          {selected ? (
            <>
              <p className="agent-responsibility">{selected.responsibility}</p>
              <TagMatrix groups={[
                { label: "Trust level", values: [selected.trust_level] },
                { label: "Target access", values: [selected.target_access] },
                { label: "Input contract", values: [selected.input_contract] },
                { label: "Output contract", values: [selected.output_contract] },
              ]} />
              <dl className="agent-ledger-summary">
                <div><dt>Active configured model</dt><dd className="mono">{selected.active_assignment.model}</dd></div>
                <div><dt>Active configured provider</dt><dd className="mono">{selected.active_assignment.provider}</dd></div>
                <div><dt>Active assignment served model</dt><dd className="mono">{selected.active_assignment.resolved_model ?? "unavailable — no campaign execution recorded"}</dd></div>
                <div><dt>Active assignment served upstream</dt><dd className="mono">{selected.active_assignment.upstream_provider ?? "unavailable — no campaign execution recorded"}</dd></div>
                <div><dt>Prompt version</dt><dd className="mono">{selected.active_assignment.prompt_version ?? "not applicable"}</dd></div>
                <div><dt>Prompt SHA-256</dt><dd className="mono">{selected.active_assignment.prompt_sha256 ?? "not applicable"}</dd></div>
                <div><dt>Role-history p50 / p95 latency</dt><dd className="mono">{selected.p50_duration_ms === null || selected.p95_duration_ms === null ? "not yet executed" : `${selected.p50_duration_ms.toFixed(1)} / ${selected.p95_duration_ms.toFixed(1)} ms`}</dd></div>
                <div><dt>Role-history cost</dt><dd className="mono">{accountingValue(selected)}</dd></div>
                <div><dt>Input / output / reasoning tokens</dt><dd className="mono">{selected.token_observation_count > 0 ? `${count(selected.input_tokens ?? 0)} / ${count(selected.output_tokens ?? 0)} / ${count(selected.reasoning_tokens ?? 0)} · ${selected.token_observation_count} observation(s)` : "not reported"}</dd></div>
                <div><dt>Provider calls</dt><dd className="mono">{physicalCallValue(selected)}</dd></div>
                <div><dt>Langfuse delivery</dt><dd className="mono">{langfuseDelivery(selected)}</dd></div>
                <div><dt>Last Langfuse query-back</dt><dd className="mono">{selected.last_langfuse_verified_at ? time(selected.last_langfuse_verified_at) : "not yet observed remotely"}</dd></div>
                <div><dt>Last activity</dt><dd className="mono">{selected.last_activity_at ? time(selected.last_activity_at) : "not yet executed"}</dd></div>
              </dl>
              <div className="evidence-stack">
                <p className="field-label">Provider budget guard</p>
                {selected.provider_budget.status === "unavailable" ? (
                  <StateNotice
                    state="unavailable"
                    detail="No authorized hosted subcap is active or staged for this role."
                  />
                ) : (
                  <dl className="agent-ledger-summary">
                    <div><dt>Budget state</dt><dd className="mono">{selected.provider_budget.status.replaceAll("_", " ")}</dd></div>
                    <div><dt>Role known spend</dt><dd className="mono">{money(selected.provider_budget.role_usd_spent)}</dd></div>
                    <div><dt>Role unresolved USD exposure</dt><dd className="mono">{money(selected.provider_budget.role_unresolved_usd_exposure)}</dd></div>
                    <div><dt>Role USD remaining</dt><dd className="mono">{budgetRemainingValue(selected.provider_budget.role_usd_remaining, selected.provider_budget.role_usd_remaining_upper_bound, selected.provider_budget.role_usd_cap)}</dd></div>
                    <div><dt>Role unresolved provider calls</dt><dd className="mono">{count(selected.provider_budget.role_unresolved_physical_calls)}</dd></div>
                    <div><dt>Role calls remaining</dt><dd className="mono">{callRemainingValue(selected.provider_budget.role_call_count_state, selected.provider_budget.role_calls_remaining, selected.provider_budget.role_physical_calls, selected.provider_budget.role_call_cap)}</dd></div>
                    <div><dt>Global known spend</dt><dd className="mono">{money(selected.provider_budget.global_usd_spent)}</dd></div>
                    <div><dt>Global unresolved USD exposure</dt><dd className="mono">{money(selected.provider_budget.global_unresolved_usd_exposure)}</dd></div>
                    <div><dt>Global USD remaining</dt><dd className="mono">{budgetRemainingValue(selected.provider_budget.global_usd_remaining, selected.provider_budget.global_usd_remaining_upper_bound, selected.provider_budget.global_usd_cap)}</dd></div>
                    <div><dt>Global unresolved provider calls</dt><dd className="mono">{count(selected.provider_budget.global_unresolved_physical_calls)}</dd></div>
                    <div><dt>Global calls remaining</dt><dd className="mono">{callRemainingValue(selected.provider_budget.global_call_count_state, selected.provider_budget.global_calls_remaining, selected.provider_budget.global_physical_calls, selected.provider_budget.global_call_cap)}</dd></div>
                  </dl>
                )}
              </div>
              {selected.latest_acceptance_execution && (
                <div className="evidence-stack">
                  <p className="field-label">Latest target-free agent acceptance</p>
                  <StateNotice
                    state={selected.latest_acceptance_execution.langfuse_status === "exported"
                      ? "ready"
                      : "degraded"}
                    detail="Live provider evidence from the bounded agent-only acceptance authority. It does not activate this assignment for campaign execution."
                  />
                  <dl className="agent-ledger-summary">
                    <div><dt>Acceptance-served model</dt><dd className="mono">{selected.latest_acceptance_execution.returned_model}</dd></div>
                    <div><dt>Acceptance-served upstream</dt><dd className="mono">{selected.latest_acceptance_execution.upstream_provider}</dd></div>
                    <div><dt>Acceptance run</dt><dd className="mono">{selected.latest_acceptance_execution.acceptance_run_id}</dd></div>
                    <div><dt>Acceptance attempt</dt><dd className="mono">{selected.latest_acceptance_execution.acceptance_attempt_id}</dd></div>
                    <div><dt>Execution</dt><dd className="mono">{selected.latest_acceptance_execution.execution_id}</dd></div>
                    <div><dt>Parent execution</dt><dd className="mono">{selected.latest_acceptance_execution.parent_execution_id ?? "root planner call"}</dd></div>
                    <div><dt>Langfuse trace</dt><dd className="mono">{selected.latest_acceptance_execution.trace_id}</dd></div>
                    <div><dt>Langfuse query-back</dt><dd className="mono">{selected.latest_acceptance_execution.langfuse_verified_at ? `observed · ${time(selected.latest_acceptance_execution.langfuse_verified_at)}` : "awaiting remote verification"}</dd></div>
                    <div><dt>Measured provider cost</dt><dd className="mono">{money(selected.latest_acceptance_execution.measured_cost)}</dd></div>
                    <div><dt>Canonical provider events</dt><dd className="mono">{count(selected.latest_acceptance_execution.provider_event_ids.length)}</dd></div>
                    <div><dt>Input / output / reasoning tokens</dt><dd className="mono">{count(selected.latest_acceptance_execution.input_tokens)} / {count(selected.latest_acceptance_execution.output_tokens)} / {count(selected.latest_acceptance_execution.reasoning_tokens)}</dd></div>
                    <div><dt>Completed</dt><dd className="mono">{time(selected.latest_acceptance_execution.finished_at)}</dd></div>
                  </dl>
                </div>
              )}
              {selected.judge_calibration && (
                <div className="evidence-stack">
                  <p className="field-label">Evaluator calibration and authority</p>
                  <StateNotice
                    state={selected.judge_calibration.decision_authority === "model"
                      ? "ready"
                      : selected.judge_calibration.oracle_comparison_count > 0
                        ? "degraded"
                        : "empty"}
                    detail={`${selected.judge_calibration.status_label} · calibration ${selected.judge_calibration.state} · ${selected.judge_calibration.decision_authority} decisive`}
                  />
                  <dl className="agent-ledger-summary">
                    <div><dt>LLM / oracle agreement</dt><dd className="mono">{selected.judge_calibration.oracle_agreement_rate === null ? "not yet measured" : `${percent(selected.judge_calibration.oracle_agreement_rate)} · ${selected.judge_calibration.oracle_agreement_count}/${selected.judge_calibration.oracle_comparison_count}`}</dd></div>
                    <div><dt>Calibration artifact</dt><dd className="mono">{selected.judge_calibration.calibration_id ?? "unavailable"}</dd></div>
                  </dl>
                </div>
              )}
              {selected.staged_assignment && (
                <>
                  <StateNotice
                    state="degraded"
                    detail={`Staged ${selected.staged_assignment.provider} configuration; it has not been activated by an exact campaign authorization.`}
                  />
                  <dl className="agent-ledger-summary">
                    <div><dt>Staged configured model</dt><dd className="mono">{selected.staged_assignment.model}</dd></div>
                    <div><dt>Staged configured provider</dt><dd className="mono">{selected.staged_assignment.provider}</dd></div>
                    <div><dt>Provider-served model</dt><dd className="mono">{selected.staged_assignment.resolved_model ?? "unavailable — staged assignment not executed"}</dd></div>
                    <div><dt>Provider-served upstream</dt><dd className="mono">{selected.staged_assignment.upstream_provider ?? "unavailable — staged assignment not executed"}</dd></div>
                    <div><dt>Staged prompt version</dt><dd className="mono">{selected.staged_assignment.prompt_version ?? "unavailable"}</dd></div>
                    <div><dt>Staged prompt SHA-256</dt><dd className="mono">{selected.staged_assignment.prompt_sha256 ?? "unavailable"}</dd></div>
                  </dl>
                </>
              )}
            </>
          ) : (
            <ResourceView result={agents.result} emptyLabel="No agent definition was returned.">
              {() => null}
            </ResourceView>
          )}
        </Panel>

        <Panel title="Hosted role assignment" meta={selectedRole} eyebrow="ATOMIC FOUR-ROLE CONFIGURATION">
          <StateNotice
            state={hostedSetAvailable ? "ready" : "degraded"}
            detail={hostedSetAvailable
              ? "All four runtime roles are staged as one server-owned LLM-backed configuration set. Exact target and corpus authorization activates the complete set."
              : "No atomic four-role LLM configuration is staged. Campaign authorization and launch remain unavailable until the protected configuration flow supplies all four roles."}
          />
          <div className="command-row">
            <button
              type="button"
              className="button button-primary"
              disabled={!hostedSetAvailable}
              title={hostedSetAvailable
                ? undefined
                : "A server-owned atomic four-role set must be staged first"}
              onClick={() => navigateTo({ screen: "targets", entityId: null })}
            >
              Open four-role authorization
            </button>
          </div>
          <p className="data-note">
            There is no per-role or deterministic fallback. The Orchestrator, Red Team, Judge,
            and Documentation roles are all LLM-backed and become active together only through
            exact target/corpus authorization and distinct human approval. The browser cannot
            select role models, provider credentials, or partial hosted authority.
          </p>
        </Panel>
      </div>

      {canConfigure && promptIdentity ? (
        <AgentPromptPanel
          client={client}
          role={selectedRole}
          version={promptIdentity.version}
          sha256={promptIdentity.sha256}
          configurationSha256={promptIdentity.configurationSha256}
          source={promptIdentity.source}
        />
      ) : canConfigure ? (
        <Panel title="System prompt" meta="CONFIG_MANAGE only" eyebrow="SERVER-OWNED PROMPT">
          <StateNotice
            state="unavailable"
            detail="No exact configuration-bound prompt identity is active or staged for this role."
          />
        </Panel>
      ) : null}

      <Panel
        title={`${selected?.display_name ?? selectedRole} activity`}
        meta={`${selectedActivity.length} linked invocations`}
        eyebrow="REAL EXECUTION LEDGER"
      >
        {selectedActivity.length > 0 ? (
          <Timeline rows={selectedActivity.slice(0, 30).map((row) => ({
            id: row.execution_id,
            title: `${row.agent_role.replace("_", " ")} · ${row.status}`,
            detail: `${shortId(row.campaign_run_id)} · ${servedModel(row)} · ${row.duration_ms === null ? "running" : `${row.duration_ms.toFixed(1)} ms`} · ${activityAccountingValue(row)} · ${langfuseDeliveryState(row)}${row.agent_role === "judge" ? ` · calibration ${row.judge_calibration_state ?? "unavailable"} · ${row.decision_authority ?? "no"} authority` : ""}`,
            at: row.started_at,
            tone: statusTone(row.status),
          }))} />
        ) : (
          <ResourceView result={activity.result} emptyLabel="This role has not executed yet.">
            {() => <StateNotice state="empty" detail="This role has not executed yet." />}
          </ResourceView>
        )}
      </Panel>

      <Panel title="All agent handoffs" meta="hashes, traces and parent links" eyebrow="OBSERVABILITY">
        <ResourceView result={activity.result} emptyLabel="No agent activity has been recorded.">
          {(data) => (
            <RecordTable
              data={data.map((row) => ({
                ...row,
                measured_cost_display: activityAccountingValue(row),
                served_model_display: servedModel(row),
                provider_lineage_display: activityProviderLineageValue(row),
                langfuse_status: langfuseDeliveryState(row),
              }))}
              identityKeys={["execution_id"]}
              columns={[
                { key: "started_at", label: "Started", mono: true, timestamp: true },
                { key: "agent_role", label: "Role" },
                { key: "status", label: "Status" },
                { key: "campaign_run_id", label: "Campaign", mono: true },
                { key: "attempt_id", label: "Attempt", mono: true },
                { key: "parent_execution_id", label: "Parent", mono: true },
                { key: "model", label: "Engine", mono: true },
                { key: "served_model_display", label: "Requested → served", mono: true },
                { key: "provider_event_status", label: "Provider event", mono: true },
                { key: "upstream_provider", label: "Upstream", mono: true },
                { key: "duration_ms", label: "Latency ms", mono: true },
                { key: "input_tokens", label: "Input tokens", mono: true },
                { key: "output_tokens", label: "Output tokens", mono: true },
                { key: "reasoning_tokens", label: "Reasoning tokens", mono: true },
                { key: "physical_attempts", label: "Provider calls", mono: true },
                { key: "provider_lineage_display", label: "Provider lineage" },
                { key: "accounting_status", label: "Accounting" },
                { key: "measured_cost_display", label: "Cost USD", mono: true },
                { key: "trace_id", label: "Trace", mono: true },
                { key: "judge_calibration_state", label: "Calibration" },
                { key: "oracle_agreement", label: "Oracle agreement", mono: true },
                { key: "decision_authority", label: "Authority" },
                { key: "langfuse_status", label: "Langfuse", mono: true },
                { key: "langfuse_verified_at", label: "Verified at", mono: true, timestamp: true },
              ]}
            />
          )}
        </ResourceView>
      </Panel>
    </div>
  );
}

const applicabilityOrder: ToolScopeReadModel["applicability"][] = [
  "in_campaign",
  "companion_scan",
  "platform_assurance",
  "adapter_available",
  "not_applicable",
];

export function ToolingScreen({ client }: { client: ApiClient }) {
  const tooling = useResource<ToolScopeReadModel[]>(client, RESOURCE_PATHS.tooling, decodeTooling);
  const records = tooling.result.data ?? [];
  const scopes = [...new Set(records.map((row) => `${row.target_id}/${row.surface_id}`))];
  const [scope, setScope] = useState("");
  const effectiveScope = scope || scopes[0] || "";
  const scoped = records.filter((row) => `${row.target_id}/${row.surface_id}` === effectiveScope);
  const executable = scoped.filter((row) => row.applicability !== "not_applicable");
  const evidenced = scoped.filter((row) => row.runtime_state === "evidenced");
  const errors = scoped.filter((row) => row.runtime_state === "error");
  const candidates = scoped.reduce((sum, row) => sum + row.reviewed_candidate_count, 0);
  const findings = scoped.reduce((sum, row) => sum + row.recorded_finding_count, 0);

  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Security tooling"
        eyebrow="TARGET-SCOPE PLANNER"
        detail="Every capability is mapped to the selected target surface. Adapter availability and real execution evidence remain visibly distinct."
      />
      {scopes.length > 1 && (
        <label className="form-field scope-picker">
          Configured target surface
          <select value={effectiveScope} onChange={(event) => setScope(event.target.value)}>
            {scopes.map((item) => <option key={item}>{item}</option>)}
          </select>
        </label>
      )}
      <MetricStrip label="Tool execution summary" values={[
        { label: "Applicable engines", value: `${executable.length}/${scoped.length}`, note: effectiveScope || "No configured surface" },
        { label: "Runtime evidence", value: `${evidenced.length}/${scoped.length}`, note: errors.length > 0 ? `${errors.length} engine(s) currently in error` : "No current tool errors" },
        { label: "Reviewed candidates", value: count(candidates), note: "Pinned into the authorized full-scan corpus" },
        { label: "Normalized findings", value: count(findings), note: "Publication remains human-gated" },
      ]} />

      <Panel title="Capability plan" meta={effectiveScope || tooling.result.state} eyebrow="SCOPE-AWARE EXECUTION">
        <ResourceView result={tooling.result} emptyLabel="No configured target surfaces are available.">
          {() => (
            <div className="tool-scope-grid">
              {applicabilityOrder.flatMap((applicability) =>
                scoped
                  .filter((row) => row.applicability === applicability)
                  .map((row) => (
                    <article className={`tool-scope-card scope-${row.applicability}`} key={`${row.tool_id}:${row.surface_id}`}>
                      <header>
                        <div>
                          <p className="eyebrow">{row.kind.replace("-", " ")}</p>
                          <h3>{row.name}</h3>
                        </div>
                        <span className="mono">{row.applicability.replaceAll("_", " ")}</span>
                      </header>
                      <p>{row.scope_reason}</p>
                      <dl>
                        <div><dt>Mode</dt><dd>{row.execution_mode}</dd></div>
                        <div><dt>Target access</dt><dd className="mono">{row.target_access}</dd></div>
                        <div><dt>Runtime state</dt><dd className="mono">{row.runtime_state}</dd></div>
                        <div><dt>Reviewed cases</dt><dd className="mono">{row.reviewed_candidate_count}</dd></div>
                        <div><dt>Executed attempts</dt><dd className="mono">{row.executed_attempt_count}</dd></div>
                        <div><dt>Scan runs</dt><dd className="mono">{row.recorded_scan_count}</dd></div>
                        <div><dt>Evidenced findings</dt><dd className="mono">{row.evidenced_finding_count}</dd></div>
                        <div><dt>Last error</dt><dd className="mono">{row.last_error_code ?? "none observed"}</dd></div>
                      </dl>
                      <TagMatrix groups={[
                        { label: "Capabilities", values: row.capabilities },
                        { label: "OWASP LLM", values: row.owasp_llm },
                        { label: "OWASP Web", values: row.owasp_web },
                        {
                          label: "Authorization",
                          values: [row.requires_separate_authorization ? "separate authorization required" : "inherits exact campaign scope"],
                        },
                      ]} />
                      <small className="mono">
                        {row.last_executed_at ? `last evidence ${time(row.last_executed_at)}` : "no execution evidence for this organization"}
                      </small>
                    </article>
                  )),
              )}
            </div>
          )}
        </ResourceView>
      </Panel>

      <Panel title="Genuine execution compatibility" meta="configured scope + persisted evidence" eyebrow="TOOL LEDGER">
        {scoped.length > 0 ? (
          <RecordTable
            data={scoped}
            identityKeys={["tool_id", "target_id", "surface_id"]}
            columns={[
              { key: "name", label: "Tool" },
              { key: "applicability", label: "Use on scope" },
              { key: "execution_mode", label: "Execution path" },
              { key: "runtime_state", label: "Runtime state" },
              { key: "reviewed_candidate_count", label: "Candidates", mono: true },
              { key: "executed_attempt_count", label: "Attempts", mono: true },
              { key: "recorded_scan_count", label: "Scans", mono: true },
              { key: "evidenced_finding_count", label: "Evidenced findings", mono: true },
              { key: "last_error_code", label: "Last error", mono: true },
              { key: "last_executed_at", label: "Last evidence", mono: true, timestamp: true },
            ]}
          />
        ) : (
          <ResourceView result={tooling.result} emptyLabel="No configured target surfaces are available.">
            {() => null}
          </ResourceView>
        )}
      </Panel>
    </div>
  );
}
