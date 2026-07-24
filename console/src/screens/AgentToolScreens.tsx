import { useEffect, useMemo, useState } from "react";

import type { ApiClient } from "../api/client";
import type { Principal } from "../api/contracts";
import { COMMAND_PATHS, RESOURCE_PATHS } from "../api/paths";
import {
  decodeAgentActivity,
  decodeAgentPrompt,
  decodeAgents,
  decodeTooling,
} from "../api/read-models";
import { AdversarialText } from "../components/AdversarialText";
import { AgentBudgetSummary } from "../components/AgentBudgetSummary";
import {
  count,
  MetricStrip,
  money,
  Panel,
  percent,
  ScreenHeading,
  shortId,
  TagMatrix,
  time,
  Timeline,
} from "../components/Analytics";
import { CommandButton } from "../components/CommandButton";
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

const deterministicModels: Record<AgentRole, string[]> = {
  orchestrator: ["coverage-governor-v1"],
  red_team: ["full-scan-corpus-v1", "corpus-replay-v1"],
  judge: ["oracle-precedence-v1"],
  documentation: ["evidence-report-v1", "concise-evidence-report-v1"],
};

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
  if (agent.accounting_status === "unavailable") return "unavailable";
  if (agent.accounting_status === "partial") return `${money(agent.measured_cost)} known · partial`;
  return money(agent.measured_cost);
};

const activityAccountingValue = (activity: AgentActivityReadModel) =>
  activity.accounting_status === "unavailable"
    ? "unavailable"
    : money(activity.measured_cost);

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
  const [executionMode, setExecutionMode] = useState<"deterministic" | "hosted_advisory">(
    "deterministic",
  );
  const [provider, setProvider] = useState("headshot");
  const [model, setModel] = useState(deterministicModels.orchestrator[0]);
  const [rationale, setRationale] = useState("");
  const selectedAssignment = selected?.active_assignment;
  const promptIdentity = selectAgentPromptIdentity(selected);

  useEffect(() => {
    if (!selectedAssignment) return;
    setExecutionMode(selectedAssignment.execution_mode);
    setProvider(selectedAssignment.provider);
    setModel(selectedAssignment.model);
    setRationale("");
  }, [
    selectedRole,
    selectedAssignment?.execution_mode,
    selectedAssignment?.provider,
    selectedAssignment?.model,
  ]);

  const records = agents.result.data ?? [];
  const activities = activity.result.data ?? [];
  const totals = useMemo(() => ({
    executions: records.reduce((sum, agent) => sum + agent.execution_count, 0),
    running: records.reduce((sum, agent) => sum + agent.running_count, 0),
    cost: records.reduce((sum, agent) => sum + agent.measured_cost, 0),
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
  const normalizedRationale = rationale.trim();
  const deterministicActivationReady =
    canConfigure
    && executionMode === "deterministic"
    && provider === "headshot"
    && deterministicModels[selectedRole].includes(model)
    && normalizedRationale.length > 0
    && normalizedRationale.length <= 2_000;

  const changeMode = (value: "deterministic" | "hosted_advisory") => {
    setExecutionMode(value);
    if (value === "deterministic") {
      setProvider("headshot");
      setModel(deterministicModels[selectedRole][0]);
    } else {
      setProvider("openrouter");
      setModel("");
    }
  };

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
                  : `${totals.physicalCalls} provider call(s) with complete accounting`,
            },
            {
              label: "Token observations",
              value: count(totals.observedTokens),
              note: totals.tokenObservations > 0
                ? `${totals.tokenObservations} hosted observations · ${totals.physicalCalls} provider calls`
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
                      <span>{agent.active_assignment.model} · configured</span>
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
                <div><dt>Configured model</dt><dd className="mono">{selected.active_assignment.model}</dd></div>
                <div><dt>Configured provider</dt><dd className="mono">{selected.active_assignment.provider}</dd></div>
                <div><dt>Provider-served model</dt><dd className="mono">{selected.active_assignment.resolved_model ?? "unavailable — not durably recorded"}</dd></div>
                <div><dt>Provider-served upstream</dt><dd className="mono">{selected.active_assignment.upstream_provider ?? "unavailable — not durably recorded"}</dd></div>
                <div><dt>Prompt version</dt><dd className="mono">{selected.active_assignment.prompt_version ?? "not applicable"}</dd></div>
                <div><dt>Prompt SHA-256</dt><dd className="mono">{selected.active_assignment.prompt_sha256 ?? "not applicable"}</dd></div>
                <div><dt>Role-history p50 / p95 latency</dt><dd className="mono">{selected.p50_duration_ms === null || selected.p95_duration_ms === null ? "not yet executed" : `${selected.p50_duration_ms.toFixed(1)} / ${selected.p95_duration_ms.toFixed(1)} ms`}</dd></div>
                <div><dt>Role-history cost</dt><dd className="mono">{accountingValue(selected)}</dd></div>
                <div><dt>Input / output / reasoning tokens</dt><dd className="mono">{selected.token_observation_count > 0 ? `${count(selected.input_tokens ?? 0)} / ${count(selected.output_tokens ?? 0)} / ${count(selected.reasoning_tokens ?? 0)} · ${selected.token_observation_count} observation(s)` : "not reported"}</dd></div>
                <div><dt>Provider calls</dt><dd className="mono">{count(selected.physical_call_count)}</dd></div>
                <div><dt>Langfuse delivery</dt><dd className="mono">{langfuseDelivery(selected)}</dd></div>
                <div><dt>Last Langfuse query-back</dt><dd className="mono">{selected.last_langfuse_verified_at ? time(selected.last_langfuse_verified_at) : "not yet observed remotely"}</dd></div>
                <div><dt>Last activity</dt><dd className="mono">{selected.last_activity_at ? time(selected.last_activity_at) : "not yet executed"}</dd></div>
              </dl>
              <AgentBudgetSummary budget={selected.provider_budget} />
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

        <Panel title="Engine assignment" meta={selectedRole} eyebrow="CONTROLLED CONFIGURATION">
          <label className="form-field">
            Execution mode
            <select
              value={executionMode}
              disabled={!canConfigure}
              onChange={(event) => changeMode(event.target.value as "deterministic" | "hosted_advisory")}
            >
              <option value="deterministic">Server-owned deterministic engine</option>
              {executionMode === "hosted_advisory" && (
                <option value="hosted_advisory" disabled>
                  Hosted role assignment · managed as an atomic four-role set
                </option>
              )}
            </select>
          </label>
          <label className="form-field">
            Configured provider
            <select
              value={provider}
              disabled
              onChange={(event) => setProvider(event.target.value)}
            >
              {executionMode === "deterministic"
                ? <option value="headshot">Headshot</option>
                : <>
                    <option value="openrouter">OpenRouter</option>
                    <option value="together">Together</option>
                    <option value="anthropic">Anthropic</option>
                  </>}
            </select>
          </label>
          <label className="form-field">
            Configured model / engine
            {executionMode === "deterministic" ? (
              <select
                disabled={!canConfigure}
                value={model}
                onChange={(event) => setModel(event.target.value)}
              >
                {deterministicModels[selectedRole].map((item) => <option key={item}>{item}</option>)}
              </select>
            ) : (
              <input
                value={model}
                disabled
                onChange={(event) => setModel(event.target.value)}
                placeholder="Configured provider model identifier"
                autoComplete="off"
              />
            )}
          </label>
          <label className="form-field">
            Rationale
            <textarea
              value={rationale}
              disabled={!canConfigure || executionMode !== "deterministic"}
              maxLength={2000}
              onChange={(event) => setRationale(event.target.value)}
              placeholder="Required audit rationale for restoring this server-owned engine"
            />
          </label>
          <div className="command-row">
            <CommandButton
              client={client}
              path={COMMAND_PATHS.configureAgent(selectedRole)}
              payload={{
                provider,
                model: model.trim(),
                execution_mode: executionMode,
                rationale: normalizedRationale,
              }}
              label="Activate deterministic role engine"
              allowed={deterministicActivationReady}
              unavailableReason={!canConfigure
                ? PERMISSIONS.configManage
                : executionMode !== "deterministic"
                  ? "selecting the server-owned deterministic engine first"
                  : normalizedRationale.length === 0
                    ? "an audit rationale"
                    : "a server-owned engine for this role"}
              onAcknowledged={() => {
                setRationale("");
                agents.refresh();
              }}
            />
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
            This per-role control can only restore a reviewed, server-owned deterministic engine.
            A staged hosted set becomes active only through the exact target/corpus authorization
            on Targets and a distinct human approval. The browser cannot select role models,
            provider credentials, or partial hosted authority.
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
            detail: `${shortId(row.campaign_run_id)} · ${row.returned_model ?? row.model} · ${row.duration_ms === null ? "running" : `${row.duration_ms.toFixed(1)} ms`} · ${activityAccountingValue(row)} · ${langfuseDeliveryState(row)}${row.agent_role === "judge" ? ` · calibration ${row.judge_calibration_state ?? "unavailable"} · ${row.decision_authority ?? "no"} authority` : ""}`,
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
                { key: "returned_model", label: "Served model", mono: true },
                { key: "upstream_provider", label: "Upstream", mono: true },
                { key: "duration_ms", label: "Latency ms", mono: true },
                { key: "input_tokens", label: "Input tokens", mono: true },
                { key: "output_tokens", label: "Output tokens", mono: true },
                { key: "reasoning_tokens", label: "Reasoning tokens", mono: true },
                { key: "physical_attempts", label: "Provider calls", mono: true },
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
