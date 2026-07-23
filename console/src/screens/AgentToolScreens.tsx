import { useEffect, useMemo, useState } from "react";

import type { ApiClient } from "../api/client";
import type { Principal } from "../api/contracts";
import { COMMAND_PATHS, RESOURCE_PATHS } from "../api/paths";
import {
  decodeAgentActivity,
  decodeAgents,
  decodeTooling,
} from "../api/read-models";
import {
  count,
  MetricStrip,
  money,
  Panel,
  ScreenHeading,
  shortId,
  TagMatrix,
  time,
  Timeline,
} from "../components/Analytics";
import { CommandButton } from "../components/CommandButton";
import { RecordTable, ResourceView, StateNotice } from "../components/ResourceView";
import { useResource } from "../hooks/useResource";
import {
  PERMISSIONS,
  type AgentActivityReadModel,
  type AgentReadModel,
  type ToolScopeReadModel,
} from "../types";

type AgentRole = AgentReadModel["role"];

const roleDisplayOrder: AgentRole[] = ["orchestrator", "red_team", "judge", "documentation"];

const deterministicModels: Record<AgentRole, string[]> = {
  orchestrator: ["coverage-governor-v1"],
  red_team: ["full-scan-corpus-v1", "corpus-replay-v1"],
  judge: ["oracle-precedence-v1"],
  documentation: ["evidence-report-v1", "concise-evidence-report-v1"],
};

const statusTone = (status: string): "success" | "failure" | "queued" =>
  status === "failed" ? "failure" : status === "running" ? "queued" : "success";

export function AgentsScreen({
  client,
  principal,
}: {
  client: ApiClient;
  principal: Principal;
}) {
  const agents = useResource<AgentReadModel[]>(client, RESOURCE_PATHS.agents, decodeAgents);
  const activity = useResource<AgentActivityReadModel[]>(
    client,
    RESOURCE_PATHS.agentActivity,
    decodeAgentActivity,
  );
  const [selectedRole, setSelectedRole] = useState<AgentRole>("orchestrator");
  const selected = agents.result.data?.find((agent) => agent.role === selectedRole) ?? null;
  const [executionMode, setExecutionMode] = useState<"deterministic" | "hosted_advisory">(
    "deterministic",
  );
  const [provider, setProvider] = useState("headshot");
  const [model, setModel] = useState(deterministicModels.orchestrator[0]);
  const [rationale, setRationale] = useState("");

  useEffect(() => {
    if (!selected) return;
    setExecutionMode(selected.active_assignment.execution_mode);
    setProvider(selected.active_assignment.provider);
    setModel(selected.active_assignment.model);
    setRationale("");
  }, [selected]);

  const records = agents.result.data ?? [];
  const activities = activity.result.data ?? [];
  const totals = useMemo(() => ({
    executions: records.reduce((sum, agent) => sum + agent.execution_count, 0),
    running: records.reduce((sum, agent) => sum + agent.running_count, 0),
    cost: records.reduce((sum, agent) => sum + agent.measured_cost, 0),
    observedTokens: records.reduce(
      (sum, agent) => sum + (agent.input_tokens ?? 0) + (agent.output_tokens ?? 0),
      0,
    ),
    tokenObservations: records.reduce((sum, agent) => sum + agent.token_observation_count, 0),
  }), [records]);
  const selectedActivity = activities.filter((row) => row.agent_role === selectedRole);
  const hostedEligible = selectedRole === "red_team" || selectedRole === "documentation";
  const canConfigure = principal.organization_permissions.includes(PERMISSIONS.configManage);
  const configurationReady = model.trim().length > 0 && rationale.trim().length > 0;

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
      <MetricStrip label="Agent execution summary" values={[
        { label: "Role boundaries", value: `${records.length}/4`, note: "Orchestrator · Red Team · Judge · Documentation" },
        { label: "Real executions", value: count(totals.executions), note: `${totals.running} currently running` },
        { label: "Measured agent cost", value: money(totals.cost), note: "Zero is valid for deterministic local engines" },
        {
          label: "Token observations",
          value: count(totals.observedTokens),
          note: totals.tokenObservations > 0
            ? `${totals.tokenObservations} hosted observations`
            : "Not reported by deterministic engines",
        },
      ]} />

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
                      <span>{agent.active_assignment.model}</span>
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
                <div><dt>Engine</dt><dd className="mono">{selected.active_assignment.provider}/{selected.active_assignment.model}</dd></div>
                <div><dt>Average latency</dt><dd className="mono">{selected.average_duration_ms === null ? "not observed" : `${selected.average_duration_ms.toFixed(1)} ms`}</dd></div>
                <div><dt>Measured cost</dt><dd className="mono">{money(selected.measured_cost)}</dd></div>
                <div><dt>Last activity</dt><dd className="mono">{selected.last_activity_at ? time(selected.last_activity_at) : "not yet executed"}</dd></div>
              </dl>
              {selected.staged_assignment && (
                <StateNotice
                  state="degraded"
                  detail={`Staged ${selected.staged_assignment.provider}/${selected.staged_assignment.model}; a new corpus authorization or calibrated drafting workflow is required before activation.`}
                />
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
              onChange={(event) => changeMode(event.target.value as "deterministic" | "hosted_advisory")}
            >
              <option value="deterministic">Deterministic production engine</option>
              {hostedEligible && <option value="hosted_advisory">Hosted advisory model (stage only)</option>}
            </select>
          </label>
          <label className="form-field">
            Provider
            <select
              value={provider}
              disabled={executionMode === "deterministic"}
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
            Model / engine
            {executionMode === "deterministic" ? (
              <select value={model} onChange={(event) => setModel(event.target.value)}>
                {deterministicModels[selectedRole].map((item) => <option key={item}>{item}</option>)}
              </select>
            ) : (
              <input
                value={model}
                onChange={(event) => setModel(event.target.value)}
                placeholder="Provider model identifier"
                autoComplete="off"
              />
            )}
          </label>
          <label className="form-field">
            Rationale
            <textarea
              value={rationale}
              onChange={(event) => setRationale(event.target.value)}
              placeholder="Why this engine is appropriate for this role"
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
                rationale: rationale.trim(),
              }}
              label={executionMode === "deterministic" ? "Activate engine" : "Stage advisory model"}
              allowed={canConfigure && configurationReady}
              unavailableReason={!canConfigure ? PERMISSIONS.configManage : "model and rationale"}
              onAcknowledged={() => agents.refresh()}
            />
          </div>
          <p className="data-note">
            Orchestrator and Judge are intentionally deterministic. Hosted Red Team or Documentation
            choices are recorded as staged and cannot alter a previously approved campaign.
          </p>
        </Panel>
      </div>

      <Panel
        title={`${selected?.display_name ?? selectedRole} activity`}
        meta={`${selectedActivity.length} linked invocations`}
        eyebrow="REAL EXECUTION LEDGER"
      >
        {selectedActivity.length > 0 ? (
          <Timeline rows={selectedActivity.slice(0, 30).map((row) => ({
            id: row.execution_id,
            title: `${row.agent_role.replace("_", " ")} · ${row.status}`,
            detail: `${shortId(row.campaign_run_id)} · ${row.model} · ${row.duration_ms === null ? "running" : `${row.duration_ms.toFixed(1)} ms`} · ${money(row.measured_cost)}`,
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
              data={data}
              identityKeys={["execution_id"]}
              columns={[
                { key: "started_at", label: "Started", mono: true },
                { key: "agent_role", label: "Role" },
                { key: "status", label: "Status" },
                { key: "campaign_run_id", label: "Campaign", mono: true },
                { key: "attempt_id", label: "Attempt", mono: true },
                { key: "parent_execution_id", label: "Parent", mono: true },
                { key: "model", label: "Engine", mono: true },
                { key: "duration_ms", label: "Latency ms", mono: true },
                { key: "measured_cost", label: "Cost USD", mono: true },
                { key: "trace_id", label: "Trace", mono: true },
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
  const executed = scoped.filter(
    (row) => row.executed_attempt_count > 0 || row.recorded_scan_count > 0,
  );
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
        { label: "Evidenced engines", value: `${executed.length}/${scoped.length}`, note: "Campaign attempts or normalized scan runs" },
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
                        <div><dt>Reviewed cases</dt><dd className="mono">{row.reviewed_candidate_count}</dd></div>
                        <div><dt>Executed attempts</dt><dd className="mono">{row.executed_attempt_count}</dd></div>
                        <div><dt>Scan runs</dt><dd className="mono">{row.recorded_scan_count}</dd></div>
                        <div><dt>Findings</dt><dd className="mono">{row.recorded_finding_count}</dd></div>
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
              { key: "reviewed_candidate_count", label: "Candidates", mono: true },
              { key: "executed_attempt_count", label: "Attempts", mono: true },
              { key: "recorded_scan_count", label: "Scans", mono: true },
              { key: "recorded_finding_count", label: "Findings", mono: true },
              { key: "last_executed_at", label: "Last evidence", mono: true },
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
