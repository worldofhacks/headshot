import { useMemo, useState } from "react";

import type { ResourceResult } from "../api/contracts";
import type { ConsoleEvent } from "../api/stream";
import type {
  BirdseyeAgentActivityReadModel,
  BirdseyeAttentionReadModel,
  BirdseyeCategoryOutcomeReadModel,
  BirdseyeNodeReadModel,
  BirdseyeSnapshotReadModel,
  BirdseyeTrustZone,
} from "../types";
import { count, money, percent, shortId, time } from "./Analytics";

const zoneOrder: BirdseyeTrustZone[] = [
  "human",
  "untrusted",
  "control",
  "execution",
  "evaluation",
  "governance",
  "data",
  "observability",
  "unclassified",
];

const zoneLabels: Record<BirdseyeTrustZone, string> = {
  human: "Operator access",
  untrusted: "Untrusted generation",
  control: "Trusted control",
  execution: "Policy-gated execution",
  evaluation: "Independent evaluation",
  governance: "Human-gated governance",
  data: "Authoritative data",
  observability: "Observability",
  unclassified: "Registered services",
};

const roleLabels: Record<BirdseyeAgentActivityReadModel["agent_role"], string> = {
  orchestrator: "Orchestrator",
  red_team: "Red Team",
  judge: "Independent Judge",
  documentation: "Documentation",
};

const age = (seconds: number | null) => {
  if (seconds === null) return "not observed";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3_600) return `${Math.round(seconds / 60)}m`;
  return `${Math.round(seconds / 3_600)}h`;
};

const latency = (value: number | null) =>
  value === null ? "Not observed" : `${value.toFixed(1)} ms`;

const humanize = (value: string) =>
  value
    .replaceAll("_", " ")
    .replaceAll(".", " · ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());

const streamLabel = (stream: ResourceResult<ConsoleEvent[]>) => {
  if (stream.state === "ready") return "Connected";
  if (stream.state === "loading") return "Connecting";
  return stream.state.replaceAll("_", " ");
};

const signedPercent = (value: number | null) => {
  if (value === null) return "Not enough versions";
  if (Math.abs(value) < 0.0001) return "No change";
  return `${value > 0 ? "+" : "−"}${percent(Math.abs(value))}`;
};

function SecurityPosture({ snapshot }: { snapshot: BirdseyeSnapshotReadModel }) {
  const posture = snapshot.security_posture;
  const coverageGaps = Math.max(0, posture.required_categories - posture.tested_categories);
  return (
    <section className="birdseye-posture" aria-label="Security outcome posture">
      <header className="birdseye-section-heading">
        <div>
          <p className="eyebrow">REQUIREMENT-LEVEL OUTCOMES</p>
          <h2>Security posture</h2>
        </div>
        <span className="mono">verified evidence only</span>
      </header>
      <div className="birdseye-posture-grid">
        <article>
          <span>Category coverage</span>
          <strong className="mono">
            {posture.tested_categories}/{posture.required_categories}
          </strong>
          <small>
            {count(posture.verified_case_count)} cases · {coverageGaps} required gaps
          </small>
        </article>
        <article>
          <span>Observed outcomes</span>
          <strong className="mono">
            {posture.observed_hold_rate === null
              ? "No decisive result"
              : `${percent(posture.observed_hold_rate)} held`}
          </strong>
          <small>
            {posture.held_count} held · {posture.exploited_count} exploited ·{" "}
            {posture.review_count} review
          </small>
        </article>
        <article className={`tone-${posture.resilience_direction}`}>
          <span>Resilience trend</span>
          <strong>{humanize(posture.resilience_direction)}</strong>
          <small>{signedPercent(posture.resilience_delta)} vs previous tested version</small>
        </article>
        <article className={posture.critical_open_finding_count > 0 ? "tone-degrading" : ""}>
          <span>Finding lifecycle</span>
          <strong className="mono">{count(posture.open_finding_count)} open</strong>
          <small>
            {posture.in_progress_finding_count} validating · {posture.resolved_finding_count}{" "}
            resolved · {posture.critical_open_finding_count} critical
          </small>
        </article>
        <article>
          <span>Cost trajectory</span>
          <strong className="mono">
            {posture.cost_per_attempt_usd === null
              ? "Not observed"
              : `${money(posture.cost_per_attempt_usd)} / attempt`}
          </strong>
          <small>
            {posture.cost_velocity_usd_per_minute === null
              ? "Velocity unavailable"
              : `${money(posture.cost_velocity_usd_per_minute)} / min`}
            {posture.projected_cost_at_attempt_cap_usd === null
              ? ""
              : ` · ${money(posture.projected_cost_at_attempt_cap_usd)} projected`}
          </small>
        </article>
      </div>
      <div className={`birdseye-priority source-${posture.priority_source}`}>
        <div>
          <span className="eyebrow">CURRENT PRIORITY SIGNAL</span>
          <strong>
            {posture.priority_category
              ? humanize(posture.priority_category)
              : "No authorized priority"}
          </strong>
        </div>
        <p>{posture.priority_reason}</p>
        <small className="mono">
          {humanize(posture.priority_source)}
          {posture.priority_at ? ` · ${time(posture.priority_at)}` : ""}
        </small>
      </div>
    </section>
  );
}

function Instrumentation({
  snapshot,
  stream,
}: {
  snapshot: BirdseyeSnapshotReadModel;
  stream: ResourceResult<ConsoleEvent[]>;
}) {
  const data = snapshot.instrumentation;
  const queueDepth = data.queue_queued + data.queue_leased;
  return (
    <section
      className="birdseye-instrumentation"
      aria-label="Operational constraints and liveness"
    >
      <div>
        <span>Authorized budget</span>
        <strong className="mono">
          {money(data.measured_cost_usd)} / {money(data.budget_usd)}
        </strong>
        <small>
          {data.budget_usd > 0 ? percent(data.budget_utilization) : "No campaign budget"}
        </small>
      </div>
      <div>
        <span>Rate ceiling</span>
        <strong className="mono">{data.requests_per_second_cap.toFixed(2)} req/s</strong>
        <small>Policy-authorized cap</small>
      </div>
      <div>
        <span>Private queue</span>
        <strong className="mono">{count(queueDepth)}</strong>
        <small>
          {data.queue_queued} queued · {data.queue_leased} leased · {data.queue_dead_letter}{" "}
          dead
        </small>
      </div>
      <div>
        <span>Judge dispositions</span>
        <strong className="mono">
          {data.confirmed_count} / {data.likely_count} / {data.review_count}
        </strong>
        <small>Confirmed · likely · review</small>
      </div>
      <div>
        <span>Runtime evidence</span>
        <strong className="mono">
          {data.healthy_components}/{data.total_components}
        </strong>
        <small>{data.system_state}</small>
      </div>
      <div>
        <span>Ordered updates</span>
        <strong className="mono">{streamLabel(stream)}</strong>
        <small>
          {"cursor" in stream && stream.cursor !== undefined
            ? `Cursor ${stream.cursor}`
            : "No cursor received"}
        </small>
      </div>
    </section>
  );
}

function CategoryOutcomes({
  outcomes,
  currentVersion,
}: {
  outcomes: BirdseyeCategoryOutcomeReadModel[];
  currentVersion: string | null;
}) {
  return (
    <section className="birdseye-category-panel">
      <header className="birdseye-section-heading">
        <div>
          <p className="eyebrow">CATEGORY × TARGET VERSION</p>
          <h2>Coverage and outcomes</h2>
        </div>
        <span className="mono">{outcomes.length} rows</span>
      </header>
      {outcomes.length === 0 ? (
        <p className="birdseye-empty">
          No hash-verified category outcomes are available for the selected target.
        </p>
      ) : (
        <div className="birdseye-outcome-table-wrap">
          <div className="birdseye-outcome-table" role="table" aria-label="Category outcomes">
            <div className="birdseye-outcome-head" role="row">
              <span role="columnheader">Version / category</span>
              <span role="columnheader">Cases</span>
              <span role="columnheader">Held</span>
              <span role="columnheader">Exploited</span>
              <span role="columnheader">Review</span>
            </div>
            {outcomes.map((row) => (
              <div
                className={row.target_version === currentVersion ? "current" : undefined}
                role="row"
                key={`${row.target_version}:${row.category}`}
              >
                <span role="cell">
                  <strong>{humanize(row.category)}</strong>
                  <small className="mono">
                    {row.target_version}
                    {row.last_evaluated_at ? ` · ${time(row.last_evaluated_at)}` : " · untested"}
                  </small>
                </span>
                <span className="mono" role="cell">
                  {row.verified_case_count}
                  <small>{row.verified_attempt_count} attempts</small>
                </span>
                <span className="mono outcome-held" role="cell">{row.held_count}</span>
                <span className="mono outcome-exploited" role="cell">{row.exploited_count}</span>
                <span className="mono outcome-review" role="cell">{row.review_count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      <p className="birdseye-footnote">
        “Held” means no exploit was observed in the recorded evidence; it is not a claim that the
        target is safe.
      </p>
    </section>
  );
}

function AgentActivity({ events }: { events: BirdseyeAgentActivityReadModel[] }) {
  return (
    <section className="birdseye-agent-sequence">
      <header className="birdseye-section-heading">
        <div>
          <p className="eyebrow">PERSISTED PARENT-LINKED EXECUTIONS</p>
          <h2>Observed agent sequence</h2>
        </div>
        <span className="mono">{events.length} events</span>
      </header>
      {events.length === 0 ? (
        <p className="birdseye-empty">
          No agent execution has been recorded for this campaign. No pipeline is inferred.
        </p>
      ) : (
        <div className="birdseye-agent-events" role="list" aria-label="Observed agent executions">
          {events.map((event, index) => {
            const evidence = [
              event.category ? humanize(event.category) : null,
              event.attempt_id ? `attempt ${shortId(event.attempt_id)}` : null,
              event.verdict_state ? humanize(event.verdict_state) : null,
              event.finding_id ? `finding ${shortId(event.finding_id)}` : null,
              event.error_code ? humanize(event.error_code) : null,
            ].filter((value): value is string => value !== null);
            return (
              <article
                className={`status-${event.status}`}
                key={event.execution_id}
                role="listitem"
              >
                <div className="birdseye-agent-index">
                  <span className="mono">{String(index + 1).padStart(2, "0")}</span>
                  {index < events.length - 1 && <i aria-hidden="true" />}
                </div>
                <div>
                  <header>
                    <div>
                      <strong>{roleLabels[event.agent_role]}</strong>
                      <span>{humanize(event.phase)}</span>
                    </div>
                    <span className={`birdseye-state state-${event.status}`}>
                      {event.status}
                    </span>
                  </header>
                  <p>{evidence.length > 0 ? evidence.join(" · ") : "Campaign-level decision"}</p>
                  <small className="mono">
                    {event.parent_execution_id
                      ? `parent ${shortId(event.parent_execution_id)} · `
                      : "root execution · "}
                    {time(event.started_at)}
                    {event.duration_ms === null ? "" : ` · ${event.duration_ms.toFixed(1)} ms`}
                  </small>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function NodeCard({
  node,
  selected,
  onSelect,
}: {
  node: BirdseyeNodeReadModel;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      className={`birdseye-node state-${node.runtime_state}${selected ? " selected" : ""}`}
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
    >
      <span className="birdseye-node-head">
        <i aria-hidden="true" />
        <strong>{node.name}</strong>
        <span className="mono">{node.runtime_state}</span>
      </span>
      <span>{node.current_task}</span>
      <small className="mono">
        {node.healthy_instances}/{node.total_instances} evidenced ·{" "}
        {node.heartbeat_at ? `activity ${age(node.freshness_seconds)} ago` : "no runtime activity"}
      </small>
    </button>
  );
}

function Topology({
  snapshot,
  selectedId,
  onSelect,
}: {
  snapshot: BirdseyeSnapshotReadModel;
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const [collapsed, setCollapsed] = useState<Set<BirdseyeTrustZone>>(() => {
    const compact =
      typeof window !== "undefined" &&
      typeof window.matchMedia === "function" &&
      window.matchMedia("(max-width: 767px)").matches;
    if (!compact) return new Set();
    return new Set(
      zoneOrder.filter(
        (zone) =>
          !snapshot.nodes.some(
            (node) => node.trust_zone === zone && node.runtime_state === "working",
          ),
      ),
    );
  });
  const zones = useMemo(
    () =>
      zoneOrder.flatMap((zone) => {
        const nodes = snapshot.nodes.filter((node) => node.trust_zone === zone);
        return nodes.length > 0 ? [{ zone, nodes }] : [];
      }),
    [snapshot.nodes],
  );
  if (zones.length === 0) {
    return (
      <p className="birdseye-empty">
        No runtime components have supplied authoritative evidence.
      </p>
    );
  }
  const toggle = (zone: BirdseyeTrustZone) =>
    setCollapsed((current) => {
      const next = new Set(current);
      if (next.has(zone)) next.delete(zone);
      else next.add(zone);
      return next;
    });
  return (
    <div className="birdseye-topology">
      {zones.map(({ zone, nodes }) => {
        const hidden = collapsed.has(zone);
        return (
          <section className={`birdseye-zone zone-${zone}`} key={zone}>
            <button
              className="birdseye-zone-heading"
              type="button"
              onClick={() => toggle(zone)}
              aria-expanded={!hidden}
            >
              <span>{zoneLabels[zone]}</span>
              <small className="mono">
                {nodes.length} registered · {hidden ? "expand" : "collapse"}
              </small>
            </button>
            {!hidden && (
              <div className="birdseye-zone-nodes">
                {nodes.map((node) => (
                  <NodeCard
                    key={node.component_id}
                    node={node}
                    selected={node.component_id === selectedId}
                    onSelect={() => onSelect(node.component_id)}
                  />
                ))}
              </div>
            )}
          </section>
        );
      })}
    </div>
  );
}

function NodeInspector({ node }: { node: BirdseyeNodeReadModel | null }) {
  if (node === null) {
    return (
      <p className="birdseye-empty">
        Select a registered component to inspect its live evidence.
      </p>
    );
  }
  return (
    <div className="birdseye-inspector">
      <header>
        <div>
          <span className="eyebrow">{zoneLabels[node.trust_zone]}</span>
          <h3>{node.name}</h3>
        </div>
        <span className={`birdseye-state state-${node.runtime_state}`}>
          {node.runtime_state}
        </span>
      </header>
      <p>{node.detail}</p>
      <dl>
        <div><dt>Registry ID</dt><dd className="mono">{node.component_id}</dd></div>
        <div><dt>Kind</dt><dd>{node.kind}</dd></div>
        <div><dt>Current task</dt><dd>{node.current_task}</dd></div>
        <div>
          <dt>Last activity / heartbeat</dt>
          <dd className="mono">
            {node.heartbeat_at ? time(node.heartbeat_at) : "Not observed"}
          </dd>
        </div>
        <div>
          <dt>Freshness</dt>
          <dd className="mono">
            {age(node.freshness_seconds)} · {node.is_fresh ? "fresh" : "not evidenced"}
          </dd>
        </div>
        <div>
          <dt>Instances</dt>
          <dd className="mono">{node.healthy_instances}/{node.total_instances}</dd>
        </div>
        <div>
          <dt>p50 / p95</dt>
          <dd className="mono">
            {latency(node.p50_latency_ms)} / {latency(node.p95_latency_ms)}
          </dd>
        </div>
        <div>
          <dt>Queue depth</dt>
          <dd className="mono">
            {node.queue_depth === null ? "Not applicable" : count(node.queue_depth)}
          </dd>
        </div>
        <div><dt>Target access</dt><dd>{node.target_access}</dd></div>
      </dl>
    </div>
  );
}

function Attention({
  items,
  onOpen,
}: {
  items: BirdseyeAttentionReadModel[];
  onOpen: (item: BirdseyeAttentionReadModel) => void;
}) {
  if (items.length === 0) {
    return (
      <p className="birdseye-empty">
        No server-prioritized integrity, approval, finding, or runtime attention is open.
      </p>
    );
  }
  return (
    <div className="birdseye-attention-list">
      {items.map((item) => (
        <button
          type="button"
          key={item.attention_id}
          className={`birdseye-attention attention-${item.kind}`}
          onClick={() => onOpen(item)}
        >
          <span className="eyebrow">P{item.priority} · {item.kind}</span>
          <strong>{item.title}</strong>
          <span>{item.detail}</span>
          <small>{item.continuation}</small>
          <time className="mono" dateTime={item.created_at}>{time(item.created_at)}</time>
        </button>
      ))}
    </div>
  );
}

function Contracts({
  snapshot,
  names,
}: {
  snapshot: BirdseyeSnapshotReadModel;
  names: Map<string, string>;
}) {
  return (
    <section className="birdseye-contracts">
      <header className="birdseye-section-heading">
        <div><p className="eyebrow">OBSERVED CAPABILITY HANDOFFS</p><h2>Live contracts</h2></div>
        <span className="mono">{snapshot.edges.length}</span>
      </header>
      {snapshot.edges.length === 0 ? (
        <p className="birdseye-empty">
          No contract is shown until both registered endpoints exist.
        </p>
      ) : (
        <div className="birdseye-contract-list">
          {snapshot.edges.map((edge) => (
            <article key={edge.edge_id}>
              <i className={`state-${edge.state}`} aria-hidden="true" />
              <div>
                <strong>{edge.contract_name}</strong>
                <span>
                  {names.get(edge.source_component_id)} → {names.get(edge.target_component_id)}
                </span>
                <small>{edge.detail}</small>
              </div>
              <div>
                <span className="mono">{edge.state}</span>
                <small className="mono">
                  {edge.last_event_at ? time(edge.last_event_at) : "No event"}
                </small>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

export function Birdseye({
  snapshot,
  stream,
  onOpenAttention,
}: {
  snapshot: BirdseyeSnapshotReadModel;
  stream: ResourceResult<ConsoleEvent[]>;
  onOpenAttention: (item: BirdseyeAttentionReadModel) => void;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected =
    snapshot.nodes.find((node) => node.component_id === selectedId) ??
    snapshot.nodes[0] ??
    null;
  const names = new Map(snapshot.nodes.map((node) => [node.component_id, node.name]));
  const campaign = snapshot.campaign;
  const openAttention = (item: BirdseyeAttentionReadModel) => {
    if (item.kind === "component") setSelectedId(item.record_id);
    else onOpenAttention(item);
  };
  return (
    <div className="birdseye">
      <section className="birdseye-summary" aria-label="Live campaign summary">
        <div>
          <p className="eyebrow">CURRENT AUTHORIZED ASSESSMENT</p>
          {campaign ? (
            <>
              <strong>{campaign.target_name}</strong>
              <span>
                <span className="mono">{campaign.target_id}@{campaign.target_version}</span>
                {" · "}
                <span className="mono">{campaign.run_id}</span>
              </span>
            </>
          ) : (
            <strong>No persisted campaign is available.</strong>
          )}
        </div>
        <dl>
          <div><dt>State</dt><dd>{campaign?.state ?? "none"}</dd></div>
          <div><dt>Profile</dt><dd>{campaign?.execution_profile ?? "none"}</dd></div>
          <div>
            <dt>Attempts</dt>
            <dd className="mono">{campaign ? count(campaign.attempt_count) : "—"}</dd>
          </div>
          <div><dt>As of</dt><dd className="mono">{time(snapshot.as_of)}</dd></div>
        </dl>
      </section>

      <div className="birdseye-outcome-layout">
        <SecurityPosture snapshot={snapshot} />
        <section className="birdseye-attention-panel">
          <header className="birdseye-section-heading">
            <div><p className="eyebrow">SERVER PRIORITY</p><h2>Needs attention</h2></div>
            <span className="mono">{snapshot.attention.length}</span>
          </header>
          <Attention items={snapshot.attention} onOpen={openAttention} />
        </section>
      </div>

      <div className="birdseye-evidence-layout">
        <CategoryOutcomes
          outcomes={snapshot.category_outcomes}
          currentVersion={campaign?.target_version ?? null}
        />
        <AgentActivity events={snapshot.agent_activity} />
      </div>

      <Instrumentation snapshot={snapshot} stream={stream} />

      <div className="birdseye-layout">
        <section className="birdseye-canvas">
          <header className="birdseye-section-heading">
            <div>
              <p className="eyebrow">REGISTRY-DERIVED RUNTIME</p>
              <h2>Trust boundaries and components</h2>
            </div>
            <span className="mono">{snapshot.nodes.length} nodes</span>
          </header>
          <Topology
            snapshot={snapshot}
            selectedId={selected?.component_id ?? null}
            onSelect={setSelectedId}
          />
        </section>
        <aside className="birdseye-rail">
          <section>
            <header className="birdseye-section-heading">
              <div><p className="eyebrow">COMPONENT EVIDENCE</p><h2>Inspector</h2></div>
              <span className="mono">{shortId(selected?.component_id)}</span>
            </header>
            <NodeInspector node={selected} />
          </section>
        </aside>
      </div>

      <div className="birdseye-lower">
        <Contracts snapshot={snapshot} names={names} />
        <section className="birdseye-activity">
          <header className="birdseye-section-heading">
            <div><p className="eyebrow">DURABLE AUDIT ORDER</p><h2>Platform activity</h2></div>
            <span className="mono">cursor {snapshot.cursor}</span>
          </header>
          {snapshot.timeline.length === 0 ? (
            <p className="birdseye-empty">
              No organization-scoped audit events have been recorded.
            </p>
          ) : (
            <div className="birdseye-timeline">
              {snapshot.timeline.map((event) => (
                <article key={event.cursor}>
                  <span className="mono">{event.cursor}</span>
                  <div>
                    <strong>{event.summary}</strong>
                    <small>
                      {event.aggregate_type} · {event.aggregate_id} · {event.actor}
                    </small>
                  </div>
                  <time className="mono" dateTime={event.created_at}>
                    {time(event.created_at)}
                  </time>
                </article>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
