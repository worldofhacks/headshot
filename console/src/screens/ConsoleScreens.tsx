import { useCallback, useState } from "react";

import type { ApiClient } from "../api/client";
import {
  isJsonRecord,
  type JsonRecord,
  type Principal,
} from "../api/contracts";
import { COMMAND_PATHS, RESOURCE_PATHS } from "../api/paths";
import {
  decodeApprovals,
  decodeAttempts,
  decodeAuditHistory,
  decodeCampaigns,
  decodeComponents,
  decodeConfiguration,
  decodeCosts,
  decodeCoverage,
  decodeEvidence,
  decodeFinding,
  decodeFindings,
  decodeResilience,
  decodeTargets,
  decodeTraces,
  type ReadModelDecoder,
} from "../api/read-models";
import { AdversarialText } from "../components/AdversarialText";
import { CommandButton } from "../components/CommandButton";
import {
  RecordDetails,
  RecordTable,
  ResourceView,
  StateNotice,
  type Column,
} from "../components/ResourceView";
import { useConsoleEvents } from "../hooks/useConsoleEvents";
import { useResource } from "../hooks/useResource";
import { navigateTo } from "../router";
import {
  PERMISSIONS,
  type ApprovalReadModel,
  type AttemptReadModel,
  type AuditReadModel,
  type CampaignReadModel,
  type ComponentReadModel,
  type ConfigurationReadModel,
  type CostReadModel,
  type CoverageReadModel,
  type EvidenceReadModel,
  type FindingDetailReadModel,
  type FindingReadModel,
  type ResilienceReadModel,
  type TargetReadModel,
  type TraceReadModel,
} from "../types";

interface ScreenProps {
  client: ApiClient;
  principal: Principal;
  entityId: string | null;
  getToken: () => Promise<string | null>;
}

const identity = (record: JsonRecord, keys: string[]) => {
  for (const key of keys) {
    if (typeof record[key] === "string" && record[key]) return record[key] as string;
  }
  return null;
};

const hasPermission = (principal: Principal, permission: string) =>
  principal.organization_permissions.includes(permission);

function Panel({ title, meta, children }: { title: string; meta?: string; children: React.ReactNode }) {
  return (
    <section className="panel">
      <header className="panel-header">
        <div>
          <p className="eyebrow">AUTHORITATIVE VIEW</p>
          <h2>{title}</h2>
        </div>
        {meta && <span className="panel-meta mono">{meta}</span>}
      </header>
      <div className="panel-body">{children}</div>
    </section>
  );
}

function ScreenHeading({ title, detail }: { title: string; detail: string }) {
  return (
    <header className="screen-heading">
      <div>
        <p className="eyebrow">HEADSHOT CONTROL PLANE</p>
        <h1>{title}</h1>
      </div>
      <p>{detail}</p>
    </header>
  );
}

function MissingCommand({ label, dependency }: { label: string; dependency: string }) {
  return (
    <div className="command-control">
      <button className="button" type="button" disabled>{label}</button>
      <span className="command-note">Requires: {dependency}</span>
    </div>
  );
}

function CampaignAttempts({
  client,
  campaignId,
}: {
  client: ApiClient;
  campaignId: string;
}) {
  const attempts = useResource<AttemptReadModel[]>(
    client,
    RESOURCE_PATHS.attempts(campaignId),
    decodeAttempts,
  );
  return (
    <Panel title="Attempts" meta={campaignId}>
      <ResourceView result={attempts.result} emptyLabel="No attempts are recorded for this campaign.">
        {(data) => (
          <RecordTable
            data={data}
            identityKeys={["attempt_id"]}
            columns={[
              { key: "attempt_id", label: "Attempt", mono: true },
              { key: "ordinal", label: "Ordinal", mono: true },
              { key: "case_id", label: "Case", mono: true },
              { key: "verdict", label: "Server verdict" },
              { key: "executed_at", label: "Executed", mono: true },
            ]}
            onSelect={(record) => {
              const attemptId = identity(record, ["attempt_id"]);
              if (attemptId) navigateTo({ screen: "live", entityId: attemptId });
            }}
          />
        )}
      </ResourceView>
    </Panel>
  );
}

function AttemptEvidence({ client, attemptId }: { client: ApiClient; attemptId: string }) {
  const evidence = useResource<EvidenceReadModel>(
    client,
    RESOURCE_PATHS.evidence(attemptId),
    decodeEvidence,
  );
  return (
    <Panel title="Quarantined evidence" meta={attemptId}>
      <ResourceView result={evidence.result} emptyLabel="No evidence is recorded for this attempt.">
        {(data) => {
          const record = data;
          const textFields = [
            "content",
            "request_text",
            "response_text",
            "raw_content",
            "attack_attempt",
            "request_transcript",
            "response_transcript",
          ].filter((key) => record[key] !== undefined);
          return (
            <div className="evidence-stack">
              <RecordDetails
                data={record}
                preferredKeys={[
                  "campaign_run_id",
                  "attempt_id",
                  "target_id",
                  "target_version",
                  "surface_id",
                  "surface_version",
                  "content_hash",
                  "verdict",
                  "executed_at",
                ]}
              />
              {textFields.map((key) => (
                <div key={key}>
                  <p className="field-label">{key.replaceAll("_", " ")}</p>
                  <AdversarialText>
                    {typeof record[key] === "string"
                      ? record[key] as string
                      : JSON.stringify(record[key], null, 2)}
                  </AdversarialText>
                </div>
              ))}
            </div>
          );
        }}
      </ResourceView>
    </Panel>
  );
}

export function LiveScreen({ client, principal, entityId, getToken }: ScreenProps) {
  const campaigns = useResource<CampaignReadModel[]>(
    client,
    RESOURCE_PATHS.campaigns,
    decodeCampaigns,
  );
  const components = useResource<ComponentReadModel[]>(
    client,
    RESOURCE_PATHS.components,
    decodeComponents,
  );
  const [selectedCampaign, setSelectedCampaign] = useState<CampaignReadModel | null>(null);
  const selectedCampaignId = selectedCampaign
    ? identity(selectedCampaign, ["run_id", "campaign_id"])
    : null;
  const reconcile = useCallback(() => {
    campaigns.refresh();
    components.refresh();
  }, [campaigns.refresh, components.refresh]);
  const events = useConsoleEvents(getToken, reconcile);
  const preparedScope = selectedCampaign && isJsonRecord(selectedCampaign.authorization_request_payload)
    ? selectedCampaign.authorization_request_payload
    : null;

  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Live operations"
        detail="Campaign, queue, component and ordered event state comes from protected server projections."
      />
      <Panel title="Campaigns">
        <ResourceView result={campaigns.result} emptyLabel="No campaigns have been persisted.">
          {(data) => (
            <RecordTable
              data={data}
              identityKeys={["run_id", "campaign_id"]}
              columns={[
                { key: "run_id", label: "Run", mono: true },
                { key: "state", label: "State" },
                { key: "scope_hash", label: "Operation hash", mono: true },
                { key: "attempt_count", label: "Attempts", mono: true },
                { key: "created_at", label: "Created", mono: true },
              ]}
              onSelect={setSelectedCampaign}
            />
          )}
        </ResourceView>
        <div className="command-row">
          {preparedScope ? (
            <CommandButton
              client={client}
              path={COMMAND_PATHS.createCampaignAuthorizationRequest}
              payload={preparedScope}
              label="Request campaign authorization"
              allowed={hasPermission(principal, PERMISSIONS.campaignLaunch)}
              unavailableReason={PERMISSIONS.campaignLaunch}
              onAcknowledged={campaigns.refresh}
            />
          ) : (
            <MissingCommand
              label="Request campaign authorization"
              dependency="a server-prepared canonical scope"
            />
          )}
          {selectedCampaignId ? (
            <CommandButton
              client={client}
              path={COMMAND_PATHS.abortCampaign(selectedCampaignId)}
              payload={{ reason: "operator_abort" }}
              label="Abort selected campaign"
              allowed={hasPermission(principal, PERMISSIONS.campaignAbort)}
              unavailableReason={PERMISSIONS.campaignAbort}
              destructive
              onAcknowledged={campaigns.refresh}
            />
          ) : (
            <MissingCommand label="Abort selected campaign" dependency="a selected persisted campaign" />
          )}
        </div>
      </Panel>
      {selectedCampaignId && <CampaignAttempts client={client} campaignId={selectedCampaignId} />}
      {entityId && <AttemptEvidence client={client} attemptId={entityId} />}
      <div className="panel-grid">
        <Panel title="Runtime components">
          <ResourceView result={components.result} emptyLabel="No components are registered.">
            {(data) => (
              <RecordTable
                data={data}
                identityKeys={["component_id", "name"]}
                columns={[
                  { key: "name", label: "Component" },
                  { key: "kind", label: "Kind" },
                  { key: "availability", label: "Server state" },
                  { key: "detail", label: "Evidence" },
                  { key: "heartbeat_at", label: "Heartbeat", mono: true },
                ]}
              />
            )}
          </ResourceView>
        </Panel>
        <Panel
          title="Ordered event stream"
          meta={"cursor" in events && events.cursor !== undefined ? `cursor ${events.cursor}` : undefined}
        >
          <ResourceView result={events} emptyLabel="No stream events are available after the current cursor.">
            {(data) => (
              <div className="event-stack">
                {data.map((event, index) => (
                  <article className="event-record" key={`${event.cursor ?? "event"}:${index}`}>
                    <header>
                      <strong>{event.event}</strong>
                      <span className="mono">
                        {event.cursor === null ? "no cursor" : `cursor ${event.cursor}`}
                      </span>
                    </header>
                    <AdversarialText>{JSON.stringify(event.data, null, 2)}</AdversarialText>
                  </article>
                ))}
              </div>
            )}
          </ResourceView>
        </Panel>
      </div>
    </div>
  );
}

function FindingDetail({
  client,
  principal,
  findingId,
  refreshList,
}: {
  client: ApiClient;
  principal: Principal;
  findingId: string;
  refreshList: () => void;
}) {
  const detail = useResource<FindingDetailReadModel>(
    client,
    RESOURCE_PATHS.finding(findingId),
    decodeFinding,
  );
  const [rationale, setRationale] = useState("");
  const refresh = () => {
    detail.refresh();
    refreshList();
  };
  return (
    <Panel title="Finding detail" meta={findingId}>
      <ResourceView result={detail.result} emptyLabel="The finding record was not returned.">
        {(data) => (
          <>
            <RecordDetails
              data={data}
              preferredKeys={[
                "finding_id",
                "category",
                "severity",
                "state",
                "target_version",
                "publication_status",
                "evidence_integrity",
              ]}
            />
            {data.history.length > 0 ? (
              <RecordTable
                data={data.history}
                identityKeys={["created_at", "actor_user_id"]}
                columns={[
                  { key: "decision", label: "Decision" },
                  { key: "actor_user_id", label: "Actor", mono: true },
                  { key: "rationale", label: "Rationale" },
                  { key: "created_at", label: "Occurred", mono: true },
                ]}
              />
            ) : (
              <StateNotice state="empty" detail="No finding history is recorded." />
            )}
            <label className="form-field">
              <span>Decision rationale</span>
              <textarea
                value={rationale}
                maxLength={2000}
                onChange={(event) => setRationale(event.currentTarget.value)}
                placeholder="Required by the server for finding decisions"
              />
            </label>
            <div className="command-row">
              <CommandButton
                client={client}
                path={COMMAND_PATHS.decideFinding(findingId)}
                payload={{ decision: "approved", rationale: rationale.trim() }}
                label="Approve finding"
                allowed={hasPermission(principal, PERMISSIONS.findingsApprove) && rationale.trim().length > 0}
                unavailableReason={rationale.trim() ? PERMISSIONS.findingsApprove : "a decision rationale"}
                onAcknowledged={refresh}
              />
              <CommandButton
                client={client}
                path={COMMAND_PATHS.decideFinding(findingId)}
                payload={{ decision: "rejected", rationale: rationale.trim() }}
                label="Reject finding"
                allowed={hasPermission(principal, PERMISSIONS.findingsApprove) && rationale.trim().length > 0}
                unavailableReason={rationale.trim() ? PERMISSIONS.findingsApprove : "a decision rationale"}
                onAcknowledged={refresh}
              />
              <CommandButton
                client={client}
                path={COMMAND_PATHS.resolveFinding(findingId)}
                payload={{ rationale: rationale.trim() }}
                label="Resolve finding"
                allowed={hasPermission(principal, PERMISSIONS.findingsResolve) && rationale.trim().length > 0}
                unavailableReason={rationale.trim() ? PERMISSIONS.findingsResolve : "a resolution rationale"}
                onAcknowledged={refresh}
              />
            </div>
          </>
        )}
      </ResourceView>
    </Panel>
  );
}

export function FindingsScreen({ client, principal, entityId }: ScreenProps) {
  const findings = useResource<FindingReadModel[]>(
    client,
    RESOURCE_PATHS.findings,
    decodeFindings,
  );
  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Findings"
        detail="Persisted findings remain bound to server verdict, evidence and publication history."
      />
      <Panel title="Finding register">
        <ResourceView result={findings.result} emptyLabel="No findings have been persisted.">
          {(data) => (
            <RecordTable
              data={data}
              identityKeys={["finding_id"]}
              columns={[
                { key: "finding_id", label: "Finding", mono: true },
                { key: "category", label: "Category" },
                { key: "severity", label: "Severity" },
                { key: "state", label: "State" },
                { key: "publication_status", label: "Publication" },
              ]}
              onSelect={(record) => {
                const findingId = identity(record, ["finding_id"]);
                if (findingId) navigateTo({ screen: "findings", entityId: findingId });
              }}
            />
          )}
        </ResourceView>
      </Panel>
      {entityId && (
        <FindingDetail
          client={client}
          principal={principal}
          findingId={entityId}
          refreshList={findings.refresh}
        />
      )}
    </div>
  );
}

export function ApprovalsScreen({ client, principal, entityId }: ScreenProps) {
  const approvals = useResource<ApprovalReadModel[]>(
    client,
    RESOURCE_PATHS.approvals,
    decodeApprovals,
  );
  const records = approvals.result.data ?? [];
  const selected = entityId
    ? records.find((record) => identity(record, ["request_id", "approval_id"]) === entityId) ?? null
    : null;
  const requestId = selected ? identity(selected, ["request_id", "approval_id"]) : null;
  const launcher = selected && typeof selected.launcher_user_id === "string"
    ? selected.launcher_user_id
    : null;
  const distinctHuman = launcher === null || launcher !== principal.user_id;
  const pending = selected?.status === "pending";
  const approved = selected?.status === "approved";
  const canAuthorize =
    hasPermission(principal, PERMISSIONS.campaignAuthorize) && distinctHuman && pending;

  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Approvals"
        detail="Decisions bind to an exact server operation hash. Queue completion is not displayed as human approval."
      />
      <Panel title="Pending and historical decisions">
        <ResourceView result={approvals.result} emptyLabel="No approval requests are pending or recorded.">
          {(data) => (
            <RecordTable
              data={data}
              identityKeys={["request_id", "approval_id"]}
              columns={[
                { key: "request_id", label: "Request", mono: true },
                { key: "status", label: "Status" },
                { key: "scope_hash", label: "Operation hash", mono: true },
                { key: "launcher_user_id", label: "Launcher", mono: true },
                { key: "expires_at", label: "Expires", mono: true },
              ]}
              onSelect={(record) => {
                const id = identity(record, ["request_id", "approval_id"]);
                if (id) navigateTo({ screen: "approvals", entityId: id });
              }}
            />
          )}
        </ResourceView>
      </Panel>
      {entityId && !selected && approvals.result.state !== "loading" && (
        <Panel title="Approval detail"><StateNotice state="empty" detail="That approval is not in the organization-scoped response." /></Panel>
      )}
      {selected && requestId && (
        <Panel title="Exact authorization scope" meta={requestId}>
          <RecordDetails
            data={selected}
            preferredKeys={[
              "request_id",
              "decision",
              "scope_hash",
              "target_id",
              "target_version",
              "surface_id",
              "surface_version",
              "corpus_hash",
              "auth_posture",
              "endpoint",
              "run_nonce",
              "launcher_user_id",
              "approver_user_id",
              "expires_at",
            ]}
          />
          {!distinctHuman && (
            <StateNotice
              state="unavailable"
              reason="requester_cannot_approve_own_operation"
              detail="The backend enforces a distinct authenticated approver; this courtesy control cannot bypass it."
            />
          )}
          <div className="command-row">
            <CommandButton
              client={client}
              path={COMMAND_PATHS.decideCampaignAuthorization(requestId)}
              payload={{ decision: "approved" }}
              label="Approve exact scope"
              allowed={canAuthorize}
              unavailableReason={
                !pending
                  ? "a pending authorization request"
                  : distinctHuman
                    ? PERMISSIONS.campaignAuthorize
                    : "distinct approver required"
              }
              onAcknowledged={approvals.refresh}
            />
            <CommandButton
              client={client}
              path={COMMAND_PATHS.decideCampaignAuthorization(requestId)}
              payload={{ decision: "rejected" }}
              label="Deny exact scope"
              allowed={hasPermission(principal, PERMISSIONS.campaignAuthorize) && pending}
              unavailableReason={
                pending ? PERMISSIONS.campaignAuthorize : "a pending authorization request"
              }
              onAcknowledged={approvals.refresh}
            />
            <CommandButton
              client={client}
              path={COMMAND_PATHS.launchCampaign}
              payload={{ authorization_request_id: requestId }}
              label="Launch approved campaign"
              allowed={hasPermission(principal, PERMISSIONS.campaignLaunch) && approved}
              unavailableReason={
                approved ? PERMISSIONS.campaignLaunch : "an approved authorization request"
              }
              onAcknowledged={approvals.refresh}
            />
          </div>
        </Panel>
      )}
    </div>
  );
}

type SimpleResourceName = "coverage" | "resilience" | "traces" | "costs";

const simpleScreens: Record<SimpleResourceName, {
  title: string;
  detail: string;
  empty: string;
  columns: Column[];
  identityKeys: string[];
}> = {
  coverage: {
    title: "Coverage",
    detail: "Only server-derived, hash-verified and nonce-deduplicated coverage is shown.",
    empty: "No verified coverage records are available.",
    identityKeys: ["target_version"],
    columns: [
      { key: "target_version", label: "Target version", mono: true },
      { key: "verified_attempt_count", label: "Verified attempts", mono: true },
      { key: "covered", label: "Server coverage decision" },
      { key: "as_of", label: "As of", mono: true },
    ],
  },
  resilience: {
    title: "Resilience",
    detail: "Version and regression history is read from the authoritative projection.",
    empty: "No resilience or regression history is recorded.",
    identityKeys: ["regression_id", "version"],
    columns: [
      { key: "version", label: "Version", mono: true },
      { key: "regression_id", label: "Regression", mono: true },
      { key: "status", label: "Status" },
      { key: "recorded_at", label: "Recorded", mono: true },
    ],
  },
  traces: {
    title: "Traces",
    detail: "Each physical target request is correlated, timed and exported from the private Runner.",
    empty: "No trace records are persisted.",
    identityKeys: ["trace_id"],
    columns: [
      { key: "trace_id", label: "Trace", mono: true },
      { key: "campaign_id", label: "Campaign", mono: true },
      { key: "attempt_id", label: "Attempt", mono: true },
      { key: "operation", label: "Operation" },
      { key: "status", label: "Status" },
      { key: "duration_ms", label: "Latency ms", mono: true },
      { key: "measured_cost", label: "Cost USD", mono: true },
      { key: "langfuse_status", label: "Langfuse" },
    ],
  },
  costs: {
    title: "Measured costs",
    detail: "Accounting values are displayed exactly as recorded by the backend.",
    empty: "No measured accounting records are available.",
    identityKeys: ["accounting_id"],
    columns: [
      { key: "accounting_id", label: "Record", mono: true },
      { key: "campaign_id", label: "Campaign", mono: true },
      { key: "provider", label: "Provider" },
      { key: "measured_cost", label: "Measured cost", mono: true },
      { key: "request_count", label: "Requests", mono: true },
      { key: "average_cost_per_request", label: "Cost / request", mono: true },
      { key: "duration_ms", label: "Run latency ms", mono: true },
      { key: "recorded_at", label: "Recorded", mono: true },
    ],
  },
};

function TypedSimpleResourceScreen<T extends JsonRecord>({
  client,
  resource,
  decode,
}: {
  client: ApiClient;
  resource: SimpleResourceName;
  decode: ReadModelDecoder<T[]>;
}) {
  const config = simpleScreens[resource];
  const controller = useResource<T[]>(client, RESOURCE_PATHS[resource], decode);
  return (
    <div className="screen-stack">
      <ScreenHeading title={config.title} detail={config.detail} />
      <Panel title={config.title}>
        <ResourceView result={controller.result} emptyLabel={config.empty}>
          {(data) => (
            <RecordTable
              data={data}
              identityKeys={config.identityKeys}
              columns={config.columns}
            />
          )}
        </ResourceView>
      </Panel>
    </div>
  );
}

export function SimpleResourceScreen({ client, resource }: { client: ApiClient; resource: SimpleResourceName }) {
  switch (resource) {
    case "coverage":
      return <TypedSimpleResourceScreen<CoverageReadModel> client={client} resource={resource} decode={decodeCoverage} />;
    case "resilience":
      return <TypedSimpleResourceScreen<ResilienceReadModel> client={client} resource={resource} decode={decodeResilience} />;
    case "traces":
      return <TypedSimpleResourceScreen<TraceReadModel> client={client} resource={resource} decode={decodeTraces} />;
    case "costs":
      return <TypedSimpleResourceScreen<CostReadModel> client={client} resource={resource} decode={decodeCosts} />;
  }
}

function TargetManagement({
  client,
  principal,
  selected,
  refresh,
}: {
  client: ApiClient;
  principal: Principal;
  selected: TargetReadModel;
  refresh: () => void;
}) {
  const targetId = identity(selected, ["target_id"]);
  const version = typeof selected.version === "string" ? selected.version : null;
  const transitions = Array.isArray(selected.allowed_lifecycle_transitions)
    ? selected.allowed_lifecycle_transitions.filter((value): value is string => typeof value === "string")
    : [];
  const probePayload = isJsonRecord(selected.probe_authorization_payload)
    ? selected.probe_authorization_payload
    : null;
  const surfaces = selected.surfaces;
  const allowed = hasPermission(principal, PERMISSIONS.targetsManage);
  const canAuthorizeProbe = hasPermission(principal, PERMISSIONS.campaignAuthorize);
  const template = selected.campaign_template;
  // Pre-filled bounded defaults so an Operator can request a campaign without hand-entering
  // caps or a nonce. The nonce is freshly generated per mount (unused → replay-safe); every
  // field stays editable, and the server still validates caps against the target's ceiling.
  const [runNonce, setRunNonce] = useState(() => `live-${globalThis.crypto.randomUUID()}`);
  const [budgetUsd, setBudgetUsd] = useState("1");
  const [maxAttempts, setMaxAttempts] = useState("9");
  const [requestsPerSecond, setRequestsPerSecond] = useState("0.5");
  const [timeoutSeconds, setTimeoutSeconds] = useState("600");
  const parsedCaps = {
    budget_usd: Number(budgetUsd),
    max_attempts_per_run: Number(maxAttempts),
    target_requests_per_second: Number(requestsPerSecond),
    run_timeout_seconds: Number(timeoutSeconds),
  };
  const capsValid = Object.values(parsedCaps).every((value) => Number.isFinite(value) && value > 0)
    && Number.isSafeInteger(parsedCaps.max_attempts_per_run);
  const requestPayload = template && capsValid && runNonce.trim().length >= 16
    ? {
        target_id: template.target_id,
        target_version: template.target_version,
        surface_id: template.surface_id,
        surface_version: template.surface_version,
        corpus_id: template.corpus_id,
        corpus_hash: template.corpus_hash,
        execution_profile: template.execution_profile,
        caps: parsedCaps,
        run_nonce: runNonce.trim(),
        expires_in_seconds: 900,
      }
    : null;
  return (
    <Panel title="Target administration" meta={targetId ?? undefined}>
      <RecordDetails
        data={selected}
        preferredKeys={[
          "target_id",
          "name",
          "version",
          "lifecycle",
          "environment",
          "adapter_kind",
          "credential_configured",
          "synthetic_data_only",
        ]}
      />
      <div className="command-row">
        {targetId && version && transitions[0] ? (
          <CommandButton
            client={client}
            path={COMMAND_PATHS.changeTargetLifecycle(targetId)}
            payload={{ version, lifecycle: transitions[0] }}
            label={`Move to ${transitions[0]}`}
            allowed={allowed}
            unavailableReason={PERMISSIONS.targetsManage}
            onAcknowledged={refresh}
          />
        ) : (
          <MissingCommand label="Change lifecycle" dependency="a server-returned allowed transition" />
        )}
        {probePayload ? (
          <CommandButton
            client={client}
            path={COMMAND_PATHS.createProbeAuthorizationRequest}
            payload={probePayload}
            label="Request live probe authorization"
            allowed={canAuthorizeProbe}
            unavailableReason={PERMISSIONS.campaignAuthorize}
            onAcknowledged={refresh}
          />
        ) : (
          <MissingCommand label="Request live probe authorization" dependency="a server-prepared probe scope" />
        )}
        <MissingCommand label="Revise target" dependency="a trusted target authoring catalog" />
        <MissingCommand label="Create attack surface" dependency="a trusted surface authoring catalog" />
        <MissingCommand label="Revise attack surface" dependency="a trusted surface revision contract" />
      </div>
      {template && (
        <div className="evidence-stack">
          <p className="field-label">Exact campaign authorization request</p>
          <RecordDetails
            data={template}
            preferredKeys={[
              "execution_profile",
              "target_id",
              "target_version",
              "surface_id",
              "surface_version",
              "corpus_id",
              "corpus_hash",
              "maximum_caps",
            ]}
          />
          <div className="panel-grid">
            <label className="form-field">
              <span>Run nonce (16+ characters)</span>
              <input value={runNonce} onChange={(event) => setRunNonce(event.currentTarget.value)} />
            </label>
            <label className="form-field">
              <span>Budget USD</span>
              <input type="number" min="0" step="0.01" value={budgetUsd} onChange={(event) => setBudgetUsd(event.currentTarget.value)} />
            </label>
            <label className="form-field">
              <span>Maximum attempts</span>
              <input type="number" min="1" step="1" value={maxAttempts} onChange={(event) => setMaxAttempts(event.currentTarget.value)} />
            </label>
            <label className="form-field">
              <span>Target requests / second</span>
              <input type="number" min="0" step="0.1" value={requestsPerSecond} onChange={(event) => setRequestsPerSecond(event.currentTarget.value)} />
            </label>
            <label className="form-field">
              <span>Run timeout seconds</span>
              <input type="number" min="1" step="1" value={timeoutSeconds} onChange={(event) => setTimeoutSeconds(event.currentTarget.value)} />
            </label>
          </div>
          <CommandButton
            client={client}
            path={COMMAND_PATHS.createCampaignAuthorizationRequest}
            payload={requestPayload ?? {}}
            label="Request exact campaign authorization"
            allowed={Boolean(requestPayload) && hasPermission(principal, PERMISSIONS.campaignLaunch)}
            unavailableReason={requestPayload ? PERMISSIONS.campaignLaunch : "valid operator-provided caps and nonce"}
            onAcknowledged={() => {
              // Roll a fresh unused nonce after each accepted request so the next campaign
              // can be requested immediately without a replayed-nonce rejection.
              setRunNonce(`live-${globalThis.crypto.randomUUID()}`);
              refresh();
            }}
          />
        </div>
      )}
      {surfaces.length > 0 ? (
        <div className="surface-stack">
          {surfaces.map((surface, index) => {
            const surfaceId = identity(surface, ["surface_id"]);
            const surfaceVersion = typeof surface.version === "string" ? surface.version : null;
            const enabled = typeof surface.enabled === "boolean" ? surface.enabled : null;
            if (!targetId || !surfaceId || !surfaceVersion || enabled === null) return null;
            return (
              <div className="surface-row" key={`${surfaceId}:${surfaceVersion}:${index}`}>
                <span className="mono">{surfaceId} · {surfaceVersion}</span>
                <CommandButton
                  client={client}
                  path={COMMAND_PATHS.changeSurfaceState(targetId, surfaceId)}
                  payload={{ version: surfaceVersion, enabled: !enabled }}
                  label={enabled ? "Disable surface" : "Enable surface"}
                  allowed={allowed}
                  unavailableReason={PERMISSIONS.targetsManage}
                  destructive={enabled}
                  onAcknowledged={refresh}
                />
              </div>
            );
          })}
        </div>
      ) : (
        <div className="command-row">
          <MissingCommand label="Enable or disable surface" dependency="a selected versioned surface record" />
        </div>
      )}
    </Panel>
  );
}

export function TargetsScreen({ client, principal }: ScreenProps) {
  const targets = useResource<TargetReadModel[]>(
    client,
    RESOURCE_PATHS.targets,
    decodeTargets,
  );
  const [selected, setSelected] = useState<TargetReadModel | null>(null);
  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Targets"
        detail="Only persisted immutable target and attack-surface versions may be selected for dispatch."
      />
      <Panel title="Target registry">
        <ResourceView result={targets.result} emptyLabel="No target definitions are registered.">
          {(data) => (
            <RecordTable
              data={data}
              identityKeys={["target_id", "version"]}
              columns={[
                { key: "target_id", label: "Target", mono: true },
                { key: "name", label: "Name" },
                { key: "version", label: "Version", mono: true },
                { key: "lifecycle", label: "Lifecycle" },
                { key: "environment", label: "Environment" },
              ]}
              onSelect={setSelected}
            />
          )}
        </ResourceView>
        <div className="command-row">
          <MissingCommand label="Create target" dependency="a trusted target authoring catalog" />
        </div>
      </Panel>
      {selected && (
        <TargetManagement
          client={client}
          principal={principal}
          selected={selected}
          refresh={targets.refresh}
        />
      )}
    </div>
  );
}

function AuditHistory({ client }: { client: ApiClient }) {
  const audit = useResource<AuditReadModel[]>(
    client,
    RESOURCE_PATHS.audit,
    decodeAuditHistory,
  );
  return (
    <ResourceView result={audit.result} emptyLabel="No audit events are recorded.">
      {(data) => (
        <RecordTable
          data={data}
          identityKeys={["cursor"]}
          columns={[
            { key: "cursor", label: "Cursor", mono: true },
            { key: "event_type", label: "Event" },
            { key: "actor_user_id", label: "Actor", mono: true },
            { key: "aggregate_id", label: "Resource", mono: true },
            { key: "created_at", label: "Occurred", mono: true },
          ]}
        />
      )}
    </ResourceView>
  );
}

export function ConfigurationScreen({ client, principal }: ScreenProps) {
  const configuration = useResource<ConfigurationReadModel>(
    client,
    RESOURCE_PATHS.configuration,
    decodeConfiguration,
  );
  const configRecord = configuration.result.data;
  const candidate = configRecord && isJsonRecord(configRecord.candidate_configuration)
    ? configRecord.candidate_configuration
    : null;
  const snapshotId = configRecord && typeof configRecord.validated_snapshot_id === "string"
    ? configRecord.validated_snapshot_id
    : null;
  const validationId = configRecord && typeof configRecord.validation_id === "string"
    ? configRecord.validation_id
    : snapshotId;
  const agentName = configRecord && typeof configRecord.agent_name === "string"
    ? configRecord.agent_name
    : null;
  const baseVersion = configRecord && typeof configRecord.base_version === "number"
    ? configRecord.base_version
    : null;
  const configurationPayload = candidate && agentName && baseVersion !== null
    ? { agent_name: agentName, base_version: baseVersion, configuration: candidate }
    : null;
  const [rationale, setRationale] = useState("");
  const allowed = hasPermission(principal, PERMISSIONS.configManage);
  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Configuration"
        detail="Immutable effective configuration, validation and publication acknowledgements remain server-owned."
      />
      <Panel title="Effective configuration">
        <ResourceView result={configuration.result} emptyLabel="No configuration snapshot is published.">
          {(data) => (
            <div className="evidence-stack">
              <RecordDetails
                data={data}
                preferredKeys={[
                  "snapshot_id",
                  "version",
                  "status",
                  "published_at",
                  "published_by",
                ]}
              />
              <div>
                <p className="field-label">Effective server configuration</p>
                <AdversarialText>{JSON.stringify(data.configuration, null, 2)}</AdversarialText>
              </div>
            </div>
          )}
        </ResourceView>
        <div className="command-row">
          {configurationPayload ? (
            <CommandButton
              client={client}
              path={COMMAND_PATHS.validateConfiguration}
              payload={configurationPayload}
              label="Validate candidate configuration"
              allowed={allowed}
              unavailableReason={PERMISSIONS.configManage}
              onAcknowledged={configuration.refresh}
            />
          ) : (
            <MissingCommand label="Validate candidate configuration" dependency="a server-returned candidate" />
          )}
          {configurationPayload && validationId ? (
            <CommandButton
              client={client}
              path={COMMAND_PATHS.publishConfiguration}
              payload={{
                ...configurationPayload,
                validation_id: validationId,
                rationale: rationale.trim(),
              }}
              label="Publish validated snapshot"
              allowed={allowed && rationale.trim().length > 0}
              unavailableReason={rationale.trim() ? PERMISSIONS.configManage : "a publication rationale"}
              onAcknowledged={configuration.refresh}
            />
          ) : (
            <MissingCommand label="Publish validated snapshot" dependency="a server-validated snapshot" />
          )}
        </div>
        <label className="form-field">
          <span>Publication rationale</span>
          <textarea
            value={rationale}
            maxLength={2000}
            onChange={(event) => setRationale(event.currentTarget.value)}
            placeholder="Required for configuration publication"
          />
        </label>
      </Panel>
      <Panel title="Append-only audit history">
        {hasPermission(principal, PERMISSIONS.auditRead) ? (
          <AuditHistory client={client} />
        ) : (
          <StateNotice state="empty" detail={`Restricted to ${PERMISSIONS.auditRead}.`} />
        )}
      </Panel>
    </div>
  );
}
