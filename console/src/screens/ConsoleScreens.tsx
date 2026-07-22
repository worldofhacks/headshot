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
  decodeCoverage,
  decodeEvidence,
  decodeFinding,
  decodeFindings,
  decodeResilience,
  decodeTargets,
} from "../api/read-models";
import { AdversarialText } from "../components/AdversarialText";
import {
  count,
  DistributionBars,
  EvidenceGrid,
  MetricStrip,
  money,
  Panel,
  percent,
  ScreenHeading,
  shortId,
  TagMatrix,
  Timeline,
} from "../components/Analytics";
import { CommandButton } from "../components/CommandButton";
import {
  RecordDetails,
  RecordTable,
  ResourceView,
  StateNotice,
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
  type CoverageReadModel,
  type EvidenceReadModel,
  type FindingDetailReadModel,
  type FindingReadModel,
  type ResilienceReadModel,
  type TargetReadModel,
} from "../types";
import { CostsScreen, TracesScreen } from "./ObservabilityScreens";

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

const frequency = (values: string[]) => {
  const result = new Map<string, number>();
  for (const value of values) result.set(value, (result.get(value) ?? 0) + 1);
  return [...result.entries()]
    .map(([label, value]) => ({ label, value }))
    .sort((left, right) => right.value - left.value || left.label.localeCompare(right.label));
};

const toneFor = (value: string): "success" | "queued" | "failure" | "brand" | undefined => {
  const normalized = value.toLowerCase();
  if (["complete", "approved", "covered", "operational and evidenced", "passed", "pass", "ready", "resolved", "published"].some((candidate) => normalized.includes(candidate))) return "success";
  if (["failed", "failure", "rejected", "aborted", "critical", "high", "error", "blocked"].some((candidate) => normalized.includes(candidate))) return "failure";
  if (["pending", "queued", "running", "deferred", "review"].some((candidate) => normalized.includes(candidate))) return "queued";
  return "brand";
};

const distribution = (values: string[]) => frequency(values).map((row) => ({
  ...row,
  tone: toneFor(row.label),
}));

const timelineTone = (value: string): "success" | "queued" | "failure" | undefined => {
  const tone = toneFor(value);
  return tone === "brand" ? undefined : tone;
};

const unique = (values: string[]) => [...new Set(values)].sort();

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
        {(data) => {
          const withEvidence = data.filter((attempt) => attempt.content_hash !== null).length;
          const live = data.filter((attempt) => attempt.evidence_provenance === "live_target").length;
          return (
            <div className="evidence-stack">
              <EvidenceGrid values={[
                { label: "Attempts", value: count(data.length) },
                { label: "Evidence bound", value: `${withEvidence}/${data.length}`, tone: withEvidence === data.length ? "success" : "queued" },
                { label: "Live provenance", value: `${live}/${data.length}`, tone: live === data.length ? "success" : undefined },
                { label: "Verdicts", value: count(unique(data.flatMap((attempt) => attempt.verdict ? [attempt.verdict] : [])).length) },
              ]} />
              {data.some((attempt) => attempt.verdict) && (
                <DistributionBars rows={distribution(data.flatMap((attempt) => attempt.verdict ? [attempt.verdict] : ["pending verdict"]))} />
              )}
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
            </div>
          );
        }}
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
  const campaignRecords = campaigns.result.data ?? [];
  const effectiveCampaign = selectedCampaign
    ?? campaignRecords.find((campaign) => campaign.state === "running")
    ?? campaignRecords[0]
    ?? null;
  const selectedCampaignId = effectiveCampaign
    ? identity(effectiveCampaign, ["run_id", "campaign_id"])
    : null;
  const reconcile = useCallback(() => {
    campaigns.refresh();
    components.refresh();
  }, [campaigns.refresh, components.refresh]);
  const events = useConsoleEvents(getToken, reconcile);
  const preparedScope = effectiveCampaign && isJsonRecord(effectiveCampaign.authorization_request_payload)
    ? effectiveCampaign.authorization_request_payload
    : null;
  const componentRecords = components.result.data ?? [];
  const operationalComponents = componentRecords.filter(
    (component) => component.availability === "operational and evidenced",
  ).length;
  const totalAttempts = campaignRecords.reduce(
    (total, campaign) => total + (campaign.attempt_count ?? 0),
    0,
  );
  const completedCampaigns = campaignRecords.filter((campaign) => campaign.state === "complete").length;
  const activeCampaigns = campaignRecords.filter((campaign) => ["queued", "running"].includes(campaign.state)).length;

  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Live operations"
        detail="Campaign, queue, component and ordered event state comes from protected server projections."
      />
      <MetricStrip label="Live platform summary" values={[
        { label: "Campaigns", value: count(campaignRecords.length), note: `${completedCampaigns} complete · ${activeCampaigns} active` },
        { label: "Selected run", value: shortId(selectedCampaignId), note: effectiveCampaign?.state ?? "No campaign selected" },
        { label: "Recorded attempts", value: count(totalAttempts), note: `${count(campaignRecords.length)} durable campaign records` },
        { label: "Components evidenced", value: `${operationalComponents}/${componentRecords.length}`, note: components.result.state },
      ]} />
      <div className="panel-grid analytical-grid">
        <Panel title="Campaign state" meta="persisted runs" eyebrow="OPERATIONAL POSTURE">
          {campaignRecords.length > 0
            ? <DistributionBars rows={distribution(campaignRecords.map((campaign) => campaign.state))} />
            : <StateNotice state="empty" detail="No campaign state is available." />}
        </Panel>
        <Panel title="Runtime posture" meta="component evidence" eyebrow="OPERATIONAL POSTURE">
          {componentRecords.length > 0
            ? <DistributionBars rows={distribution(componentRecords.map((component) => component.availability))} />
            : <ResourceView result={components.result} emptyLabel="No components are registered.">{() => null}</ResourceView>}
          <p className="data-note">Component posture is taken from the latest protected heartbeat projection.</p>
        </Panel>
      </div>
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
              <div className="evidence-stack">
                <Timeline rows={[...data.history].reverse().map((entry, index) => ({
                  id: `${entry.created_at}:${entry.actor_user_id}:${index}`,
                  title: entry.decision,
                  detail: `${shortId(entry.actor_user_id)} · ${entry.rationale}`,
                  at: entry.created_at,
                  tone: timelineTone(entry.decision),
                }))} />
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
              </div>
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
                allowed={data.source_kind !== "security_tool" && hasPermission(principal, PERMISSIONS.findingsApprove) && rationale.trim().length > 0}
                unavailableReason={data.source_kind === "security_tool" ? "independent validation before a finding decision" : rationale.trim() ? PERMISSIONS.findingsApprove : "a decision rationale"}
                onAcknowledged={refresh}
              />
              <CommandButton
                client={client}
                path={COMMAND_PATHS.decideFinding(findingId)}
                payload={{ decision: "rejected", rationale: rationale.trim() }}
                label="Reject finding"
                allowed={data.source_kind !== "security_tool" && hasPermission(principal, PERMISSIONS.findingsApprove) && rationale.trim().length > 0}
                unavailableReason={data.source_kind === "security_tool" ? "independent validation before a finding decision" : rationale.trim() ? PERMISSIONS.findingsApprove : "a decision rationale"}
                onAcknowledged={refresh}
              />
              <CommandButton
                client={client}
                path={COMMAND_PATHS.resolveFinding(findingId)}
                payload={{ rationale: rationale.trim() }}
                label="Resolve finding"
                allowed={data.source_kind !== "security_tool" && hasPermission(principal, PERMISSIONS.findingsResolve) && rationale.trim().length > 0}
                unavailableReason={data.source_kind === "security_tool" ? "independent validation before resolution" : rationale.trim() ? PERMISSIONS.findingsResolve : "a resolution rationale"}
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
      <ResourceView result={findings.result} emptyLabel="No findings have been persisted.">
        {(data) => {
          const elevated = data.filter((finding) => ["critical", "high"].includes(finding.severity.toLowerCase())).length;
          const published = data.filter((finding) => finding.publication_status.toLowerCase().includes("publish")).length;
          const integrityVerified = data.filter((finding) => ["verified", "valid", "bound"].some((value) => finding.evidence_integrity.toLowerCase().includes(value))).length;
          return (
            <>
              <MetricStrip label="Finding summary" values={[
                { label: "Persisted findings", value: count(data.length), note: `${unique(data.map((finding) => finding.category)).length} categories` },
                { label: "Critical / high", value: count(elevated), note: `${percent(data.length ? elevated / data.length : 0)} of register` },
                { label: "Published", value: count(published), note: `${data.length - published} gated or withheld` },
                { label: "Evidence verified", value: `${integrityVerified}/${data.length}`, note: "server integrity state" },
              ]} />
              <div className="panel-grid analytical-grid">
                <Panel title="Risk distribution" meta="server severity" eyebrow="FINDING POSTURE">
                  <DistributionBars rows={distribution(data.map((finding) => finding.severity))} />
                </Panel>
                <Panel title="Lifecycle state" meta="decision + publication" eyebrow="FINDING POSTURE">
                  <DistributionBars rows={distribution([
                    ...data.map((finding) => `state · ${finding.state}`),
                    ...data.map((finding) => `publication · ${finding.publication_status}`),
                  ])} />
                </Panel>
              </div>
              <Panel title="Taxonomy and provenance" meta="normalized evidence" eyebrow="FINDING POSTURE">
                <TagMatrix groups={[
                  { label: "Categories", values: unique(data.map((finding) => finding.category)) },
                  { label: "Sources", values: unique(data.map((finding) => finding.source_kind)) },
                  { label: "Provenance", values: unique(data.map((finding) => finding.evidence_provenance)) },
                  { label: "Execution profiles", values: unique(data.map((finding) => finding.execution_profile)) },
                ]} />
              </Panel>
              <Panel title="Finding register" meta="select for evidence and decision">
                <RecordTable
                  data={data}
                  identityKeys={["finding_id"]}
                  columns={[
                    { key: "finding_id", label: "Finding", mono: true },
                    { key: "category", label: "Category" },
                    { key: "severity", label: "Severity" },
                    { key: "state", label: "State" },
                    { key: "evidence_integrity", label: "Evidence" },
                    { key: "publication_status", label: "Publication" },
                  ]}
                  onSelect={(record) => {
                    const findingId = identity(record, ["finding_id"]);
                    if (findingId) navigateTo({ screen: "findings", entityId: findingId });
                  }}
                />
              </Panel>
            </>
          );
        }}
      </ResourceView>
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
      <ResourceView result={approvals.result} emptyLabel="No approval requests are pending or recorded.">
        {(data) => {
          const pendingCount = data.filter((approval) => approval.status === "pending").length;
          const approvedCount = data.filter((approval) => approval.status === "approved").length;
          const decidedCount = data.length - pendingCount;
          const totalBudget = data.reduce((total, approval) => total + approval.caps.budget_usd, 0);
          const totalAttempts = data.reduce((total, approval) => total + approval.caps.max_attempts_per_run, 0);
          return (
            <>
              <MetricStrip label="Approval summary" values={[
                { label: "Authorization scopes", value: count(data.length), note: `${unique(data.map((approval) => approval.target_id)).length} targets` },
                { label: "Pending review", value: count(pendingCount), note: `${decidedCount} decided` },
                { label: "Approval rate", value: decidedCount ? percent(approvedCount / decidedCount) : "—", note: `${approvedCount} approved` },
                { label: "Budget authorized", value: money(totalBudget), note: `${count(totalAttempts)} maximum attempts` },
              ]} />
              <div className="panel-grid analytical-grid">
                <Panel title="Decision state" meta="human gate" eyebrow="AUTHORIZATION POSTURE">
                  <DistributionBars rows={distribution(data.map((approval) => approval.status))} />
                </Panel>
                <Panel title="Bound safety caps" meta="all returned scopes" eyebrow="AUTHORIZATION POSTURE">
                  <EvidenceGrid values={[
                    { label: "Budget", value: money(totalBudget) },
                    { label: "Maximum attempts", value: count(totalAttempts) },
                    { label: "Peak request rate", value: `${Math.max(...data.map((approval) => approval.caps.target_requests_per_second))}/s` },
                    { label: "Longest timeout", value: `${Math.max(...data.map((approval) => approval.caps.run_timeout_seconds))}s` },
                  ]} />
                  <p className="data-note">These are signed scope limits, not measured spend or execution counts.</p>
                </Panel>
              </div>
              <Panel title="Pending and historical decisions" meta="select exact scope">
                <RecordTable
                  data={data}
                  identityKeys={["request_id", "approval_id"]}
                  columns={[
                    { key: "request_id", label: "Request", mono: true },
                    { key: "status", label: "Status" },
                    { key: "target_id", label: "Target", mono: true },
                    { key: "scope_hash", label: "Operation hash", mono: true },
                    { key: "launcher_user_id", label: "Launcher", mono: true },
                    { key: "expires_at", label: "Expires", mono: true },
                  ]}
                  onSelect={(record) => {
                    const id = identity(record, ["request_id", "approval_id"]);
                    if (id) navigateTo({ screen: "approvals", entityId: id });
                  }}
                />
              </Panel>
            </>
          );
        }}
      </ResourceView>
      {entityId && !selected && approvals.result.state !== "loading" && (
        <Panel title="Approval detail"><StateNotice state="empty" detail="That approval is not in the organization-scoped response." /></Panel>
      )}
      {selected && requestId && (
        <Panel title="Exact authorization scope" meta={requestId}>
          <EvidenceGrid values={[
            { label: "Budget cap", value: money(selected.caps.budget_usd) },
            { label: "Attempt cap", value: count(selected.caps.max_attempts_per_run) },
            { label: "Request rate", value: `${selected.caps.target_requests_per_second}/s` },
            { label: "Run timeout", value: `${selected.caps.run_timeout_seconds}s` },
          ]} />
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

type SimpleResourceName = "coverage" | "resilience";
type ResourceScreenName = SimpleResourceName | "traces" | "costs";

function CoverageScreen({ client }: { client: ApiClient }) {
  const controller = useResource<CoverageReadModel[]>(client, RESOURCE_PATHS.coverage, decodeCoverage);
  return (
    <div className="screen-stack">
      <ScreenHeading title="Coverage" detail="Only server-derived, hash-verified and nonce-deduplicated coverage is shown." />
      <ResourceView result={controller.result} emptyLabel="No verified coverage records are available.">
        {(data) => {
          const verified = data.reduce((total, record) => total + record.verified_attempt_count, 0);
          const cases = data.reduce((total, record) => total + record.total_case_count, 0);
          const covered = data.filter((record) => record.covered).length;
          const verdicts = new Map<string, number>();
          for (const record of data) {
            for (const [verdict, rawCount] of Object.entries(record.verdict_counts)) {
              if (typeof rawCount === "number") verdicts.set(verdict, (verdicts.get(verdict) ?? 0) + rawCount);
            }
          }
          return (
            <>
              <MetricStrip label="Coverage summary" values={[
                { label: "Verified attempts", value: count(verified), note: `${count(cases)} total cases` },
                { label: "Case execution", value: cases ? percent(verified / cases) : "—", note: "verified / total" },
                { label: "Covered versions", value: `${covered}/${data.length}`, note: "server coverage decision" },
                { label: "Mapped controls", value: count(unique(data.flatMap((record) => [...record.owasp_web, ...record.owasp_llm])).length), note: "OWASP Web + LLM" },
              ]} />
              <div className="panel-grid analytical-grid">
                <Panel title="Execution by target version" meta="verified / total" eyebrow="COVERAGE POSTURE">
                  <DistributionBars rows={data.map((record) => ({
                    label: record.target_version,
                    value: record.verified_attempt_count,
                    display: `${record.verified_attempt_count} / ${record.total_case_count}`,
                    tone: record.covered ? "success" as const : "queued" as const,
                  }))} />
                </Panel>
                <Panel title="Verdict distribution" meta="verified attempts" eyebrow="COVERAGE POSTURE">
                  {verdicts.size > 0
                    ? <DistributionBars rows={[...verdicts.entries()].map(([label, value]) => ({ label, value, tone: toneFor(label) }))} />
                    : <StateNotice state="empty" detail="No verdict counts are present in the coverage projection." />}
                </Panel>
              </div>
              <Panel title="Taxonomy coverage" meta="deduplicated mappings" eyebrow="COVERAGE POSTURE">
                <TagMatrix groups={[
                  { label: "Classifications", values: unique(data.flatMap((record) => record.classifications)) },
                  { label: "OWASP Web Top 10", values: unique(data.flatMap((record) => record.owasp_web)) },
                  { label: "OWASP LLM Top 10", values: unique(data.flatMap((record) => record.owasp_llm)) },
                  { label: "Evidence provenance", values: unique(data.map((record) => record.evidence_provenance)) },
                ]} />
              </Panel>
              <Panel title="Coverage ledger" meta="authoritative snapshots">
                <RecordTable
                  data={data}
                  identityKeys={["target_version"]}
                  columns={[
                    { key: "target_version", label: "Target version", mono: true },
                    { key: "verified_attempt_count", label: "Verified", mono: true },
                    { key: "total_case_count", label: "Cases", mono: true },
                    { key: "category_count", label: "Categories", mono: true },
                    { key: "execution_profile", label: "Profile" },
                    { key: "covered", label: "Coverage decision" },
                    { key: "as_of", label: "As of", mono: true },
                  ]}
                />
              </Panel>
            </>
          );
        }}
      </ResourceView>
    </div>
  );
}

function ResilienceScreen({ client }: { client: ApiClient }) {
  const controller = useResource<ResilienceReadModel[]>(client, RESOURCE_PATHS.resilience, decodeResilience);
  return (
    <div className="screen-stack">
      <ScreenHeading title="Resilience" detail="Version and regression history is read from the authoritative projection." />
      <ResourceView result={controller.result} emptyLabel="No resilience or regression history is recorded.">
        {(data) => {
          const passing = data.filter((record) => timelineTone(record.status) === "success").length;
          const failing = data.filter((record) => timelineTone(record.status) === "failure").length;
          const latest = [...data].sort((left, right) => Date.parse(right.recorded_at) - Date.parse(left.recorded_at))[0];
          return (
            <>
              <MetricStrip label="Resilience summary" values={[
                { label: "Regression checks", value: count(data.length), note: `${unique(data.map((record) => record.version)).length} target versions` },
                { label: "Passing", value: count(passing), note: `${percent(data.length ? passing / data.length : 0)} of history` },
                { label: "Regressions", value: count(failing), note: "failed or degraded states" },
                { label: "Latest version", value: latest?.version ?? "—", note: latest?.status ?? "No status" },
              ]} />
              <div className="panel-grid analytical-grid">
                <Panel title="Regression posture" meta="all recorded checks" eyebrow="RESILIENCE POSTURE">
                  <DistributionBars rows={distribution(data.map((record) => record.status))} />
                </Panel>
                <Panel title="Version activity" meta="checks per version" eyebrow="RESILIENCE POSTURE">
                  <DistributionBars rows={distribution(data.map((record) => record.version))} />
                </Panel>
              </div>
              <Panel title="Regression timeline" meta="newest first" eyebrow="RESILIENCE POSTURE">
                <Timeline rows={[...data]
                  .sort((left, right) => Date.parse(right.recorded_at) - Date.parse(left.recorded_at))
                  .map((record) => ({
                    id: `${record.regression_id}:${record.version}:${record.recorded_at}`,
                    title: `${record.version} · ${record.status}`,
                    detail: record.regression_id,
                    at: record.recorded_at,
                    tone: timelineTone(record.status),
                  }))} />
              </Panel>
              <Panel title="Resilience ledger" meta="authoritative history">
                <RecordTable
                  data={data}
                  identityKeys={["regression_id", "version"]}
                  columns={[
                    { key: "version", label: "Version", mono: true },
                    { key: "regression_id", label: "Regression", mono: true },
                    { key: "status", label: "Status" },
                    { key: "recorded_at", label: "Recorded", mono: true },
                  ]}
                />
              </Panel>
            </>
          );
        }}
      </ResourceView>
    </div>
  );
}

export function SimpleResourceScreen({ client, resource }: { client: ApiClient; resource: ResourceScreenName }) {
  switch (resource) {
    case "coverage":
      return <CoverageScreen client={client} />;
    case "resilience":
      return <ResilienceScreen client={client} />;
    case "traces":
      return <TracesScreen client={client} />;
    case "costs":
      return <CostsScreen client={client} />;
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
  const [requestsPerSecond, setRequestsPerSecond] = useState("1");
  const [timeoutSeconds, setTimeoutSeconds] = useState("900");
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
      <div className="panel-grid analytical-grid target-detail-grid">
        <div>
          <p className="field-label">Maximum safety envelope</p>
          <EvidenceGrid values={[
            { label: "Budget", value: money(selected.safety_caps.budget_usd) },
            { label: "Attempts", value: count(selected.safety_caps.max_attempts_per_run) },
            { label: "Request rate", value: `${selected.safety_caps.target_requests_per_second}/s` },
            { label: "Timeout", value: `${selected.safety_caps.run_timeout_seconds}s` },
          ]} />
        </div>
        <div>
          <p className="field-label">Attack surface posture</p>
          {surfaces.length > 0
            ? <DistributionBars rows={distribution(surfaces.map((surface) => surface.enabled ? `enabled · ${surface.risk}` : `disabled · ${surface.risk}`))} />
            : <StateNotice state="empty" detail="No versioned surfaces are attached." />}
        </div>
      </div>
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
  const records = targets.result.data ?? [];
  const surfaces = records.flatMap((target) => target.surfaces);
  const enabledSurfaces = surfaces.filter((surface) => surface.enabled).length;
  const readyTargets = records.filter((target) => target.lifecycle.toLowerCase().includes("ready")).length;
  const credentialedTargets = records.filter((target) => target.credential_configured).length;
  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Targets"
        detail="Only persisted immutable target and attack-surface versions may be selected for dispatch."
      />
      {records.length > 0 && (
        <>
          <MetricStrip label="Target summary" values={[
            { label: "Target versions", value: count(records.length), note: `${unique(records.map((target) => target.target_id)).length} logical targets` },
            { label: "Dispatch ready", value: `${readyTargets}/${records.length}`, note: "persisted lifecycle state" },
            { label: "Enabled surfaces", value: `${enabledSurfaces}/${surfaces.length}`, note: `${unique(surfaces.map((surface) => surface.kind)).length} surface kinds` },
            { label: "Credentials bound", value: `${credentialedTargets}/${records.length}`, note: "configuration presence only" },
          ]} />
          <div className="panel-grid analytical-grid">
            <Panel title="Target lifecycle" meta="immutable versions" eyebrow="TARGET POSTURE">
              <DistributionBars rows={distribution(records.map((target) => target.lifecycle))} />
            </Panel>
            <Panel title="Surface risk" meta="registered attack surfaces" eyebrow="TARGET POSTURE">
              {surfaces.length > 0
                ? <DistributionBars rows={distribution(surfaces.map((surface) => surface.risk))} />
                : <StateNotice state="empty" detail="No attack surfaces are registered." />}
            </Panel>
          </div>
          <Panel title="Dispatch topology" meta="registered capabilities" eyebrow="TARGET POSTURE">
            <TagMatrix groups={[
              { label: "Environments", values: unique(records.map((target) => target.environment)) },
              { label: "Adapters", values: unique(records.map((target) => target.adapter_kind)) },
              { label: "Protocols", values: unique(surfaces.map((surface) => surface.protocol)) },
              { label: "Trust boundaries", values: unique(surfaces.map((surface) => surface.trust_boundary)) },
            ]} />
          </Panel>
        </>
      )}
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
      {(data) => {
        const ordered = [...data].sort((left, right) => right.cursor - left.cursor);
        return (
          <div className="evidence-stack">
            <EvidenceGrid values={[
              { label: "Events", value: count(data.length) },
              { label: "Latest cursor", value: String(ordered[0]?.cursor ?? "—") },
              { label: "Event types", value: count(unique(data.map((event) => event.event_type)).length) },
              { label: "Human actors", value: count(unique(data.flatMap((event) => event.actor_user_id ? [event.actor_user_id] : [])).length) },
            ]} />
            <div className="panel-grid analytical-grid audit-grid">
              <DistributionBars rows={distribution(data.map((event) => event.event_type))} />
              <Timeline rows={ordered.slice(0, 8).map((event) => ({
                id: String(event.cursor),
                title: event.event_type,
                detail: `${event.aggregate_type} · ${shortId(event.aggregate_id)}`,
                at: event.created_at,
                tone: timelineTone(event.event_type),
              }))} />
            </div>
            <RecordTable
              data={ordered}
              identityKeys={["cursor"]}
              columns={[
                { key: "cursor", label: "Cursor", mono: true },
                { key: "event_type", label: "Event" },
                { key: "actor_user_id", label: "Actor", mono: true },
                { key: "aggregate_id", label: "Resource", mono: true },
                { key: "created_at", label: "Occurred", mono: true },
              ]}
            />
          </div>
        );
      }}
    </ResourceView>
  );
}

export function ConfigurationScreen({ client, principal }: ScreenProps) {
  const configuration = useResource<ConfigurationReadModel>(
    client,
    RESOURCE_PATHS.configuration,
    decodeConfiguration,
  );
  const components = useResource<ComponentReadModel[]>(
    client,
    RESOURCE_PATHS.components,
    decodeComponents,
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
  const componentRecords = components.result.data ?? [];
  const operationalComponents = componentRecords.filter((component) => component.availability === "operational and evidenced").length;
  const configurationKeys = configRecord ? Object.keys(configRecord.configuration) : [];
  const workbench = configRecord && isJsonRecord(configRecord.configuration.security_workbench)
    ? configRecord.configuration.security_workbench
    : null;
  const workbenchCapabilities = workbench && Array.isArray(workbench.capabilities)
    ? workbench.capabilities.filter(isJsonRecord)
    : [];
  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Configuration"
        detail="Immutable effective configuration, validation and publication acknowledgements remain server-owned."
      />
      {configRecord && (
        <MetricStrip label="Configuration summary" values={[
          { label: "Snapshot", value: shortId(configRecord.snapshot_id), note: `version ${configRecord.version}` },
          { label: "Publication state", value: configRecord.status, note: configRecord.published_at },
          { label: "Configuration areas", value: count(configurationKeys.length), note: configurationKeys.slice(0, 3).join(" · ") || "No top-level keys" },
          { label: "Components/tools evidenced", value: `${operationalComponents}/${componentRecords.length}`, note: components.result.state },
        ]} />
      )}
      <div className="panel-grid analytical-grid">
        <Panel title="Configuration topology" meta={configRecord ? `v${configRecord.version}` : configuration.result.state} eyebrow="RUNTIME POSTURE">
          {configRecord ? (
            <TagMatrix groups={[
              { label: "Effective areas", values: configurationKeys },
              { label: "Publication status", values: [configRecord.status] },
              { label: "Publisher", values: [shortId(configRecord.published_by)] },
              { label: "Snapshot", values: [shortId(configRecord.snapshot_id)] },
            ]} />
          ) : (
            <ResourceView result={configuration.result} emptyLabel="No configuration snapshot is published.">{() => null}</ResourceView>
          )}
        </Panel>
        <Panel title="Component and tool status" meta="heartbeat + catalog verification" eyebrow="RUNTIME POSTURE">
          {componentRecords.length > 0
            ? <DistributionBars rows={distribution(componentRecords.map((component) => component.availability))} />
            : <ResourceView result={components.result} emptyLabel="No runtime components are registered.">{() => null}</ResourceView>}
          {componentRecords.length > 0 && <p className="data-note">{unique(componentRecords.map((component) => component.environment)).join(" · ")}</p>}
        </Panel>
      </div>
      <Panel title="LLM security workbench" meta="Burp-style workflow · Headshot controls" eyebrow="GOVERNED TESTING">
        {workbenchCapabilities.length > 0 ? (
          <RecordTable
            data={workbenchCapabilities}
            identityKeys={["workflow"]}
            columns={[
              { key: "workflow", label: "Workflow" },
              { key: "headshot_control", label: "Headshot control" },
              { key: "state", label: "State" },
              { key: "llm_focus", label: "LLM focus" },
              { key: "safeguard", label: "Safety boundary" },
              { key: "evidence", label: "Evidence" },
            ]}
          />
        ) : (
          <StateNotice state="empty" detail="No security-workbench capability map is published." />
        )}
        <p className="data-note">This is a governed LLM security workbench, not a claim that the commercial PortSwigger Burp Suite product is installed.</p>
      </Panel>
      <Panel title="Security engines" meta="native artifacts + runtime controls" eyebrow="EVIDENCED TOOLING">
        {componentRecords.filter((component) => component.kind.startsWith("security-tool:")).length > 0 ? (
          <RecordTable
            data={componentRecords.filter((component) => component.kind.startsWith("security-tool:"))}
            identityKeys={["component_id"]}
            columns={[
              { key: "name", label: "Tool" },
              { key: "version", label: "Version", mono: true },
              { key: "availability", label: "Availability" },
              { key: "operational_scope", label: "Operational scope" },
              { key: "adapter_only_scope", label: "Adapter-only scope" },
              { key: "owasp_llm", label: "OWASP LLM" },
              { key: "target_access", label: "Tool target access", mono: true },
            ]}
          />
        ) : (
          <ResourceView result={components.result} emptyLabel="No security-tool records are available.">{() => null}</ResourceView>
        )}
      </Panel>
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
