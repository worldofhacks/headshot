import { useCallback, useEffect, useState } from "react";

import type { ApiClient } from "../api/client";
import {
  isJsonRecord,
  type JsonRecord,
  type Principal,
} from "../api/contracts";
import { COMMAND_PATHS, RESOURCE_PATHS } from "../api/paths";
import {
  decodeApprovals,
  decodeApprovalDetail,
  decodeAttempts,
  decodeAuditHistory,
  decodeBirdseye,
  decodeCampaigns,
  decodeComponents,
  decodeConfiguration,
  decodeEvidence,
  decodeFinding,
  decodeFindings,
  decodeReports,
  decodeTargetCatalog,
  decodeTargets,
} from "../api/read-models";
import { AdversarialText } from "../components/AdversarialText";
import { AgentActivityPanel } from "../components/AgentActivityPanel";
import { Birdseye } from "../components/Birdseye";
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
import {
  LIVE_RESOURCE_POLL_INTERVAL_MS,
  useResource,
} from "../hooks/useResource";
import { navigateTo } from "../router";
import {
  PERMISSIONS,
  type ApprovalReadModel,
  type ApprovalDetailReadModel,
  type AttemptReadModel,
  type AuditReadModel,
  type BirdseyeAttentionReadModel,
  type BirdseyeSnapshotReadModel,
  type CampaignReadModel,
  type ComponentReadModel,
  type ConfigurationReadModel,
  type EvidenceReadModel,
  type FindingDetailReadModel,
  type FindingReadModel,
  type FindingVerificationReadModel,
  type ReportReadModel,
  type TargetCatalogEntryReadModel,
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

const isPublished = (value: string) => {
  const normalized = value.toLowerCase();
  return normalized === "published" || normalized === "published_after_human_approval";
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
                  { key: "executed_at", label: "Executed", mono: true, timestamp: true },
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
  const targets = useResource<TargetReadModel[]>(
    client,
    RESOURCE_PATHS.targets,
    decodeTargets,
  );
  const birdseye = useResource<BirdseyeSnapshotReadModel>(
    client,
    RESOURCE_PATHS.birdseye,
    decodeBirdseye,
  );
  const [liveView, setLiveView] = useState<"birdseye" | "attempts">(
    entityId ? "attempts" : "birdseye",
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
    targets.refresh();
    birdseye.refresh();
  }, [campaigns.refresh, components.refresh, targets.refresh, birdseye.refresh]);
  const events = useConsoleEvents(getToken, reconcile);
  const [rerunNonce, setRerunNonce] = useState(() => `live-${globalThis.crypto.randomUUID()}`);
  const currentTarget = effectiveCampaign
    ? targets.result.data?.find((target) => (
        target.target_id === effectiveCampaign.target_id && target.campaign_template !== null
      )) ?? null
    : null;
  const rerunTemplate = currentTarget?.campaign_template ?? null;
  // A persisted campaign is an immutable historical scope. A rerun must use the current
  // server-prepared target/corpus template, bounded by both that target and the prior run's
  // operator-selected budget/rate/timeout. A fresh nonce prevents authorization replay.
  const preparedScope = effectiveCampaign && rerunTemplate
    && rerunTemplate.maximum_caps.max_attempts_per_run >= rerunTemplate.case_count
    ? {
        target_id: rerunTemplate.target_id,
        target_version: rerunTemplate.target_version,
        surface_id: rerunTemplate.surface_id,
        surface_version: rerunTemplate.surface_version,
        corpus_id: rerunTemplate.corpus_id,
        corpus_hash: rerunTemplate.corpus_hash,
        execution_profile: rerunTemplate.execution_profile,
        caps: {
          budget_usd: Math.min(
            effectiveCampaign.caps.budget_usd,
            rerunTemplate.maximum_caps.budget_usd,
          ),
          max_attempts_per_run: rerunTemplate.case_count,
          target_requests_per_second: Math.min(
            effectiveCampaign.caps.target_requests_per_second,
            rerunTemplate.maximum_caps.target_requests_per_second,
          ),
          run_timeout_seconds: Math.min(
            effectiveCampaign.caps.run_timeout_seconds,
            rerunTemplate.maximum_caps.run_timeout_seconds,
          ),
        },
        run_nonce: rerunNonce,
        expires_in_seconds: 900,
      }
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
  const campaignAbortable = Boolean(
    effectiveCampaign && ["queued", "running"].includes(effectiveCampaign.state),
  );

  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Live operations"
        detail="Campaign, queue, component and ordered event state comes from protected server projections."
      />
      <div className="view-switcher" role="tablist" aria-label="Live operations view">
        <button
          type="button"
          role="tab"
          aria-selected={liveView === "birdseye"}
          className={liveView === "birdseye" ? "active" : undefined}
          onClick={() => setLiveView("birdseye")}
        >
          Birdseye
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={liveView === "attempts"}
          className={liveView === "attempts" ? "active" : undefined}
          onClick={() => setLiveView("attempts")}
        >
          Attempt stream
        </button>
      </div>
      {liveView === "birdseye" ? (
        <ResourceView
          result={birdseye.result}
          emptyLabel="No authoritative Birdseye snapshot is available."
        >
          {(snapshot) => (
            <Birdseye
              snapshot={snapshot}
              stream={events}
              onOpenAttention={(item: BirdseyeAttentionReadModel) => {
                if (item.kind === "approval") {
                  navigateTo({ screen: "approvals", entityId: item.record_id });
                } else if (item.kind === "finding") {
                  navigateTo({ screen: "findings", entityId: item.record_id });
                } else if (item.kind === "integrity") {
                  navigateTo({ screen: "live", entityId: item.record_id });
                  setLiveView("attempts");
                }
              }}
            />
          )}
        </ResourceView>
      ) : (
        <>
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
                { key: "created_at", label: "Created", mono: true, timestamp: true },
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
              label="Request rerun authorization"
              allowed={hasPermission(principal, PERMISSIONS.campaignLaunch)}
              unavailableReason={PERMISSIONS.campaignLaunch}
              onAcknowledged={() => {
                setRerunNonce(`live-${globalThis.crypto.randomUUID()}`);
                campaigns.refresh();
              }}
            />
          ) : (
            <MissingCommand
              label="Request rerun authorization"
              dependency="a current full-scan target template"
            />
          )}
          {selectedCampaignId ? (
            <CommandButton
              client={client}
              path={COMMAND_PATHS.abortCampaign(selectedCampaignId)}
              payload={{ reason: "operator_abort" }}
              label="Abort selected campaign"
              allowed={campaignAbortable && hasPermission(principal, PERMISSIONS.campaignAbort)}
              unavailableReason={campaignAbortable
                ? PERMISSIONS.campaignAbort
                : "a queued or running campaign"}
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
                  { key: "heartbeat_at", label: "Heartbeat", mono: true, timestamp: true },
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
                {data.map((event, index) => {
                  const aggregateType = isJsonRecord(event.data)
                    && typeof event.data.aggregate_type === "string"
                    ? event.data.aggregate_type
                    : null;
                  return (
                    <details className="event-record" key={`${event.cursor ?? "event"}:${index}`}>
                      <summary>
                        <span>
                          <strong>{event.event}</strong>
                          {aggregateType && <small>{aggregateType}</small>}
                        </span>
                        <span className="mono">
                          {event.cursor === null ? "no cursor" : `cursor ${event.cursor}`}
                        </span>
                      </summary>
                      <AdversarialText>{JSON.stringify(event.data, null, 2)}</AdversarialText>
                    </details>
                  );
                })}
              </div>
            )}
          </ResourceView>
        </Panel>
      </div>
        </>
      )}
      <AgentActivityPanel
        client={client}
        campaignRunId={selectedCampaignId}
        title="Selected campaign agents"
      />
    </div>
  );
}

function VerificationChain({
  verification,
}: {
  verification: FindingVerificationReadModel;
}) {
  if (verification.availability === "unavailable") {
    return (
      <StateNotice
        state="unavailable"
        reason={verification.reason_code ?? "verification_unavailable"}
        detail="This source has no campaign transcript chain. No evidence has been inferred."
      />
    );
  }
  const judge = verification.judge;
  const attackCase = verification.attack_case;
  const integrity = verification.integrity;
  const dispositionTone = judge ? toneFor(judge.state) : "queued";
  return (
    <div className="evidence-stack" aria-label="Full verification chain">
      <p className="field-label">Attack case and deterministic basis</p>
      <EvidenceGrid values={[
        { label: "Case", value: attackCase?.case_id ?? "Unavailable" },
        { label: "Classification", value: attackCase?.attack_class ?? "Unavailable" },
        {
          label: "Judge disposition",
          value: judge?.state ?? "Unavailable",
          tone: dispositionTone === "brand" ? undefined : dispositionTone,
        },
        { label: "Basis source", value: judge?.confirmation_source ?? "Unavailable" },
      ]} />
      {attackCase && (
        <RecordDetails
          data={attackCase}
          preferredKeys={[
            "case_id",
            "category",
            "attack_class",
            "owasp_mappings",
            "oracle_expectation",
            "case_content_sha256",
            "corpus_reconciliation",
          ]}
        />
      )}
      {verification.input_sequence.length > 0 && (
        <div>
          <p className="field-label">Input sequence · identifiers redacted</p>
          {verification.input_sequence.map((turn, index) => (
            <AdversarialText key={index}>{`${index + 1}. ${turn}`}</AdversarialText>
          ))}
        </div>
      )}
      {verification.attack_attempt && (
        <div>
          <p className="field-label">Attack attempt · identifiers redacted</p>
          <AdversarialText>{JSON.stringify(verification.attack_attempt, null, 2)}</AdversarialText>
        </div>
      )}
      {verification.request_transcript && (
        <div>
          <p className="field-label">Request transcript · identifiers redacted</p>
          <AdversarialText>{JSON.stringify(verification.request_transcript, null, 2)}</AdversarialText>
        </div>
      )}
      {verification.response_transcript && (
        <div>
          <p className="field-label">Response transcript · identifiers redacted</p>
          <AdversarialText>{verification.response_transcript}</AdversarialText>
        </div>
      )}
      {judge && (
        <div>
          <p className="field-label">Independent Judge rationale</p>
          <RecordDetails
            data={judge}
            preferredKeys={[
              "state",
              "confidence",
              "confirmation_source",
              "oracle_refs",
              "canary_refs",
              "reason_codes",
              "rationale",
              "rationale_availability",
              "rationale_detail",
              "error_code",
            ]}
          />
        </div>
      )}
      {verification.minimal_reproduction.length > 0 && (
        <div>
          <p className="field-label">Minimal reproduction · draft only</p>
          <ol>
            {verification.minimal_reproduction.map((step, index) => (
              <li key={index}><AdversarialText>{step}</AdversarialText></li>
            ))}
          </ol>
        </div>
      )}
      {verification.regression && (
        <div>
          <p className="field-label">Regression admission</p>
          <RecordDetails
            data={verification.regression}
            preferredKeys={[
              "state",
              "reason_codes",
              "reproduction_attempted",
              "deterministic_reproduction",
              "passes_for_right_reason",
              "human_approved",
              "admitted",
            ]}
          />
        </div>
      )}
      {integrity && (
        <div>
          <p className="field-label">Integrity and reconciliation</p>
          <RecordDetails
            data={integrity}
            preferredKeys={[
              "evidence_record",
              "finding_link",
              "stored_content_sha256",
              "finding_link_sha256",
              "recomputed_content_sha256",
              "observability_reconciliation",
              "observability_detail",
            ]}
          />
        </div>
      )}
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
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
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
            <VerificationChain verification={data.verification} />
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
                    { key: "created_at", label: "Occurred", mono: true, timestamp: true },
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
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  const selectedFinding = entityId
    ? findings.result.data?.find((finding) => finding.finding_id === entityId) ?? null
    : null;
  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Findings"
        detail="Persisted findings remain bound to server verdict, evidence and publication history."
      />
      <ResourceView result={findings.result} emptyLabel="No findings have been persisted.">
        {(data) => {
          const elevated = data.filter((finding) => ["critical", "high"].includes(finding.severity.toLowerCase())).length;
          const published = data.filter((finding) => isPublished(finding.publication_status)).length;
          const categories = data.map((finding) => finding.category ?? "unavailable");
          const integrityVerified = data.filter(
            (finding) => finding.evidence_integrity === "verified",
          ).length;
          return (
            <>
              <MetricStrip label="Finding summary" values={[
                { label: "Persisted findings", value: count(data.length), note: `${unique(categories).length} category labels` },
                { label: "Critical / high", value: count(elevated), note: `${percent(data.length ? elevated / data.length : 0)} of register` },
                { label: "Published after approval", value: count(published), note: `${data.length - published} draft, gated, or withheld` },
                { label: "Evidence verified", value: `${integrityVerified}/${data.length}`, note: "record or artifact binding" },
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
                  { label: "Categories", values: unique(categories) },
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
      <AgentActivityPanel
        client={client}
        campaignRunId={selectedFinding?.campaign_run_id}
        title={selectedFinding ? "Finding verification agents" : "Recent finding agents"}
      />
    </div>
  );
}

function ApprovalVerificationDetail({
  client,
  requestId,
  onCampaignRunId,
}: {
  client: ApiClient;
  requestId: string;
  onCampaignRunId: (campaignRunId: string | null) => void;
}) {
  const detail = useResource<ApprovalDetailReadModel>(
    client,
    RESOURCE_PATHS.approval(requestId),
    decodeApprovalDetail,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  const campaignRunId = detail.result.data?.campaign_run_id;
  useEffect(() => {
    if (detail.result.data !== null) {
      onCampaignRunId(campaignRunId ?? null);
    }
  }, [campaignRunId, detail.result.data, onCampaignRunId]);
  return (
    <div className="evidence-stack">
      <p className="field-label">Post-run verification chain</p>
      <ResourceView
        result={detail.result}
        emptyLabel="No organization-scoped approval detail was returned."
      >
        {(data) => data.verification_chain.length > 0 ? (
          <>
            <EvidenceGrid values={[
              { label: "Campaign", value: data.campaign_run_id ?? "Not consumed" },
              { label: "Verified findings", value: count(data.verification_chain.length) },
              { label: "Authorization", value: data.status },
              { label: "Scope hash", value: shortId(data.scope_hash) },
            ]} />
            {data.verification_chain.map((verification) => (
              <VerificationChain
                key={`${verification.finding_id}:${verification.attempt_id ?? "unavailable"}`}
                verification={verification}
              />
            ))}
          </>
        ) : (
          <StateNotice
            state="empty"
            detail="This authorization has no confirmed finding evidence. Pending approvals are intentionally pre-evidence."
          />
        )}
      </ResourceView>
    </div>
  );
}

export function ApprovalsScreen({ client, principal, entityId }: ScreenProps) {
  const approvals = useResource<ApprovalReadModel[]>(
    client,
    RESOURCE_PATHS.approvals,
    decodeApprovals,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  const records = approvals.result.data ?? [];
  const selected = entityId
    ? records.find((record) => identity(record, ["request_id", "approval_id"]) === entityId) ?? null
    : null;
  const requestId = selected ? identity(selected, ["request_id", "approval_id"]) : null;
  const [selectedCampaignRunId, setSelectedCampaignRunId] = useState<
    string | null | undefined
  >(undefined);
  useEffect(() => {
    setSelectedCampaignRunId(undefined);
  }, [requestId]);
  const launcher = selected && typeof selected.launcher_user_id === "string"
    ? selected.launcher_user_id
    : null;
  const distinctHuman = launcher === null || launcher !== principal.user_id;
  const canApproveIdentity = distinctHuman;
  const isLauncher = launcher !== null && launcher === principal.user_id;
  const actionable = Boolean(selected && !selected.expired && !selected.consumed);
  const pending = selected?.status === "pending" && actionable;
  const approved = selected?.status === "approved" && actionable;
  const canAuthorize =
    hasPermission(principal, PERMISSIONS.campaignAuthorize) && canApproveIdentity && pending;

  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Approvals"
        detail="Decisions bind to an exact server operation hash. Queue completion is not displayed as human approval."
      />
      <ResourceView result={approvals.result} emptyLabel="No approval requests are pending or recorded.">
        {(data) => {
          const pendingCount = data.filter((approval) => approval.status === "pending").length;
          const decidedCount = data.length - pendingCount;
          const totalBudget = data.reduce((total, approval) => total + approval.caps.budget_usd, 0);
          const totalAttempts = data.reduce((total, approval) => total + approval.caps.max_attempts_per_run, 0);
          return (
            <>
              <MetricStrip label="Approval summary" values={[
                { label: "Authorization scopes", value: count(data.length), note: `${unique(data.map((approval) => approval.target_id)).length} targets` },
                { label: "Pending review", value: count(pendingCount), note: `${decidedCount} decided` },
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
                    { key: "expires_at", label: "Expires", mono: true, timestamp: true },
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
          {selected.hosted_run ? (
            <div className="evidence-stack">
              <p className="field-label">Exact hosted four-role binding</p>
              <StateNotice
                state="ready"
                detail="This approval binds the immutable hosted configuration, generation policy, and provider call envelope shown below. It contains no credential reference."
              />
              <EvidenceGrid values={[
                {
                  label: "Provider call cap",
                  value: count(selected.hosted_run.provider_model_call_limit),
                },
                {
                  label: "Provider spend cap",
                  value: `$${selected.hosted_run.provider_model_spend_limit_usd}`,
                },
                {
                  label: "Provider retries",
                  value: count(selected.hosted_run.provider_max_retries),
                },
                {
                  label: "Provider timeout",
                  value: `${selected.hosted_run.provider_timeout_seconds}s`,
                },
              ]} />
              <RecordDetails
                data={selected.hosted_run}
                preferredKeys={[
                  "configuration_set_sha256",
                  "generation_policy_sha256",
                  "session_generation",
                  "provider_model_call_limit",
                  "provider_model_spend_limit_usd",
                  "provider_max_retries",
                  "provider_max_concurrency",
                  "provider_timeout_seconds",
                ]}
              />
            </div>
          ) : (
            <StateNotice
              state="empty"
              detail="This authorization does not permit hosted role model calls."
            />
          )}
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
              "self_approval_override",
              "expires_at",
              "expired",
              "consumed",
            ]}
          />
          <ApprovalVerificationDetail
            client={client}
            requestId={requestId}
            onCampaignRunId={setSelectedCampaignRunId}
          />
          {selected.expired && (
            <StateNotice
              state="unavailable"
              reason="authorization_expired"
              detail="This authorization window has expired and cannot be decided or launched."
            />
          )}
          {selected.consumed && (
            <StateNotice
              state="unavailable"
              reason="authorization_consumed"
              detail="This authorization has already been consumed by a campaign."
            />
          )}
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
                  : canApproveIdentity
                    ? PERMISSIONS.campaignAuthorize
                    : "a distinct approver"
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
              allowed={hasPermission(principal, PERMISSIONS.campaignLaunch) && approved && isLauncher}
              unavailableReason={
                !approved
                  ? "an approved authorization request"
                  : isLauncher
                    ? PERMISSIONS.campaignLaunch
                    : "the persisted campaign launcher"
              }
              onAcknowledged={approvals.refresh}
            />
          </div>
        </Panel>
      )}
      {!selected && !entityId && (
        <AgentActivityPanel
          client={client}
          title="Recent authorization and review agents"
        />
      )}
      {selected && selectedCampaignRunId && (
        <AgentActivityPanel
          client={client}
          campaignRunId={selectedCampaignRunId}
          title="Selected authorization agents"
        />
      )}
      {selected && selectedCampaignRunId === null && (
        <Panel title="Selected authorization agents" eyebrow="AGENT EXECUTION LEDGER">
          <StateNotice
            state="empty"
            detail="No campaign has consumed this authorization, so it has no scoped agent executions."
          />
        </Panel>
      )}
    </div>
  );
}

export function ReportsScreen({ client, entityId }: ScreenProps) {
  const reports = useResource<ReportReadModel[]>(
    client,
    RESOURCE_PATHS.reports,
    decodeReports,
  );
  const selected = entityId
    ? reports.result.data?.find((report) => report.report_id === entityId) ?? null
    : null;
  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Reports"
        eyebrow="DOCUMENTATION AGENT DRAFTS"
        detail="Schema-validated vulnerability reports remain unpublished until a separate human decision. Every report below is reconciled to immutable evidence before display."
      />
      <ResourceView result={reports.result} emptyLabel="No vulnerability reports have been drafted.">
        {(data) => {
          const gated = data.filter(
            (report) => report.publication_state === "blocked_pending_human_approval",
          ).length;
          const admitted = data.filter((report) => report.regression?.admitted === true).length;
          return (
            <>
              <MetricStrip label="Report summary" values={[
                { label: "Validated drafts", value: count(data.length), note: "Documentation output, never publication authority" },
                { label: "Human-gated", value: count(gated), note: `${data.length - gated} draft unpublished` },
                { label: "Regression admitted", value: count(admitted), note: "Requires deterministic replay and human approval" },
                { label: "Integrity verified", value: `${data.filter((report) => report.report_integrity === "verified").length}/${data.length}`, note: "Report, lineage and reproduction hash" },
              ]} />
              <Panel title="Report register" meta="select a report for the full chain">
                <RecordTable
                  data={data}
                  identityKeys={["report_id"]}
                  columns={[
                    { key: "report_id", label: "Report", mono: true },
                    { key: "finding_id", label: "Finding", mono: true },
                    { key: "severity", label: "Severity" },
                    { key: "category", label: "Category" },
                    { key: "status", label: "Status" },
                    { key: "publication_state", label: "Publication gate" },
                    { key: "report_integrity", label: "Integrity" },
                  ]}
                  onSelect={(record) => {
                    const reportId = identity(record, ["report_id"]);
                    if (reportId) navigateTo({ screen: "reports", entityId: reportId });
                  }}
                />
              </Panel>
            </>
          );
        }}
      </ResourceView>
      {entityId && selected && (
        <Panel title="Vulnerability report" meta={selected.report_id} eyebrow="DRAFT · HUMAN GATED">
          <RecordDetails
            data={selected}
            preferredKeys={[
              "report_id",
              "finding_id",
              "source_case_id",
              "severity",
              "category",
              "status",
              "publication_state",
              "report_integrity",
              "reproduction_sha256",
              "created_at",
            ]}
          />
          {[
            ["Description", selected.description],
            ["Clinical impact", selected.clinical_impact],
            ["Observed behavior", selected.observed_behavior],
            ["Expected behavior", selected.expected_behavior],
            ["Recommended remediation", selected.recommended_remediation],
          ].map(([label, value]) => (
            <div key={label}>
              <p className="field-label">{label}</p>
              <AdversarialText>{value}</AdversarialText>
            </div>
          ))}
          <VerificationChain verification={selected.verification} />
        </Panel>
      )}
      {entityId && !selected && reports.result.state !== "loading" && (
        <Panel title="Vulnerability report">
          <StateNotice state="empty" detail="That report is not in the organization-scoped response." />
        </Panel>
      )}
    </div>
  );
}

type ResourceScreenName = "traces" | "costs";

export function SimpleResourceScreen({ client, resource }: { client: ApiClient; resource: ResourceScreenName }) {
  switch (resource) {
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
  const surfaces = selected.surfaces;
  const template = selected.campaign_template;
  const canManageTargets = hasPermission(principal, PERMISSIONS.targetsManage);
  // Pre-filled bounded defaults so an Operator can request a campaign without hand-entering
  // caps or a nonce. The nonce is freshly generated per mount (unused → replay-safe); every
  // field stays editable, and the server still validates caps against the target's ceiling.
  const [runNonce, setRunNonce] = useState(() => `live-${globalThis.crypto.randomUUID()}`);
  const [budgetUsd, setBudgetUsd] = useState(
    () => template ? String(template.maximum_caps.budget_usd) : "",
  );
  const [maxAttempts, setMaxAttempts] = useState(
    () => template ? String(template.case_count) : "",
  );
  const [requestsPerSecond, setRequestsPerSecond] = useState(
    () => template ? String(template.maximum_caps.target_requests_per_second) : "",
  );
  const [timeoutSeconds, setTimeoutSeconds] = useState(
    () => template ? String(template.maximum_caps.run_timeout_seconds) : "",
  );
  const parsedCaps = {
    budget_usd: Number(budgetUsd),
    max_attempts_per_run: Number(maxAttempts),
    target_requests_per_second: Number(requestsPerSecond),
    run_timeout_seconds: Number(timeoutSeconds),
  };
  const capsValid = Object.values(parsedCaps).every((value) => Number.isFinite(value) && value > 0)
    && Number.isSafeInteger(parsedCaps.max_attempts_per_run);
  const fullScanFitsTarget = Boolean(
    template && template.maximum_caps.max_attempts_per_run >= template.case_count,
  );
  const capsWithinTarget = template
    ? parsedCaps.budget_usd <= template.maximum_caps.budget_usd
      && parsedCaps.max_attempts_per_run <= template.maximum_caps.max_attempts_per_run
      && parsedCaps.max_attempts_per_run >= template.case_count
      && parsedCaps.target_requests_per_second <= template.maximum_caps.target_requests_per_second
      && parsedCaps.run_timeout_seconds <= template.maximum_caps.run_timeout_seconds
    : false;
  const requestPayload = template && fullScanFitsTarget && capsValid && capsWithinTarget
    && runNonce.trim().length >= 16
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
    <Panel title="Registered target" meta={targetId ?? undefined}>
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
      <div className="evidence-stack">
        <p className="field-label">Immutable surface state</p>
        {surfaces.length > 0 ? (
          <div className="surface-stack">
            {surfaces.map((surface) => {
              const mayEnable = !surface.enabled && selected.lifecycle === "draft";
              const allowed = canManageTargets && (surface.enabled || mayEnable);
              return (
                <div
                  className="surface-row"
                  key={`${surface.surface_id}:${surface.version}`}
                >
                  <span>
                    <span className="mono">{surface.surface_id}@{surface.version}</span>
                    {" · "}
                    {surface.enabled ? "enabled" : "disabled"}
                    {" · "}
                    {surface.kind}
                  </span>
                  <CommandButton
                    client={client}
                    path={COMMAND_PATHS.changeSurfaceState(
                      selected.target_id,
                      surface.surface_id,
                    )}
                    payload={{ version: surface.version, enabled: !surface.enabled }}
                    label={surface.enabled ? "Disable surface" : "Enable surface"}
                    allowed={allowed}
                    unavailableReason={!canManageTargets
                      ? PERMISSIONS.targetsManage
                      : "a server-reported draft target before re-enabling"}
                    destructive={surface.enabled}
                    onAcknowledged={refresh}
                  />
                </div>
              );
            })}
          </div>
        ) : (
          <StateNotice state="empty" detail="No immutable surfaces are attached." />
        )}
        <p className="data-note">
          Disabling an existing immutable surface is immediately fail-closed. The backend permits
          re-enabling only while its target is in the draft lifecycle; reviewed targets expose no
          recovery control here.
        </p>
      </div>
      {template && (
        <div className="evidence-stack">
          <p className="field-label">Exact campaign authorization request</p>
          <MetricStrip label="Full scan profile" values={[
            { label: "Planned attacks", value: count(template.case_count), note: "Exact corpus bound into authorization" },
            { label: "Corpus", value: template.corpus_id, note: shortId(template.corpus_hash) },
            { label: "Reviewed tool sources", value: count(template.tool_sources.length), note: template.tool_sources.join(" · ") || "No reviewed tool sources" },
            { label: "Execution", value: template.execution_profile, note: "Every request passes the policy gateway" },
          ]} />
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
              "case_count",
              "tool_sources",
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
            unavailableReason={requestPayload
              ? PERMISSIONS.campaignLaunch
              : "a complete full-scan cap envelope and valid nonce"}
            onAcknowledged={() => {
              // Roll a fresh unused nonce after each accepted request so the next campaign
              // can be requested immediately without a replayed-nonce rejection.
              setRunNonce(`live-${globalThis.crypto.randomUUID()}`);
              refresh();
            }}
          />
        </div>
      )}
    </Panel>
  );
}

export function TargetsScreen({ client, principal }: ScreenProps) {
  const catalog = useResource<TargetCatalogEntryReadModel[]>(
    client,
    RESOURCE_PATHS.targetCatalog,
    decodeTargetCatalog,
  );
  const targets = useResource<TargetReadModel[]>(
    client,
    RESOURCE_PATHS.targets,
    decodeTargets,
  );
  const [selectedIdentity, setSelectedIdentity] = useState<string | null>(null);
  const [catalogIdentity, setCatalogIdentity] = useState("");
  const records = targets.result.data ?? [];
  const catalogRecords = catalog.result.data ?? [];
  const selectedCatalog = catalogRecords.find(
    (entry) => `${entry.target_id}\n${entry.version}` === catalogIdentity,
  ) ?? null;
  const canManageTargets = hasPermission(principal, PERMISSIONS.targetsManage);
  const selected = selectedIdentity
    ? records.find(
        (target) => `${target.target_id}\n${target.version}` === selectedIdentity,
      ) ?? null
    : null;
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
      <Panel
        title="Trusted target catalog"
        meta="server-owned registration"
        eyebrow="CONTROL PLANE"
      >
        <ResourceView
          result={catalog.result}
          emptyLabel="No reviewed target versions are available in the server catalog."
        >
          {(data) => (
            <div className="evidence-stack">
              <label className="form-field">
                <span>Reviewed target version</span>
                <select
                  aria-label="Reviewed target version"
                  value={catalogIdentity}
                  onChange={(event) => setCatalogIdentity(event.currentTarget.value)}
                >
                  <option value="">Select an exact catalog entry</option>
                  {data.map((entry) => (
                    <option
                      key={`${entry.target_id}:${entry.version}`}
                      value={`${entry.target_id}\n${entry.version}`}
                    >
                      {entry.name} · {entry.target_id}@{entry.version} · {entry.registration_state}
                    </option>
                  ))}
                </select>
              </label>
              {selectedCatalog && (
                <EvidenceGrid values={[
                  { label: "Target", value: selectedCatalog.target_id },
                  { label: "Version", value: selectedCatalog.version },
                  { label: "Environment", value: selectedCatalog.environment },
                  { label: "Surfaces", value: count(selectedCatalog.surface_count) },
                  { label: "Registration", value: selectedCatalog.registration_state },
                ]} />
              )}
              <CommandButton
                client={client}
                path={COMMAND_PATHS.createTarget}
                payload={selectedCatalog
                  ? {
                      target_id: selectedCatalog.target_id,
                      version: selectedCatalog.version,
                    }
                  : {}}
                label="Register exact catalog target"
                allowed={Boolean(
                  canManageTargets
                  && selectedCatalog?.registration_state === "available",
                )}
                unavailableReason={!canManageTargets
                  ? PERMISSIONS.targetsManage
                  : selectedCatalog?.registration_state === "registered"
                    ? "an unregistered catalog target"
                    : selectedCatalog?.registration_state === "conflict"
                      ? "manual resolution of the persisted immutable-state conflict"
                      : "an exact reviewed target version"}
                onAcknowledged={() => {
                  catalog.refresh();
                  targets.refresh();
                }}
              />
              <p className="data-note">
                The browser submits only the selected target ID and version. URLs, hosts,
                adapters, credentials, authorization references, and surface definitions remain
                server-owned.
              </p>
            </div>
          )}
        </ResourceView>
      </Panel>
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
              onSelect={(target) =>
                setSelectedIdentity(`${target.target_id}\n${target.version}`)}
            />
          )}
        </ResourceView>
      </Panel>
      {selected && (
        <TargetManagement
          key={`${selected.target_id}:${selected.version}`}
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
                { key: "created_at", label: "Occurred", mono: true, timestamp: true },
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
        detail="Read-only effective application state from the existing deployment. Runtime topology, secrets, targets, and activation are frozen in this recovery."
      />
      {configRecord && (
        <MetricStrip label="Configuration summary" values={[
          { label: "Snapshot", value: shortId(configRecord.snapshot_id), note: `version ${configRecord.version}` },
          { label: "Runtime snapshot state", value: configRecord.status, note: `Observed ${configRecord.published_at}` },
          { label: "Configuration areas", value: count(configurationKeys.length), note: configurationKeys.slice(0, 3).join(" · ") || "No top-level keys" },
          { label: "Components/tools evidenced", value: `${operationalComponents}/${componentRecords.length}`, note: components.result.state },
        ]} />
      )}
      <div className="panel-grid analytical-grid">
        <Panel title="Configuration topology" meta={configRecord ? `v${configRecord.version}` : configuration.result.state} eyebrow="RUNTIME POSTURE">
          {configRecord ? (
            <TagMatrix groups={[
              { label: "Effective areas", values: configurationKeys },
              { label: "Runtime status", values: [configRecord.status] },
              { label: "Snapshot source", values: [shortId(configRecord.published_by)] },
              { label: "Snapshot", values: [shortId(configRecord.snapshot_id)] },
            ]} />
          ) : (
            <ResourceView result={configuration.result} emptyLabel="No effective runtime snapshot is available.">{() => null}</ResourceView>
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
      <Panel title="Effective runtime snapshot">
        <ResourceView result={configuration.result} emptyLabel="No effective runtime snapshot is available.">
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
                <p className="field-label">Effective server state</p>
                <AdversarialText>{JSON.stringify(data.configuration, null, 2)}</AdversarialText>
              </div>
            </div>
          )}
        </ResourceView>
        <StateNotice
          state="unavailable"
          reason="frozen_application_configuration"
          detail="Candidate validation, snapshot publication, and runtime activation are unavailable here. Four-role hosted sets may only be staged atomically through the protected API v1 resource."
        />
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
