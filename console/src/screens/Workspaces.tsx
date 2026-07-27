import { useEffect, type ComponentProps } from "react";

import type { ApiClient } from "../api/client";
import type { Principal } from "../api/contracts";
import { RESOURCE_PATHS } from "../api/paths";
import { decodeEvidence } from "../api/read-models";
import { ResourceView, StateNotice } from "../components/ResourceView";
import { WorkspaceTabs } from "../components/WorkspaceTabs";
import { useResource } from "../hooks/useResource";
import type { EvidenceReadModel } from "../types";
import { PERMISSIONS } from "../types";
import { AgentsScreen, ToolingScreen } from "./AgentToolScreens";
import {
  ConfigurationScreen,
  FindingsScreen,
  ReportsScreen,
  TargetsScreen,
} from "./ConsoleScreens";
import { CostsScreen, TracesScreen } from "./ObservabilityScreens";
import { RunOperationsScreen } from "./RunOperationsScreen";

interface SharedWorkspaceProps {
  client: ApiClient;
  principal: Principal;
  entityId: string | null;
  getToken: () => Promise<string | null>;
}

export type RunsView = "operations" | "targets";

function ResolvedLegacyOperations({
  evidence,
  attemptId,
  onCampaignResolved,
  ...props
}: ComponentProps<typeof RunOperationsScreen> & {
  evidence: EvidenceReadModel;
  attemptId: string;
  onCampaignResolved?: (campaignId: string) => void;
}) {
  useEffect(() => {
    onCampaignResolved?.(evidence.campaign_run_id);
  }, [evidence.campaign_run_id, onCampaignResolved]);
  return (
    <RunOperationsScreen
      {...props}
      campaignId={evidence.campaign_run_id}
      expandedAttemptId={attemptId}
    />
  );
}

function LegacyAttemptResolver({
  client,
  principal,
  attemptId,
  onCampaignResolved,
  ...props
}: Omit<ComponentProps<typeof RunOperationsScreen>, "campaignId" | "expandedAttemptId">
  & {
    client: ApiClient;
    principal: Principal;
    attemptId: string;
    onCampaignResolved?: (campaignId: string) => void;
  }) {
  const evidence = useResource<EvidenceReadModel>(
    client,
    RESOURCE_PATHS.evidence(attemptId),
    decodeEvidence,
  );
  return (
    <ResourceView
      result={evidence.result}
      emptyLabel="The legacy attempt deep link does not resolve to accessible evidence."
    >
      {(data) => {
        if (data.attempt_id !== attemptId) {
          return (
            <StateNotice
              state="error"
              detail="The resolved evidence identity does not match the legacy attempt deep link."
            />
          );
        }
        return (
          <ResolvedLegacyOperations
            {...props}
            client={client}
            principal={principal}
            evidence={data}
            attemptId={attemptId}
            onCampaignResolved={onCampaignResolved}
          />
        );
      }}
    </ResourceView>
  );
}

function LegacyAttemptOperations(
  props: Omit<ComponentProps<typeof RunOperationsScreen>, "campaignId" | "expandedAttemptId">
    & {
      client: ApiClient;
      principal: Principal;
      attemptId: string;
      onCampaignResolved?: (campaignId: string) => void;
    },
) {
  if (!props.principal.organization_permissions.includes(PERMISSIONS.evidenceRead)) {
    return (
      <StateNotice
        state="unavailable"
        detail="Resolving this legacy attempt deep link requires org:evidence:read. Open Runs and select its campaign scope."
      />
    );
  }
  return <LegacyAttemptResolver {...props} />;
}

export function RunsWorkspace({
  view,
  onViewChange,
  campaignId,
  expandedAttemptId,
  onCampaignSelect,
  onCampaignResolved,
  onAttemptSelect,
  ...props
}: SharedWorkspaceProps & {
  view: RunsView;
  onViewChange: (view: RunsView) => void;
  campaignId?: string | null;
  expandedAttemptId?: string | null;
  onCampaignSelect?: (campaignId: string) => void;
  onCampaignResolved?: (campaignId: string) => void;
  onAttemptSelect?: (attemptId: string) => void;
}) {
  return (
    <div className="screen-stack">
      <WorkspaceTabs
        label="Runs workspace"
        active={view}
        onChange={onViewChange}
        tabs={[
          { id: "operations", label: "Operations" },
          { id: "targets", label: "Targets" },
        ]}
      />
      {view === "operations"
        ? expandedAttemptId
          ? (
            <LegacyAttemptOperations
              client={props.client}
              principal={props.principal}
              attemptId={expandedAttemptId}
              onCampaignResolved={onCampaignResolved}
              onCampaignSelect={onCampaignSelect}
              onAttemptSelect={onAttemptSelect}
            />
          )
          : (
          <RunOperationsScreen
            client={props.client}
            principal={props.principal}
            campaignId={campaignId}
            expandedAttemptId={expandedAttemptId}
            onCampaignSelect={onCampaignSelect}
            onAttemptSelect={onAttemptSelect}
          />
            )
        : <TargetsScreen {...props} campaignId={campaignId} />}
    </div>
  );
}

export type FindingsView = "findings" | "reports";

export function FindingsWorkspace({
  view,
  onViewChange,
  ...props
}: SharedWorkspaceProps & {
  view: FindingsView;
  onViewChange: (view: FindingsView) => void;
}) {
  return (
    <div className="screen-stack">
      <WorkspaceTabs
        label="Findings workspace"
        active={view}
        onChange={onViewChange}
        tabs={[
          { id: "findings", label: "Findings" },
          { id: "reports", label: "Reports" },
        ]}
      />
      {view === "findings" ? <FindingsScreen {...props} /> : <ReportsScreen {...props} />}
    </div>
  );
}

export type ObservabilityView = "traces" | "costs";

export function ObservabilityWorkspace({
  client,
  campaignId,
  view,
  onViewChange,
}: Pick<SharedWorkspaceProps, "client"> & {
  campaignId?: string | null;
  view: ObservabilityView;
  onViewChange: (view: ObservabilityView) => void;
}) {
  return (
    <div className="screen-stack">
      <WorkspaceTabs
        label="Observability workspace"
        active={view}
        onChange={onViewChange}
        tabs={[
          { id: "traces", label: "Traces" },
          { id: "costs", label: "Costs" },
        ]}
      />
      {view === "traces"
        ? <TracesScreen client={client} campaignId={campaignId ?? undefined} />
        : <CostsScreen client={client} campaignId={campaignId ?? undefined} />}
    </div>
  );
}

export type SystemView = "agents" | "tools" | "configuration";

export function SystemWorkspace({
  client,
  principal,
  entityId,
  getToken,
  view,
  onViewChange,
}: SharedWorkspaceProps & {
  view: SystemView;
  onViewChange: (view: SystemView) => void;
}) {
  return (
    <div className="screen-stack">
      <WorkspaceTabs
        label="System workspace"
        active={view}
        onChange={onViewChange}
        tabs={[
          { id: "agents", label: "Agents" },
          { id: "tools", label: "Tool inventory" },
          { id: "configuration", label: "Configuration" },
        ]}
      />
      {view === "agents" && <AgentsScreen client={client} principal={principal} />}
      {view === "tools" && <ToolingScreen client={client} />}
      {view === "configuration" && (
        <ConfigurationScreen
          client={client}
          principal={principal}
          entityId={entityId}
          getToken={getToken}
        />
      )}
    </div>
  );
}
