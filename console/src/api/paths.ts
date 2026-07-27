const segment = (value: string) => encodeURIComponent(value);
const campaignScoped = (path: string, campaignId: string) =>
  `${path}?campaign_id=${encodeURIComponent(campaignId)}`;

export const RESOURCE_PATHS = {
  principal: "principal",
  campaigns: "campaigns",
  campaign: (campaignId: string) => `campaigns/${segment(campaignId)}`,
  campaignOperations: (campaignId: string) =>
    `campaigns/${segment(campaignId)}/operations`,
  attempts: (campaignId: string) => `campaigns/${segment(campaignId)}/attempts`,
  evidence: (attemptId: string) => `attempts/${segment(attemptId)}/evidence`,
  findings: "findings",
  finding: (findingId: string) => `findings/${segment(findingId)}`,
  approvals: "approvals",
  approval: (requestId: string) => `approvals/${segment(requestId)}`,
  reports: "reports",
  report: (reportId: string) => `reports/${segment(reportId)}`,
  coverage: "coverage",
  resilience: "resilience",
  traces: "traces",
  campaignTraces: (campaignId: string) => campaignScoped("traces", campaignId),
  providerCalls: "provider-calls",
  campaignProviderCalls: (campaignId: string) =>
    campaignScoped("provider-calls", campaignId),
  providerCallEvidence: (invocationId: string) =>
    `provider-calls/${segment(invocationId)}/evidence`,
  targetCallEvidence: (requestId: string) =>
    `target-calls/${segment(requestId)}/evidence`,
  costs: "costs",
  campaignCosts: (campaignId: string) => campaignScoped("costs", campaignId),
  targetCatalog: "target-catalog",
  targets: "targets",
  target: (targetId: string) => `targets/${segment(targetId)}`,
  configuration: "configuration",
  components: "components",
  agents: "agents",
  agentPrompt: (
    agentRole: string,
    promptVersion: string,
    promptSha256: string,
    configurationSha256: string,
  ) =>
    `agent-prompts/${segment(agentRole)}/${segment(promptVersion)}/${segment(promptSha256)}`
    + `/${segment(configurationSha256)}`,
  agentActivity: "agent-activity",
  campaignAgentActivity: (campaignId: string) =>
    campaignScoped("agent-activity", campaignId),
  agentPromptSnapshot: (executionId: string) =>
    `agent-executions/${segment(executionId)}/prompt-snapshot`,
  tooling: "tooling",
  birdseye: "birdseye",
  audit: "audit",
} as const;

export const COMMAND_PATHS = {
  createCampaignAuthorizationRequest: "campaign-authorization-requests",
  decideCampaignAuthorization: (requestId: string) =>
    `campaign-authorization-requests/${segment(requestId)}/decisions`,
  launchCampaign: "campaigns",
  abortCampaign: (runId: string) => `campaigns/${segment(runId)}/abort`,
  decideFinding: (findingId: string) => `findings/${segment(findingId)}/decisions`,
  resolveFinding: (findingId: string) => `findings/${segment(findingId)}/resolve`,
  createTarget: "targets",
  reviseTarget: (targetId: string) => `targets/${segment(targetId)}/versions`,
  changeTargetLifecycle: (targetId: string) => `targets/${segment(targetId)}/lifecycle`,
  createSurface: (targetId: string) => `targets/${segment(targetId)}/surfaces`,
  reviseSurface: (targetId: string, surfaceId: string) =>
    `targets/${segment(targetId)}/surfaces/${segment(surfaceId)}/versions`,
  changeSurfaceState: (targetId: string, surfaceId: string) =>
    `targets/${segment(targetId)}/surfaces/${segment(surfaceId)}/state`,
  createProbeAuthorizationRequest: "live-probe-authorization-requests",
  validateConfiguration: "configuration/validate",
  publishConfiguration: "configuration/publish",
  configureAgent: (agentRole: string) => `agents/${segment(agentRole)}/configuration`,
} as const;
