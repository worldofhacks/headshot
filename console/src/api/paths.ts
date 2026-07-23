const segment = (value: string) => encodeURIComponent(value);

export const RESOURCE_PATHS = {
  principal: "principal",
  campaigns: "campaigns",
  campaign: (campaignId: string) => `campaigns/${segment(campaignId)}`,
  attempts: (campaignId: string) => `campaigns/${segment(campaignId)}/attempts`,
  evidence: (attemptId: string) => `attempts/${segment(attemptId)}/evidence`,
  findings: "findings",
  finding: (findingId: string) => `findings/${segment(findingId)}`,
  approvals: "approvals",
  coverage: "coverage",
  resilience: "resilience",
  traces: "traces",
  costs: "costs",
  targets: "targets",
  target: (targetId: string) => `targets/${segment(targetId)}`,
  configuration: "configuration",
  components: "components",
  agents: "agents",
  agentActivity: "agent-activity",
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
