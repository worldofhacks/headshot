import type { JsonRecord } from "./api/contracts";

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export interface SafetyCapsReadModel extends JsonRecord {
  budget_usd: number;
  max_attempts_per_run: number;
  target_requests_per_second: number;
  run_timeout_seconds: number;
}

export interface AuthorizationScopeReadModel extends JsonRecord {
  target_id: string;
  target_version: string;
  surface_id: string;
  surface_version: string;
  adapter_kind: string;
  environment: string;
  exact_host: string;
  auth_mode: string;
  explicit_no_auth: boolean;
  auth_posture: string;
  protocol: string;
  method: string;
  relative_path: string;
  endpoint: string;
  corpus_id: string;
  corpus_hash: string;
  caps: SafetyCapsReadModel;
  run_nonce: string;
  execution_profile: "synthetic" | "live";
}

export interface CampaignReadModel extends AuthorizationScopeReadModel {
  run_id: string;
  authorization_request_id: string;
  scope_hash: string;
  launcher_user_id: string;
  state: "queued" | "running" | "complete" | "aborted" | "failed";
  attempt_count: number | null;
  created_at: string;
}

export interface AttemptReadModel extends JsonRecord {
  attempt_id: string;
  ordinal: number;
  case_id: string;
  content_hash: string | null;
  executed_at: string | null;
  trace_id: string | null;
  verdict: string | null;
  confidence: number | null;
  execution_profile: "synthetic" | "live" | null;
  evidence_provenance: "synthetic_offline" | "live_target" | "scan_only" | "simulated" | null;
  created_at: string;
}

export interface EvidenceReadModel extends JsonRecord {
  campaign_run_id: string;
  attempt_id: string;
  target_id: string | null;
  target_version: string | null;
  surface_id: string | null;
  surface_version: string | null;
  attack_attempt: JsonRecord | null;
  request_transcript: JsonRecord | null;
  response_transcript: string | null;
  policy_decision_id: string | null;
  executed_at: string | null;
  trace_id: string | null;
  content_hash: string;
  verdict: string | null;
  confidence: number | null;
}

export interface FindingHistoryReadModel extends JsonRecord {
  decision: string;
  actor_user_id: string;
  rationale: string;
  created_at: string;
}

export interface FindingReadModel extends JsonRecord {
  finding_id: string;
  state: string;
  severity: string;
  category: string;
  target_version: string;
  publication_status: string;
  evidence_integrity: string;
  source_kind: string;
  execution_profile: "synthetic" | "live";
  evidence_provenance: string;
  campaign_run_id: string | null;
  attempt_id: string | null;
  evidence_content_hash: string;
  history: FindingHistoryReadModel[];
}

export type FindingDetailReadModel = FindingReadModel;

export interface ApprovalReadModel extends AuthorizationScopeReadModel {
  request_id: string;
  scope_hash: string;
  launcher_user_id: string;
  expires_at: string;
  created_at: string;
  status: "pending" | "approved" | "rejected";
  decision: "approved" | "rejected" | null;
  approver_user_id: string | null;
  self_approval_override: boolean;
  decided_at: string | null;
}

export interface CoverageReadModel extends JsonRecord {
  target_version: string;
  verified_attempt_count: number;
  total_case_count: number;
  category_count: number;
  execution_profile: "synthetic" | "live";
  evidence_provenance: string;
  classifications: string[];
  owasp_web: string[];
  owasp_llm: string[];
  verdict_counts: JsonRecord;
  covered: boolean;
  as_of: string;
}

export interface ResilienceReadModel extends JsonRecord {
  regression_id: string;
  version: string;
  status: string;
  recorded_at: string;
}

export interface TraceReadModel extends JsonRecord {
  request_id: string | null;
  trace_id: string;
  campaign_id: string;
  attempt_id: string | null;
  operation: string;
  provider: string;
  method: string | null;
  destination_host: string | null;
  relative_path: string | null;
  status: string;
  status_code: number | null;
  error_code: string | null;
  started_at: string;
  finished_at: string | null;
  duration_ms: number;
  request_bytes: number;
  response_bytes: number | null;
  measured_cost: number;
  currency: string;
  langfuse_status: string;
  request_preview: string | null;
  response_preview: string | null;
  request_sha256: string | null;
  response_sha256: string | null;
  inspection_flags: string[];
  inspection_owasp_mappings: string[];
}

export interface CostReadModel extends JsonRecord {
  accounting_id: string;
  campaign_id: string;
  provider: string;
  measured_cost: number;
  currency: string;
  request_count: number;
  attempt_count: number;
  confirmed_finding_count: number;
  average_cost_per_request: number;
  budget_usd: number | null;
  budget_utilization: number | null;
  duration_ms: number;
  execution_profile: "synthetic" | "live";
  started_at: string;
  ended_at: string;
  recorded_at: string;
}

export interface AttackSurfaceReadModel extends JsonRecord {
  surface_id: string;
  version: string;
  target_version: string;
  content_hash: string;
  kind: string;
  protocol: string;
  method: string;
  relative_path: string;
  trust_boundary: string;
  authentication_required: boolean;
  risk: string;
  owasp_mappings: JsonRecord[];
  oracle_refs: string[];
  enabled: boolean;
  created_at: string;
}

export interface CampaignTemplateReadModel extends JsonRecord {
  target_id: string;
  target_version: string;
  surface_id: string;
  surface_version: string;
  corpus_id: string;
  corpus_hash: string;
  case_count: number;
  tool_sources: string[];
  execution_profile: "synthetic" | "live";
  maximum_caps: SafetyCapsReadModel;
}

export interface TargetReadModel extends JsonRecord {
  target_id: string;
  version: string;
  content_hash: string;
  name: string;
  adapter_kind: string;
  environment: string;
  base_url: string;
  auth_mode: string;
  credential_configured: boolean;
  synthetic_data_only: boolean;
  safety_caps: SafetyCapsReadModel;
  lifecycle: string;
  allowed_lifecycle_transitions: string[];
  surfaces: AttackSurfaceReadModel[];
  campaign_template: CampaignTemplateReadModel | null;
  created_at: string;
}

export interface ConfigurationReadModel extends JsonRecord {
  snapshot_id: string;
  version: number;
  status: string;
  configuration: JsonRecord;
  published_at: string;
  published_by: string;
}

export interface ComponentReadModel extends JsonRecord {
  component_id: string;
  name: string;
  kind: string;
  availability: "operational and evidenced" | "adapter integrated, execution deferred" | "evaluated and rejected" | "blocked pending authorization";
  environment: string;
  detail: string;
  version: string;
  target_access: string;
  capabilities: string[];
  owasp_llm: string[];
  owasp_web: string[];
  operational_scope: string[];
  adapter_only_scope: string[];
  execution_evidence: string[];
  heartbeat_at: string;
}

export interface AgentAssignmentReadModel extends JsonRecord {
  role: "orchestrator" | "red_team" | "judge" | "documentation";
  provider: string;
  model: string;
  execution_mode: "deterministic" | "hosted_advisory";
  activation_state: "active" | "staged_pending_authorization";
  version: number;
  configuration_sha256: string;
  configured_at: string | null;
  configured_by: string | null;
}

export interface AgentReadModel extends JsonRecord {
  role: "orchestrator" | "red_team" | "judge" | "documentation";
  display_name: string;
  responsibility: string;
  trust_level: string;
  target_access: string;
  input_contract: string;
  output_contract: string;
  active_assignment: AgentAssignmentReadModel;
  staged_assignment: AgentAssignmentReadModel | null;
  execution_count: number;
  running_count: number;
  succeeded_count: number;
  failed_count: number;
  skipped_count: number;
  measured_cost: number;
  currency: string;
  input_tokens: number | null;
  output_tokens: number | null;
  token_observation_count: number;
  average_duration_ms: number | null;
  last_activity_at: string | null;
  last_status: string | null;
  last_campaign_run_id: string | null;
  last_attempt_id: string | null;
}

export interface AgentActivityReadModel extends JsonRecord {
  execution_id: string;
  campaign_run_id: string;
  attempt_id: string | null;
  parent_execution_id: string | null;
  agent_role: "orchestrator" | "red_team" | "judge" | "documentation";
  status: "running" | "succeeded" | "failed" | "skipped";
  provider: string;
  model: string;
  execution_mode: "deterministic" | "hosted_advisory";
  configuration_version: number;
  input_sha256: string;
  output_sha256: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  measured_cost: number;
  currency: string;
  trace_id: string;
  detail: JsonRecord;
  error_code: string | null;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
}

export interface ToolScopeReadModel extends JsonRecord {
  tool_id: string;
  name: string;
  version: string;
  kind: string;
  availability: string;
  target_access: string;
  target_id: string;
  target_version: string;
  target_lifecycle: string;
  surface_id: string;
  surface_version: string;
  surface_kind: string;
  endpoint: string;
  applicability: "in_campaign" | "companion_scan" | "platform_assurance" | "adapter_available" | "not_applicable";
  execution_mode: string;
  scope_reason: string;
  requires_separate_authorization: boolean;
  capabilities: string[];
  owasp_llm: string[];
  owasp_web: string[];
  reviewed_candidate_count: number;
  executed_attempt_count: number;
  recorded_scan_count: number;
  recorded_finding_count: number;
  last_executed_at: string | null;
}

export interface BirdseyeCampaignReadModel extends JsonRecord {
  run_id: string;
  target_id: string;
  target_name: string;
  target_version: string;
  state: "queued" | "running" | "complete" | "aborted" | "failed";
  execution_profile: "synthetic" | "live";
  scope_hash: string;
  attempt_count: number;
}

export interface BirdseyeInstrumentationReadModel extends JsonRecord {
  budget_usd: number;
  measured_cost_usd: number;
  budget_utilization: number;
  requests_per_second_cap: number;
  queue_queued: number;
  queue_leased: number;
  queue_dead_letter: number;
  confirmed_count: number;
  likely_count: number;
  review_count: number;
  healthy_components: number;
  total_components: number;
  system_state: "nominal" | "degraded" | "unavailable";
}

export interface BirdseyeSecurityPostureReadModel extends JsonRecord {
  tested_categories: number;
  required_categories: number;
  verified_case_count: number;
  held_count: number;
  exploited_count: number;
  review_count: number;
  observed_hold_rate: number | null;
  open_finding_count: number;
  in_progress_finding_count: number;
  resolved_finding_count: number;
  critical_open_finding_count: number;
  resilience_direction: "improving" | "steady" | "degrading" | "unavailable";
  current_regression_hold_rate: number | null;
  previous_regression_hold_rate: number | null;
  resilience_delta: number | null;
  cost_per_attempt_usd: number | null;
  cost_velocity_usd_per_minute: number | null;
  projected_cost_at_attempt_cap_usd: number | null;
  priority_category: string | null;
  priority_reason: string;
  priority_source: "orchestrator_decision" | "coverage_policy" | "unavailable";
  priority_at: string | null;
}

export interface BirdseyeCategoryOutcomeReadModel extends JsonRecord {
  target_version: string;
  category: string;
  verified_case_count: number;
  verified_attempt_count: number;
  held_count: number;
  exploited_count: number;
  review_count: number;
  last_evaluated_at: string | null;
}

export interface BirdseyeAgentActivityReadModel extends JsonRecord {
  execution_id: string;
  parent_execution_id: string | null;
  agent_role: "orchestrator" | "red_team" | "judge" | "documentation";
  status: "running" | "succeeded" | "failed" | "skipped";
  phase: string;
  attempt_id: string | null;
  category: string | null;
  verdict_state: string | null;
  finding_id: string | null;
  error_code: string | null;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
}

export type BirdseyeTrustZone =
  | "human"
  | "untrusted"
  | "control"
  | "execution"
  | "evaluation"
  | "governance"
  | "data"
  | "observability"
  | "unclassified";

export type BirdseyeRuntimeState =
  | "ready"
  | "working"
  | "waiting"
  | "degraded"
  | "error"
  | "stale"
  | "unavailable";

export interface BirdseyeNodeReadModel extends JsonRecord {
  component_id: string;
  name: string;
  kind: string;
  trust_zone: BirdseyeTrustZone;
  availability: string;
  runtime_state: BirdseyeRuntimeState;
  detail: string;
  current_task: string;
  heartbeat_at: string | null;
  freshness_seconds: number | null;
  is_fresh: boolean;
  healthy_instances: number;
  total_instances: number;
  p50_latency_ms: number | null;
  p95_latency_ms: number | null;
  queue_depth: number | null;
  target_access: string;
}

export interface BirdseyeEdgeReadModel extends JsonRecord {
  edge_id: string;
  source_component_id: string;
  target_component_id: string;
  contract_name: string;
  state: "idle" | "active" | "complete" | "error" | "stale" | "unavailable";
  attempt_id: string | null;
  last_event_at: string | null;
  detail: string;
}

export interface BirdseyeAttentionReadModel extends JsonRecord {
  attention_id: string;
  priority: number;
  kind: "integrity" | "approval" | "finding" | "component";
  title: string;
  detail: string;
  continuation: string;
  record_type: string;
  record_id: string;
  route: string;
  created_at: string;
}

export interface BirdseyeTimelineReadModel extends JsonRecord {
  cursor: number;
  event_type: string;
  actor: string;
  summary: string;
  aggregate_type: string;
  aggregate_id: string;
  created_at: string;
}

export interface BirdseyeSnapshotReadModel extends JsonRecord {
  campaign: BirdseyeCampaignReadModel | null;
  instrumentation: BirdseyeInstrumentationReadModel;
  security_posture: BirdseyeSecurityPostureReadModel;
  category_outcomes: BirdseyeCategoryOutcomeReadModel[];
  agent_activity: BirdseyeAgentActivityReadModel[];
  nodes: BirdseyeNodeReadModel[];
  edges: BirdseyeEdgeReadModel[];
  attention: BirdseyeAttentionReadModel[];
  timeline: BirdseyeTimelineReadModel[];
  cursor: number;
  as_of: string;
}

export interface AuditReadModel extends JsonRecord {
  cursor: number;
  event_type: string;
  aggregate_type: string;
  aggregate_id: string;
  actor_user_id: string | null;
  payload: JsonRecord;
  created_at: string;
}

export const PERMISSIONS = {
  consoleRead: "org:console:read",
  findingsRead: "org:findings:read",
  evidenceRead: "org:evidence:read",
  campaignLaunch: "org:campaign:launch",
  campaignAbort: "org:campaign:abort",
  campaignAuthorize: "org:campaign:authorize",
  targetsManage: "org:targets:manage",
  configManage: "org:config:manage",
  findingsApprove: "org:findings:approve",
  findingsResolve: "org:findings:resolve",
  auditRead: "org:audit:read",
} as const;
