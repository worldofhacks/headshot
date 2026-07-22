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
