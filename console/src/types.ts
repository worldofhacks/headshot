import type { JsonRecord } from "./api/contracts";
import type { FindingDecisionReasonCode } from "./finding-decisions";

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export interface SafetyCapsReadModel extends JsonRecord {
  budget_usd: number;
  max_attempts_per_run: number;
  target_requests_per_second: number;
  run_timeout_seconds: number;
  logical_case_limit: number | null;
  physical_request_limit: number | null;
  target_retries_per_turn: number | null;
}

export interface HostedRunBindingReadModel extends JsonRecord {
  configuration_set_sha256: string;
  generation_policy_sha256: string;
  session_generation: string;
  provider_model_call_limit: number;
  provider_model_spend_limit_usd: string;
  provider_max_retries: number;
  provider_max_concurrency: 1;
  provider_timeout_seconds: number;
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
  hosted_run: HostedRunBindingReadModel | null;
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

export interface CampaignOperationsCaseProgressReadModel extends JsonRecord {
  planned: number | null;
  started: number;
  running: number;
  completed: number;
  failed: number;
  skipped: number | null;
  remaining: number | null;
}

export interface CampaignOperationsExecutionCountsReadModel extends JsonRecord {
  logical_attempts: number;
  physical_target_requests: number;
  provider_calls: number;
}

export interface CampaignOperationsCurrentWorkReadModel extends JsonRecord {
  stage: string;
  agent_role: "orchestrator" | "red_team" | "judge" | "documentation" | null;
  execution_id: string | null;
  attempt_id: string | null;
  started_at: string;
}

export interface CampaignOperationsCostReadModel extends JsonRecord {
  provider_measured_usd: number | null;
  target_measured_usd: number | null;
  total_measured_usd: number | null;
  provider_measurement_state: "measured" | "partial" | "unavailable";
  target_measurement_state: "measured" | "partial" | "unavailable";
  measurement_state: "measured" | "partial" | "unavailable";
  currency: "USD";
}

export interface CampaignOperationsLimitsReadModel extends JsonRecord {
  target_budget_usd: number | null;
  target_budget_remaining_usd: number | null;
  provider_budget_usd: number | null;
  provider_budget_remaining_usd: number | null;
  logical_case_limit: number | null;
  physical_request_limit: number | null;
  physical_requests_remaining: number | null;
  provider_call_limit: number | null;
  provider_calls_remaining: number | null;
  target_requests_per_second: number | null;
  run_timeout_seconds: number | null;
  max_attempts_per_run: number | null;
  target_retries_per_turn: number | null;
  provider_max_retries: number | null;
  provider_max_concurrency: number | null;
  provider_timeout_seconds: number | null;
}

export interface CampaignOperationsQueueReadModel extends JsonRecord {
  queued_jobs: number;
  leased_jobs: number;
  dead_lettered_jobs: number;
  rate_limit_active: boolean | null;
}

export interface CampaignOperationsTerminalFailureReadModel extends JsonRecord {
  stage: string;
  error_code: string;
  attempt_id: string | null;
  execution_id: string | null;
  agent_role: "orchestrator" | "red_team" | "judge" | "documentation" | null;
  provider: string | null;
  model: string | null;
  retryable: boolean | null;
  retries_remaining: number | null;
  occurred_at: string;
  operator_summary: string;
}

export interface CampaignOperationsReadModel extends JsonRecord {
  campaign_id: string;
  state: "queued" | "running" | "complete" | "aborted" | "failed";
  created_at: string;
  progress: CampaignOperationsCaseProgressReadModel;
  executions: CampaignOperationsExecutionCountsReadModel;
  current_work: CampaignOperationsCurrentWorkReadModel | null;
  costs: CampaignOperationsCostReadModel;
  limits: CampaignOperationsLimitsReadModel;
  verdict_distribution: Record<string, number>;
  queue: CampaignOperationsQueueReadModel;
  terminal_failure: CampaignOperationsTerminalFailureReadModel | null;
  as_of: string;
  cursor: number;
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
  execution_profile: "synthetic" | "live" | null;
  evidence_provenance: "synthetic_offline" | "live_target" | "scan_only" | "simulated" | null;
}

export interface FindingHistoryReadModel extends JsonRecord {
  decision: string;
  actor_user_id: string;
  rationale: string;
  reason_code: FindingDecisionReasonCode | null;
  created_at: string;
}

interface FindingReadModelBase extends JsonRecord {
  finding_id: string;
  state: string;
  severity: string;
  category: string | null;
  target_version: string | null;
  publication_status: string;
  source_kind: string;
  execution_profile: "synthetic" | "live";
  evidence_provenance: string;
  campaign_run_id: string | null;
  attempt_id: string | null;
  history: FindingHistoryReadModel[];
}

export type FindingReadModel = FindingReadModelBase & (
  | {
      evidence_integrity: "verified";
      evidence_content_hash: string;
    }
  | {
      evidence_integrity: "unavailable";
      evidence_content_hash: null;
    }
);

export interface AttackCaseEvidenceReadModel extends JsonRecord {
  case_id: string;
  case_content_sha256: string | null;
  category: string | null;
  attack_class: "boundary" | "invariant" | "regression" | null;
  owasp_mappings: JsonRecord[];
  oracle_expectation: JsonRecord | null;
  corpus_reconciliation: "verified" | "unavailable";
}

export interface JudgeBasisReadModel extends JsonRecord {
  state: string;
  confidence: number | null;
  reason_codes: string[];
  confirmation_source: "oracle" | "canary" | "calibrated_model" | "human" | null;
  oracle_refs: string[];
  canary_refs: string[];
  rationale: string | null;
  rationale_availability: "unavailable";
  rationale_detail: string;
  error_code: string | null;
}

export interface EvidenceIntegrityReadModel extends JsonRecord {
  stored_content_sha256: string;
  finding_link_sha256: string;
  recomputed_content_sha256: string;
  evidence_record: "verified";
  finding_link: "verified";
  observability_reconciliation: "unavailable";
  observability_detail: string;
}

export interface RegressionDispositionReadModel extends JsonRecord {
  disposition_id: string;
  state: string;
  reason_codes: string[];
  reproduction_attempted: boolean;
  deterministic_reproduction: boolean;
  passes_for_right_reason: boolean;
  human_approved: boolean;
  admitted: boolean;
}

export interface FindingVerificationReadModel extends JsonRecord {
  availability: "ready" | "unavailable";
  reason_code: string | null;
  finding_id: string;
  campaign_run_id: string | null;
  attempt_id: string | null;
  attack_case: AttackCaseEvidenceReadModel | null;
  attack_attempt: JsonRecord | null;
  input_sequence: string[];
  request_transcript: JsonRecord | null;
  response_transcript: string | null;
  policy_decision_id: string | null;
  executed_at: string | null;
  trace_id: string | null;
  judge: JudgeBasisReadModel | null;
  report_id: string | null;
  minimal_reproduction: string[];
  reproduction_sha256: string | null;
  regression: RegressionDispositionReadModel | null;
  integrity: EvidenceIntegrityReadModel | null;
  redaction_state: "synthetic_identifiers_redacted";
}

export type FindingDetailReadModel = FindingReadModel & {
  verification: FindingVerificationReadModel;
};

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
  expired: boolean;
  consumed: boolean;
}

export interface ApprovalDetailReadModel extends ApprovalReadModel {
  campaign_run_id: string | null;
  verification_chain: FindingVerificationReadModel[];
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

export interface ReportReadModel extends JsonRecord {
  schema_version: "1";
  report_id: string;
  finding_id: string;
  campaign_run_id: string;
  attempt_id: string;
  source_case_id: string;
  severity: "low" | "medium" | "high" | "critical";
  category: string;
  description: string;
  clinical_impact: string;
  minimal_reproduction: string[];
  reproduction_sha256: string;
  observed_behavior: string;
  expected_behavior: string;
  recommended_remediation: string;
  status: "draft" | "validated" | "remediation_pending" | "fix_pending" | "fixed" | "regressed";
  fix_validation: JsonRecord;
  evidence_references: string[];
  publication_state: "draft_unpublished" | "blocked_pending_human_approval";
  regression: RegressionDispositionReadModel | null;
  report_integrity: "verified";
  created_at: string;
  verification: FindingVerificationReadModel;
}

export type JudgeCalibrationState =
  | "unavailable"
  | "failed"
  | "passed"
  | "invalidated"
  | "enabled";

export type JudgeDecisionAuthority = "oracle" | "model" | "none";

export interface AgentBudgetReadModel extends JsonRecord {
  status:
    | "staged_pending_authorization"
    | "active"
    | "historical"
    | "agent_acceptance"
    | "unavailable";
  campaign_run_id: string | null;
  configuration_set_sha256: string | null;
  role_cost_measurement_state: CostMeasurementState | null;
  role_usd_cap: number | null;
  role_usd_spent: number;
  role_unresolved_usd_exposure: number;
  role_usd_remaining: number | null;
  role_usd_remaining_upper_bound: number | null;
  role_usd_overrun: number;
  role_call_cap: number | null;
  role_physical_calls: number;
  role_unresolved_physical_calls: number;
  role_call_count_state: "exact" | "lower_bound" | null;
  role_calls_remaining: number | null;
  role_call_overrun: number;
  global_cost_measurement_state: CostMeasurementState | null;
  global_usd_cap: number | null;
  global_usd_spent: number;
  global_unresolved_usd_exposure: number;
  global_usd_remaining: number | null;
  global_usd_remaining_upper_bound: number | null;
  global_usd_overrun: number;
  global_call_cap: number | null;
  global_physical_calls: number;
  global_unresolved_physical_calls: number;
  global_call_count_state: "exact" | "lower_bound" | null;
  global_calls_remaining: number | null;
  global_call_overrun: number;
}

export type CostMeasurementState =
  | "measured"
  | "partial"
  | "not_observed"
  | "invalid";

export type ProviderEventStatus =
  | "succeeded"
  | "timeout"
  | "retryable_failure"
  | "terminal_failure"
  | "model_mismatch"
  | "identity_invalid"
  | "route_unauthorized"
  | "invalid_usage"
  | "invalid_output"
  | "outcome_unknown";

export interface JudgeCalibrationSummaryReadModel extends JsonRecord {
  state: JudgeCalibrationState;
  calibration_id: string | null;
  decision_authority: JudgeDecisionAuthority;
  oracle_comparison_count: number;
  oracle_agreement_count: number;
  oracle_agreement_rate: number | null;
  status_label:
    | "not yet measured"
    | "live, verified against oracle"
    | "live, model-decisive after calibration";
}

export interface TraceReadModel extends JsonRecord {
  request_id: string | null;
  execution_id: string | null;
  parent_execution_id: string | null;
  trace_id: string;
  campaign_id: string;
  attempt_id: string | null;
  operation: string;
  provider: string;
  model: string | null;
  agent_role: "orchestrator" | "red_team" | "judge" | "documentation" | null;
  execution_mode: "deterministic" | "hosted_advisory" | null;
  requested_model: string | null;
  returned_model: string | null;
  model_substituted: boolean;
  upstream_provider: string | null;
  provider_request_id: string | null;
  configuration_set_sha256: string | null;
  role_configuration_sha256: string | null;
  generation_policy_sha256: string | null;
  physical_attempts: number | null;
  method: string | null;
  destination_host: string | null;
  relative_path: string | null;
  status: string;
  status_code: number | null;
  error_code: string | null;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
  request_bytes: number;
  response_bytes: number | null;
  measured_cost: number | null;
  cost_measurement_state: CostMeasurementState;
  accounting_status: "measured" | "partial" | "unavailable";
  provider_event_ids: string[];
  provider_event_status: ProviderEventStatus | null;
  provider_lineage_state:
    | "not_applicable"
    | "canonical_physical"
    | "historical_not_instrumented";
  currency: string;
  input_tokens: number | null;
  output_tokens: number | null;
  reasoning_tokens: number | null;
  judge_calibration_id: string | null;
  judge_calibration_state: JudgeCalibrationState | null;
  oracle_agreement: boolean | null;
  decision_authority: JudgeDecisionAuthority | null;
  p50_duration_ms: number | null;
  p95_duration_ms: number | null;
  langfuse_status:
    | "not_attempted"
    | "disabled"
    | "queued"
    | "exported"
    | "error"
    | "historical_not_instrumented";
  langfuse_verified_at: string | null;
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
  agent_role: "orchestrator" | "red_team" | "judge" | "documentation" | null;
  record_kind: "campaign" | "agent";
  execution_mode: "deterministic" | "hosted_advisory" | null;
  measured_cost: number | null;
  cost_measurement_state: CostMeasurementState | "not_applicable";
  accounting_status: "not_applicable" | "measured" | "partial" | "unavailable";
  provider_event_ids: string[];
  currency: string;
  request_count: number;
  execution_count: number;
  attempt_count: number;
  confirmed_finding_count: number;
  average_cost_per_request: number | null;
  input_tokens: number | null;
  output_tokens: number | null;
  reasoning_tokens: number | null;
  token_observation_count: number;
  physical_call_count: number;
  physical_call_count_state: "not_applicable" | "exact" | "lower_bound";
  provider_budget: AgentBudgetReadModel | null;
  p50_duration_ms: number | null;
  p95_duration_ms: number | null;
  budget_usd: number | null;
  budget_utilization: number | null;
  duration_ms: number;
  execution_profile: "synthetic" | "live";
  started_at: string;
  ended_at: string | null;
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
  hosted_run: HostedRunBindingReadModel | null;
}

export interface CampaignSuiteBatchReadModel extends CampaignTemplateReadModel {
  ordinal: number;
  batch_id: string;
  physical_request_count: number;
}

export interface CampaignSuiteTemplateReadModel extends JsonRecord {
  suite_id: string;
  title: string;
  case_count: number;
  physical_request_count: number;
  categories: string[];
  batches: CampaignSuiteBatchReadModel[];
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
  campaign_suite_templates?: CampaignSuiteTemplateReadModel[];
  created_at: string;
}

export interface TargetCatalogEntryReadModel extends JsonRecord {
  target_id: string;
  version: string;
  name: string;
  environment: "local" | "staging" | "production";
  synthetic_data_only: true;
  surface_count: number;
  registration_state: "available" | "registered" | "conflict";
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

interface AgentAssignmentReadModelBase extends JsonRecord {
  role: "orchestrator" | "red_team" | "judge" | "documentation";
  provider: string;
  model: string;
  prompt_sha256: string | null;
  prompt_version: string | null;
  execution_mode: "deterministic" | "hosted_advisory";
  activation_state: "active" | "staged_pending_authorization";
  version: number;
  configuration_sha256: string;
  configured_at: string | null;
  configured_by: string | null;
}

export type AgentAssignmentReadModel = AgentAssignmentReadModelBase & (
  | {
      resolved_model: string;
      upstream_provider: string;
    }
  | {
      resolved_model: null;
      upstream_provider: null;
    }
);

export interface AgentAcceptanceExecutionReadModel extends JsonRecord {
  scope: "agent_acceptance";
  agent_role: "orchestrator" | "red_team" | "judge" | "documentation";
  acceptance_run_id: string;
  acceptance_attempt_id: string;
  execution_id: string;
  parent_execution_id: string | null;
  configuration_set_sha256: string;
  returned_model: string;
  upstream_provider: string;
  trace_id: string;
  measured_cost: number;
  cost_measurement_state: "measured";
  provider_event_ids: string[];
  currency: "USD";
  input_tokens: number;
  output_tokens: number;
  reasoning_tokens: number;
  langfuse_status: "queued" | "exported";
  langfuse_verified_at: string | null;
  finished_at: string;
}

export interface AgentPromptReadModel extends JsonRecord {
  role: "orchestrator" | "red_team" | "judge" | "documentation";
  prompt_version: string;
  prompt_sha256: string;
  system_prompt: string;
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
  latest_acceptance_execution: AgentAcceptanceExecutionReadModel | null;
  execution_count: number;
  hosted_execution_count: number;
  running_count: number;
  succeeded_count: number;
  failed_count: number;
  skipped_count: number;
  measured_cost: number | null;
  cost_measurement_state: CostMeasurementState | "not_applicable";
  accounting_status: "not_applicable" | "measured" | "partial" | "unavailable";
  provider_event_ids: string[];
  currency: string;
  input_tokens: number | null;
  output_tokens: number | null;
  reasoning_tokens: number | null;
  token_observation_count: number;
  physical_call_count: number;
  physical_call_count_state: "not_applicable" | "exact" | "lower_bound";
  provider_budget: AgentBudgetReadModel;
  judge_calibration: JudgeCalibrationSummaryReadModel | null;
  average_duration_ms: number | null;
  p50_duration_ms: number | null;
  p95_duration_ms: number | null;
  langfuse_not_attempted_count: number;
  langfuse_disabled_count: number;
  langfuse_queued_count: number;
  langfuse_exported_count: number;
  langfuse_error_count: number;
  langfuse_verified_count: number;
  last_langfuse_verified_at: string | null;
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
  returned_model: string | null;
  model_substituted: boolean;
  upstream_provider: string | null;
  provider_request_id: string | null;
  execution_mode: "deterministic" | "hosted_advisory";
  configuration_version: number;
  configuration_set_sha256: string | null;
  role_configuration_sha256: string | null;
  generation_policy_sha256: string | null;
  input_sha256: string;
  output_sha256: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  reasoning_tokens: number | null;
  physical_attempts: number | null;
  measured_cost: number | null;
  cost_measurement_state: CostMeasurementState;
  accounting_status: "measured" | "partial" | "unavailable";
  provider_event_ids: string[];
  provider_event_status: ProviderEventStatus | null;
  provider_lineage_state:
    | "not_applicable"
    | "canonical_physical"
    | "historical_not_instrumented";
  currency: string;
  trace_id: string;
  langfuse_status: "not_attempted" | "disabled" | "queued" | "exported" | "error";
  langfuse_verified_at: string | null;
  detail: JsonRecord;
  judge_calibration_id: string | null;
  judge_calibration_state: JudgeCalibrationState | null;
  oracle_agreement: boolean | null;
  decision_authority: JudgeDecisionAuthority | null;
  error_code: string | null;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
}

export interface AgentPromptSnapshotMessageReadModel extends JsonRecord {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
}

export interface AgentPromptSnapshotRedactionReadModel extends JsonRecord {
  path: string;
  reason: string;
  replacement: string;
}

export interface AgentPromptSnapshotReadModel extends JsonRecord {
  execution_id: string;
  campaign_run_id: string;
  attempt_id: string | null;
  agent_role: "orchestrator" | "red_team" | "judge" | "documentation";
  system_prompt_version: string;
  system_prompt_sha256: string;
  system_prompt_content: string;
  provider_messages: AgentPromptSnapshotMessageReadModel[];
  transcript_sha256: string;
  redactions: AgentPromptSnapshotRedactionReadModel[];
  created_at: string;
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
  runtime_state: "idle" | "running" | "evidenced" | "error";
  evidenced_finding_count: number;
  last_error_code: string | null;
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
  confirmed_finding_count: number;
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
  execution_count: number | null;
  measured_cost_usd: number | null;
  accounting_status: "not_applicable" | "measured" | "partial" | "unavailable" | null;
  currency: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  reasoning_tokens: number | null;
  token_observation_count: number | null;
  langfuse_not_attempted_count: number | null;
  langfuse_disabled_count: number | null;
  langfuse_queued_count: number | null;
  langfuse_exported_count: number | null;
  langfuse_error_count: number | null;
  langfuse_verified_count: number | null;
  last_langfuse_verified_at: string | null;
  langfuse_status: string | null;
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
