import { isJsonRecord, type JsonRecord, type Principal } from "./contracts";
import type {
  ApprovalReadModel,
  AgentActivityReadModel,
  AgentAssignmentReadModel,
  AgentReadModel,
  AttackSurfaceReadModel,
  AttemptReadModel,
  AuditReadModel,
  BirdseyeAgentActivityReadModel,
  BirdseyeAttentionReadModel,
  BirdseyeCampaignReadModel,
  BirdseyeCategoryOutcomeReadModel,
  BirdseyeEdgeReadModel,
  BirdseyeInstrumentationReadModel,
  BirdseyeNodeReadModel,
  BirdseyeSecurityPostureReadModel,
  BirdseyeSnapshotReadModel,
  BirdseyeTimelineReadModel,
  CampaignReadModel,
  ComponentReadModel,
  ConfigurationReadModel,
  CostReadModel,
  CoverageReadModel,
  EvidenceReadModel,
  FindingHistoryReadModel,
  FindingReadModel,
  ResilienceReadModel,
  SafetyCapsReadModel,
  TargetReadModel,
  ToolScopeReadModel,
  TraceReadModel,
} from "../types";

export type ReadModelDecoder<T> = (value: unknown) => T;

const invalid = (name: string): never => {
  throw new Error(`Invalid ${name} read model`);
};

const record = (value: unknown, name: string): JsonRecord =>
  isJsonRecord(value) ? value : invalid(name);

const exactKeys = (value: JsonRecord, allowed: readonly string[], name: string): void => {
  const allowedSet = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedSet.has(key))) invalid(name);
};

const records = <T>(
  value: unknown,
  name: string,
  decode: (entry: unknown) => T,
): T[] => {
  if (!Array.isArray(value)) return invalid(name);
  return value.map(decode);
};

const string = (value: JsonRecord, key: string, name: string): string => {
  const candidate = value[key];
  if (typeof candidate !== "string" || candidate.length === 0) return invalid(name);
  return candidate;
};

const timestamp = (value: JsonRecord, key: string, name: string): string => {
  const candidate = string(value, key, name);
  if (Number.isNaN(Date.parse(candidate))) return invalid(name);
  return candidate;
};

const nullableString = (value: JsonRecord, key: string, name: string): string | null => {
  const candidate = value[key];
  if (candidate === null) return null;
  if (typeof candidate !== "string" || candidate.length === 0) return invalid(name);
  return candidate;
};

const nullableTimestamp = (value: JsonRecord, key: string, name: string): string | null => {
  const candidate = nullableString(value, key, name);
  if (candidate !== null && Number.isNaN(Date.parse(candidate))) return invalid(name);
  return candidate;
};

const number = (
  value: JsonRecord,
  key: string,
  name: string,
  { integer = false, minimum }: { integer?: boolean; minimum?: number } = {},
): number => {
  const candidate = value[key];
  if (
    typeof candidate !== "number" ||
    !Number.isFinite(candidate) ||
    (integer && !Number.isSafeInteger(candidate)) ||
    (minimum !== undefined && candidate < minimum)
  ) {
    return invalid(name);
  }
  return candidate;
};

const nullableNumber = (value: JsonRecord, key: string, name: string): number | null => {
  if (value[key] === null) return null;
  return number(value, key, name);
};

const boolean = (value: JsonRecord, key: string, name: string): boolean => {
  const candidate = value[key];
  if (typeof candidate !== "boolean") return invalid(name);
  return candidate;
};

const object = (value: JsonRecord, key: string, name: string): JsonRecord =>
  record(value[key], name);

const nullableObject = (value: JsonRecord, key: string, name: string): JsonRecord | null => {
  if (value[key] === null) return null;
  return object(value, key, name);
};

const stringArray = (value: JsonRecord, key: string, name: string): string[] => {
  const candidate = value[key];
  if (!Array.isArray(candidate) || !candidate.every((entry) => typeof entry === "string")) {
    return invalid(name);
  }
  return candidate;
};

const objectArray = (value: JsonRecord, key: string, name: string): JsonRecord[] =>
  records(value[key], name, (entry) => record(entry, name));

const literal = <T extends string>(
  value: JsonRecord,
  key: string,
  allowed: readonly T[],
  name: string,
): T => {
  const candidate = string(value, key, name);
  return allowed.includes(candidate as T) ? candidate as T : invalid(name);
};

const nullableLiteral = <T extends string>(
  value: JsonRecord,
  key: string,
  allowed: readonly T[],
  name: string,
): T | null => {
  const candidate = nullableString(value, key, name);
  return candidate === null || allowed.includes(candidate as T) ? candidate as T | null : invalid(name);
};

const scopeKeys = [
  "target_id",
  "target_version",
  "surface_id",
  "surface_version",
  "adapter_kind",
  "environment",
  "exact_host",
  "auth_mode",
  "explicit_no_auth",
  "auth_posture",
  "protocol",
  "method",
  "relative_path",
  "endpoint",
  "corpus_id",
  "corpus_hash",
  "caps",
  "run_nonce",
  "execution_profile",
] as const;

const decodeCaps = (value: unknown): SafetyCapsReadModel => {
  const name = "safety caps";
  const result = record(value, name);
  exactKeys(result, [
    "budget_usd",
    "max_attempts_per_run",
    "target_requests_per_second",
    "run_timeout_seconds",
  ], name);
  number(result, "budget_usd", name);
  number(result, "max_attempts_per_run", name, { integer: true });
  number(result, "target_requests_per_second", name);
  number(result, "run_timeout_seconds", name);
  return result as SafetyCapsReadModel;
};

const validateScope = (result: JsonRecord, name: string, extraKeys: readonly string[]): void => {
  exactKeys(result, [...scopeKeys, ...extraKeys], name);
  for (const key of [
    "target_id",
    "target_version",
    "surface_id",
    "surface_version",
    "adapter_kind",
    "environment",
    "exact_host",
    "auth_mode",
    "auth_posture",
    "protocol",
    "method",
    "relative_path",
    "endpoint",
    "corpus_id",
    "corpus_hash",
    "run_nonce",
  ]) {
    string(result, key, name);
  }
  boolean(result, "explicit_no_auth", name);
  literal(result, "execution_profile", ["synthetic", "live"], name);
  result.caps = decodeCaps(result.caps);
};

export const decodePrincipal: ReadModelDecoder<Principal> = (value) => {
  const name = "principal";
  const result = record(value, name);
  exactKeys(result, [
    "user_id",
    "session_id",
    "organization_id",
    "organization_role",
    "organization_permissions",
  ], name);
  for (const key of ["user_id", "session_id", "organization_id", "organization_role"]) {
    string(result, key, name);
  }
  stringArray(result, "organization_permissions", name);
  return result as unknown as Principal;
};

const decodeCampaign = (value: unknown): CampaignReadModel => {
  const name = "campaign";
  const result = record(value, name);
  validateScope(result, name, [
    "run_id",
    "authorization_request_id",
    "scope_hash",
    "launcher_user_id",
    "state",
    "attempt_count",
    "created_at",
  ]);
  for (const key of [
    "run_id",
    "authorization_request_id",
    "scope_hash",
    "launcher_user_id",
  ]) {
    string(result, key, name);
  }
  literal(result, "state", ["queued", "running", "complete", "aborted", "failed"], name);
  if (result.attempt_count !== null) {
    number(result, "attempt_count", name, { integer: true, minimum: 0 });
  }
  timestamp(result, "created_at", name);
  return result as CampaignReadModel;
};

export const decodeCampaigns: ReadModelDecoder<CampaignReadModel[]> = (value) =>
  records(value, "campaigns", decodeCampaign);

const decodeAttempt = (value: unknown): AttemptReadModel => {
  const name = "attempt";
  const result = record(value, name);
  exactKeys(result, [
    "attempt_id",
    "ordinal",
    "case_id",
    "content_hash",
    "executed_at",
    "trace_id",
    "verdict",
    "confidence",
    "execution_profile",
    "evidence_provenance",
    "created_at",
  ], name);
  string(result, "attempt_id", name);
  number(result, "ordinal", name, { integer: true, minimum: 0 });
  string(result, "case_id", name);
  nullableString(result, "content_hash", name);
  nullableTimestamp(result, "executed_at", name);
  nullableString(result, "trace_id", name);
  nullableString(result, "verdict", name);
  nullableNumber(result, "confidence", name);
  nullableLiteral(result, "execution_profile", ["synthetic", "live"], name);
  nullableLiteral(result, "evidence_provenance", [
    "synthetic_offline", "live_target", "scan_only", "simulated",
  ], name);
  timestamp(result, "created_at", name);
  return result as AttemptReadModel;
};

export const decodeAttempts: ReadModelDecoder<AttemptReadModel[]> = (value) =>
  records(value, "attempts", decodeAttempt);

export const decodeEvidence: ReadModelDecoder<EvidenceReadModel> = (value) => {
  const name = "evidence";
  const result = record(value, name);
  exactKeys(result, [
    "campaign_run_id",
    "attempt_id",
    "target_id",
    "target_version",
    "surface_id",
    "surface_version",
    "attack_attempt",
    "request_transcript",
    "response_transcript",
    "policy_decision_id",
    "executed_at",
    "trace_id",
    "content_hash",
    "verdict",
    "confidence",
    "execution_profile",
    "evidence_provenance",
  ], name);
  for (const key of ["campaign_run_id", "attempt_id", "content_hash"]) string(result, key, name);
  for (const key of [
    "target_id",
    "target_version",
    "surface_id",
    "surface_version",
    "response_transcript",
    "policy_decision_id",
    "trace_id",
    "verdict",
  ]) {
    nullableString(result, key, name);
  }
  nullableObject(result, "attack_attempt", name);
  nullableObject(result, "request_transcript", name);
  nullableTimestamp(result, "executed_at", name);
  nullableNumber(result, "confidence", name);
  nullableLiteral(result, "execution_profile", ["synthetic", "live"], name);
  nullableLiteral(result, "evidence_provenance", [
    "synthetic_offline", "live_target", "scan_only", "simulated",
  ], name);
  return result as EvidenceReadModel;
};

const decodeFindingHistory = (value: unknown): FindingHistoryReadModel => {
  const name = "finding history";
  const result = record(value, name);
  exactKeys(result, ["decision", "actor_user_id", "rationale", "created_at"], name);
  for (const key of ["decision", "actor_user_id", "rationale"]) string(result, key, name);
  timestamp(result, "created_at", name);
  return result as FindingHistoryReadModel;
};

const decodeFindingRecord = (value: unknown): FindingReadModel => {
  const name = "finding";
  const result = record(value, name);
  exactKeys(result, [
    "finding_id",
    "state",
    "severity",
    "category",
    "target_version",
    "publication_status",
    "evidence_integrity",
    "source_kind",
    "execution_profile",
    "evidence_provenance",
    "campaign_run_id",
    "attempt_id",
    "evidence_content_hash",
    "history",
  ], name);
  for (const key of [
    "finding_id",
    "state",
    "severity",
    "category",
    "target_version",
    "publication_status",
    "evidence_integrity",
    "source_kind",
    "evidence_provenance",
    "evidence_content_hash",
  ]) {
    string(result, key, name);
  }
  nullableString(result, "campaign_run_id", name);
  nullableString(result, "attempt_id", name);
  literal(result, "execution_profile", ["synthetic", "live"], name);
  result.history = records(result.history, "finding history", decodeFindingHistory);
  return result as FindingReadModel;
};

export const decodeFindings: ReadModelDecoder<FindingReadModel[]> = (value) =>
  records(value, "findings", decodeFindingRecord);

export const decodeFinding: ReadModelDecoder<FindingReadModel> = decodeFindingRecord;

const decodeApproval = (value: unknown): ApprovalReadModel => {
  const name = "approval";
  const result = record(value, name);
  validateScope(result, name, [
    "request_id",
    "scope_hash",
    "launcher_user_id",
    "expires_at",
    "created_at",
    "status",
    "decision",
    "approver_user_id",
    "self_approval_override",
    "decided_at",
  ]);
  for (const key of ["request_id", "scope_hash", "launcher_user_id"]) string(result, key, name);
  timestamp(result, "expires_at", name);
  timestamp(result, "created_at", name);
  literal(result, "status", ["pending", "approved", "rejected"], name);
  nullableLiteral(result, "decision", ["approved", "rejected"], name);
  nullableString(result, "approver_user_id", name);
  boolean(result, "self_approval_override", name);
  nullableTimestamp(result, "decided_at", name);
  return result as ApprovalReadModel;
};

export const decodeApprovals: ReadModelDecoder<ApprovalReadModel[]> = (value) =>
  records(value, "approvals", decodeApproval);

const decodeCoverageRecord = (value: unknown): CoverageReadModel => {
  const name = "coverage";
  const result = record(value, name);
  exactKeys(result, [
    "target_version",
    "verified_attempt_count",
    "total_case_count",
    "category_count",
    "execution_profile",
    "evidence_provenance",
    "classifications",
    "owasp_web",
    "owasp_llm",
    "verdict_counts",
    "covered",
    "as_of",
  ], name);
  string(result, "target_version", name);
  number(result, "verified_attempt_count", name, { integer: true, minimum: 0 });
  number(result, "total_case_count", name, { integer: true, minimum: 0 });
  number(result, "category_count", name, { integer: true, minimum: 0 });
  literal(result, "execution_profile", ["synthetic", "live"], name);
  string(result, "evidence_provenance", name);
  stringArray(result, "classifications", name);
  stringArray(result, "owasp_web", name);
  stringArray(result, "owasp_llm", name);
  object(result, "verdict_counts", name);
  boolean(result, "covered", name);
  timestamp(result, "as_of", name);
  return result as CoverageReadModel;
};

export const decodeCoverage: ReadModelDecoder<CoverageReadModel[]> = (value) =>
  records(value, "coverage", decodeCoverageRecord);

const decodeResilienceRecord = (value: unknown): ResilienceReadModel => {
  const name = "resilience";
  const result = record(value, name);
  exactKeys(result, ["regression_id", "version", "status", "recorded_at"], name);
  for (const key of ["regression_id", "version", "status"]) string(result, key, name);
  timestamp(result, "recorded_at", name);
  return result as ResilienceReadModel;
};

export const decodeResilience: ReadModelDecoder<ResilienceReadModel[]> = (value) =>
  records(value, "resilience", decodeResilienceRecord);

const decodeTrace = (value: unknown): TraceReadModel => {
  const name = "trace";
  const result = record(value, name);
  exactKeys(result, [
    "request_id",
    "trace_id",
    "campaign_id",
    "attempt_id",
    "operation",
    "provider",
    "method",
    "destination_host",
    "relative_path",
    "status",
    "status_code",
    "error_code",
    "started_at",
    "finished_at",
    "duration_ms",
    "request_bytes",
    "response_bytes",
    "measured_cost",
    "currency",
    "langfuse_status",
    "request_preview",
    "response_preview",
    "request_sha256",
    "response_sha256",
    "inspection_flags",
    "inspection_owasp_mappings",
  ], name);
  for (const key of ["trace_id", "campaign_id", "operation", "provider", "status", "currency", "langfuse_status"]) string(result, key, name);
  for (const key of ["request_id", "attempt_id", "method", "destination_host", "relative_path", "error_code", "request_preview", "response_preview", "request_sha256", "response_sha256"]) nullableString(result, key, name);
  nullableNumber(result, "status_code", name);
  timestamp(result, "started_at", name);
  nullableTimestamp(result, "finished_at", name);
  number(result, "duration_ms", name, { minimum: 0 });
  number(result, "request_bytes", name, { integer: true, minimum: 0 });
  if (result.response_bytes !== null) number(result, "response_bytes", name, { integer: true, minimum: 0 });
  number(result, "measured_cost", name, { minimum: 0 });
  stringArray(result, "inspection_flags", name);
  stringArray(result, "inspection_owasp_mappings", name);
  return result as TraceReadModel;
};

export const decodeTraces: ReadModelDecoder<TraceReadModel[]> = (value) =>
  records(value, "traces", decodeTrace);

const decodeCost = (value: unknown): CostReadModel => {
  const name = "cost";
  const result = record(value, name);
  exactKeys(result, [
    "accounting_id",
    "campaign_id",
    "provider",
    "measured_cost",
    "currency",
    "request_count",
    "attempt_count",
    "confirmed_finding_count",
    "average_cost_per_request",
    "budget_usd",
    "budget_utilization",
    "duration_ms",
    "execution_profile",
    "started_at",
    "ended_at",
    "recorded_at",
  ], name);
  for (const key of ["accounting_id", "campaign_id", "provider", "currency"]) {
    string(result, key, name);
  }
  number(result, "measured_cost", name, { minimum: 0 });
  number(result, "request_count", name, { integer: true, minimum: 0 });
  number(result, "attempt_count", name, { integer: true, minimum: 0 });
  number(result, "confirmed_finding_count", name, { integer: true, minimum: 0 });
  number(result, "average_cost_per_request", name, { minimum: 0 });
  nullableNumber(result, "budget_usd", name);
  nullableNumber(result, "budget_utilization", name);
  number(result, "duration_ms", name, { minimum: 0 });
  literal(result, "execution_profile", ["synthetic", "live"], name);
  timestamp(result, "started_at", name);
  timestamp(result, "ended_at", name);
  timestamp(result, "recorded_at", name);
  return result as CostReadModel;
};

export const decodeCosts: ReadModelDecoder<CostReadModel[]> = (value) =>
  records(value, "costs", decodeCost);

const decodeSurface = (value: unknown): AttackSurfaceReadModel => {
  const name = "attack surface";
  const result = record(value, name);
  exactKeys(result, [
    "surface_id",
    "version",
    "target_version",
    "content_hash",
    "kind",
    "protocol",
    "method",
    "relative_path",
    "trust_boundary",
    "authentication_required",
    "risk",
    "owasp_mappings",
    "oracle_refs",
    "enabled",
    "created_at",
  ], name);
  for (const key of [
    "surface_id",
    "version",
    "target_version",
    "content_hash",
    "kind",
    "protocol",
    "method",
    "relative_path",
    "trust_boundary",
    "risk",
  ]) {
    string(result, key, name);
  }
  boolean(result, "authentication_required", name);
  objectArray(result, "owasp_mappings", name);
  stringArray(result, "oracle_refs", name);
  boolean(result, "enabled", name);
  timestamp(result, "created_at", name);
  return result as AttackSurfaceReadModel;
};

const decodeTarget = (value: unknown): TargetReadModel => {
  const name = "target";
  const result = record(value, name);
  exactKeys(result, [
    "target_id",
    "version",
    "content_hash",
    "name",
    "adapter_kind",
    "environment",
    "base_url",
    "auth_mode",
    "credential_configured",
    "synthetic_data_only",
    "safety_caps",
    "lifecycle",
    "allowed_lifecycle_transitions",
    "surfaces",
    "campaign_template",
    "created_at",
  ], name);
  for (const key of [
    "target_id",
    "version",
    "content_hash",
    "name",
    "adapter_kind",
    "environment",
    "base_url",
    "auth_mode",
    "lifecycle",
  ]) {
    string(result, key, name);
  }
  boolean(result, "credential_configured", name);
  boolean(result, "synthetic_data_only", name);
  result.safety_caps = decodeCaps(result.safety_caps);
  stringArray(result, "allowed_lifecycle_transitions", name);
  result.surfaces = records(result.surfaces, "attack surfaces", decodeSurface);
  if (result.campaign_template !== null) {
    const template = object(result, "campaign_template", name);
    exactKeys(template, [
      "target_id",
      "target_version",
      "surface_id",
      "surface_version",
      "corpus_id",
      "corpus_hash",
      "case_count",
      "tool_sources",
      "execution_profile",
      "maximum_caps",
    ], "campaign template");
    for (const key of [
      "target_id",
      "target_version",
      "surface_id",
      "surface_version",
      "corpus_id",
      "corpus_hash",
    ]) string(template, key, "campaign template");
    number(template, "case_count", "campaign template", { integer: true, minimum: 1 });
    stringArray(template, "tool_sources", "campaign template");
    literal(template, "execution_profile", ["synthetic", "live"], "campaign template");
    template.maximum_caps = decodeCaps(template.maximum_caps);
  }
  timestamp(result, "created_at", name);
  return result as TargetReadModel;
};

export const decodeTargets: ReadModelDecoder<TargetReadModel[]> = (value) =>
  records(value, "targets", decodeTarget);

export const decodeConfiguration: ReadModelDecoder<ConfigurationReadModel> = (value) => {
  const name = "configuration";
  const result = record(value, name);
  exactKeys(result, [
    "snapshot_id",
    "version",
    "status",
    "configuration",
    "published_at",
    "published_by",
  ], name);
  string(result, "snapshot_id", name);
  number(result, "version", name, { integer: true, minimum: 1 });
  string(result, "status", name);
  object(result, "configuration", name);
  timestamp(result, "published_at", name);
  string(result, "published_by", name);
  return result as ConfigurationReadModel;
};

const decodeComponent = (value: unknown): ComponentReadModel => {
  const name = "component";
  const result = record(value, name);
  exactKeys(result, ["component_id", "name", "kind", "availability", "environment", "detail", "version", "target_access", "capabilities", "owasp_llm", "owasp_web", "operational_scope", "adapter_only_scope", "execution_evidence", "heartbeat_at"], name);
  for (const key of ["component_id", "name", "kind", "environment", "detail", "version", "target_access"]) string(result, key, name);
  for (const key of ["capabilities", "owasp_llm", "owasp_web", "operational_scope", "adapter_only_scope", "execution_evidence"]) stringArray(result, key, name);
  literal(result, "availability", ["operational and evidenced", "adapter integrated, execution deferred", "evaluated and rejected", "blocked pending authorization"], name);
  timestamp(result, "heartbeat_at", name);
  return result as ComponentReadModel;
};

export const decodeComponents: ReadModelDecoder<ComponentReadModel[]> = (value) =>
  records(value, "components", decodeComponent);

const agentRoles = ["orchestrator", "red_team", "judge", "documentation"] as const;

const decodeAgentAssignment = (value: unknown): AgentAssignmentReadModel => {
  const name = "agent assignment";
  const result = record(value, name);
  exactKeys(result, [
    "role",
    "provider",
    "model",
    "execution_mode",
    "activation_state",
    "version",
    "configuration_sha256",
    "configured_at",
    "configured_by",
  ], name);
  literal(result, "role", agentRoles, name);
  for (const key of ["provider", "model", "configuration_sha256"]) string(result, key, name);
  literal(result, "execution_mode", ["deterministic", "hosted_advisory"], name);
  literal(result, "activation_state", ["active", "staged_pending_authorization"], name);
  number(result, "version", name, { integer: true, minimum: 1 });
  nullableTimestamp(result, "configured_at", name);
  nullableString(result, "configured_by", name);
  return result as AgentAssignmentReadModel;
};

const decodeAgent = (value: unknown): AgentReadModel => {
  const name = "agent";
  const result = record(value, name);
  exactKeys(result, [
    "role",
    "display_name",
    "responsibility",
    "trust_level",
    "target_access",
    "input_contract",
    "output_contract",
    "active_assignment",
    "staged_assignment",
    "execution_count",
    "running_count",
    "succeeded_count",
    "failed_count",
    "skipped_count",
    "measured_cost",
    "currency",
    "input_tokens",
    "output_tokens",
    "token_observation_count",
    "average_duration_ms",
    "last_activity_at",
    "last_status",
    "last_campaign_run_id",
    "last_attempt_id",
  ], name);
  literal(result, "role", agentRoles, name);
  for (const key of [
    "display_name",
    "responsibility",
    "trust_level",
    "target_access",
    "input_contract",
    "output_contract",
    "currency",
  ]) string(result, key, name);
  result.active_assignment = decodeAgentAssignment(result.active_assignment);
  result.staged_assignment = result.staged_assignment === null
    ? null
    : decodeAgentAssignment(result.staged_assignment);
  for (const key of [
    "execution_count",
    "running_count",
    "succeeded_count",
    "failed_count",
    "skipped_count",
    "token_observation_count",
  ]) number(result, key, name, { integer: true, minimum: 0 });
  number(result, "measured_cost", name, { minimum: 0 });
  nullableNumber(result, "input_tokens", name);
  nullableNumber(result, "output_tokens", name);
  nullableNumber(result, "average_duration_ms", name);
  nullableTimestamp(result, "last_activity_at", name);
  nullableString(result, "last_status", name);
  nullableString(result, "last_campaign_run_id", name);
  nullableString(result, "last_attempt_id", name);
  return result as AgentReadModel;
};

export const decodeAgents: ReadModelDecoder<AgentReadModel[]> = (value) =>
  records(value, "agents", decodeAgent);

const decodeAgentActivityRecord = (value: unknown): AgentActivityReadModel => {
  const name = "agent activity";
  const result = record(value, name);
  exactKeys(result, [
    "execution_id",
    "campaign_run_id",
    "attempt_id",
    "parent_execution_id",
    "agent_role",
    "status",
    "provider",
    "model",
    "execution_mode",
    "configuration_version",
    "input_sha256",
    "output_sha256",
    "input_tokens",
    "output_tokens",
    "measured_cost",
    "currency",
    "trace_id",
    "detail",
    "error_code",
    "started_at",
    "finished_at",
    "duration_ms",
  ], name);
  for (const key of [
    "execution_id",
    "campaign_run_id",
    "provider",
    "model",
    "input_sha256",
    "currency",
    "trace_id",
  ]) string(result, key, name);
  for (const key of [
    "attempt_id",
    "parent_execution_id",
    "output_sha256",
    "error_code",
  ]) nullableString(result, key, name);
  literal(result, "agent_role", agentRoles, name);
  literal(result, "status", ["running", "succeeded", "failed", "skipped"], name);
  literal(result, "execution_mode", ["deterministic", "hosted_advisory"], name);
  number(result, "configuration_version", name, { integer: true, minimum: 1 });
  nullableNumber(result, "input_tokens", name);
  nullableNumber(result, "output_tokens", name);
  number(result, "measured_cost", name, { minimum: 0 });
  object(result, "detail", name);
  timestamp(result, "started_at", name);
  nullableTimestamp(result, "finished_at", name);
  nullableNumber(result, "duration_ms", name);
  return result as AgentActivityReadModel;
};

export const decodeAgentActivity: ReadModelDecoder<AgentActivityReadModel[]> = (value) =>
  records(value, "agent activity", decodeAgentActivityRecord);

const decodeToolScope = (value: unknown): ToolScopeReadModel => {
  const name = "tool scope";
  const result = record(value, name);
  exactKeys(result, [
    "tool_id",
    "name",
    "version",
    "kind",
    "availability",
    "target_access",
    "target_id",
    "target_version",
    "target_lifecycle",
    "surface_id",
    "surface_version",
    "surface_kind",
    "endpoint",
    "applicability",
    "execution_mode",
    "scope_reason",
    "requires_separate_authorization",
    "capabilities",
    "owasp_llm",
    "owasp_web",
    "reviewed_candidate_count",
    "executed_attempt_count",
    "recorded_scan_count",
    "recorded_finding_count",
    "last_executed_at",
  ], name);
  for (const key of [
    "tool_id",
    "name",
    "version",
    "kind",
    "availability",
    "target_access",
    "target_id",
    "target_version",
    "target_lifecycle",
    "surface_id",
    "surface_version",
    "surface_kind",
    "endpoint",
    "execution_mode",
    "scope_reason",
  ]) string(result, key, name);
  literal(result, "applicability", [
    "in_campaign",
    "companion_scan",
    "platform_assurance",
    "adapter_available",
    "not_applicable",
  ], name);
  boolean(result, "requires_separate_authorization", name);
  for (const key of ["capabilities", "owasp_llm", "owasp_web"]) stringArray(result, key, name);
  for (const key of [
    "reviewed_candidate_count",
    "executed_attempt_count",
    "recorded_scan_count",
    "recorded_finding_count",
  ]) number(result, key, name, { integer: true, minimum: 0 });
  nullableTimestamp(result, "last_executed_at", name);
  return result as ToolScopeReadModel;
};

export const decodeTooling: ReadModelDecoder<ToolScopeReadModel[]> = (value) =>
  records(value, "tooling", decodeToolScope);

const decodeBirdseyeCampaign = (value: unknown): BirdseyeCampaignReadModel => {
  const name = "Birdseye campaign";
  const result = record(value, name);
  exactKeys(result, [
    "run_id",
    "target_id",
    "target_name",
    "target_version",
    "state",
    "execution_profile",
    "scope_hash",
    "attempt_count",
  ], name);
  for (const key of ["run_id", "target_id", "target_name", "target_version", "scope_hash"]) {
    string(result, key, name);
  }
  literal(result, "state", ["queued", "running", "complete", "aborted", "failed"], name);
  literal(result, "execution_profile", ["synthetic", "live"], name);
  number(result, "attempt_count", name, { integer: true, minimum: 0 });
  return result as BirdseyeCampaignReadModel;
};

const decodeBirdseyeInstrumentation = (
  value: unknown,
): BirdseyeInstrumentationReadModel => {
  const name = "Birdseye instrumentation";
  const result = record(value, name);
  exactKeys(result, [
    "budget_usd",
    "measured_cost_usd",
    "budget_utilization",
    "requests_per_second_cap",
    "queue_queued",
    "queue_leased",
    "queue_dead_letter",
    "confirmed_count",
    "likely_count",
    "review_count",
    "healthy_components",
    "total_components",
    "system_state",
  ], name);
  for (const key of [
    "budget_usd",
    "measured_cost_usd",
    "budget_utilization",
    "requests_per_second_cap",
  ]) {
    number(result, key, name, { minimum: 0 });
  }
  for (const key of [
    "queue_queued",
    "queue_leased",
    "queue_dead_letter",
    "confirmed_count",
    "likely_count",
    "review_count",
    "healthy_components",
    "total_components",
  ]) {
    number(result, key, name, { integer: true, minimum: 0 });
  }
  literal(result, "system_state", ["nominal", "degraded", "unavailable"], name);
  return result as BirdseyeInstrumentationReadModel;
};

const decodeBirdseyeSecurityPosture = (
  value: unknown,
): BirdseyeSecurityPostureReadModel => {
  const name = "Birdseye security posture";
  const result = record(value, name);
  exactKeys(result, [
    "tested_categories",
    "required_categories",
    "verified_case_count",
    "held_count",
    "exploited_count",
    "review_count",
    "observed_hold_rate",
    "open_finding_count",
    "in_progress_finding_count",
    "resolved_finding_count",
    "critical_open_finding_count",
    "resilience_direction",
    "current_regression_hold_rate",
    "previous_regression_hold_rate",
    "resilience_delta",
    "cost_per_attempt_usd",
    "cost_velocity_usd_per_minute",
    "projected_cost_at_attempt_cap_usd",
    "priority_category",
    "priority_reason",
    "priority_source",
    "priority_at",
  ], name);
  for (const key of [
    "tested_categories",
    "verified_case_count",
    "held_count",
    "exploited_count",
    "review_count",
    "open_finding_count",
    "in_progress_finding_count",
    "resolved_finding_count",
    "critical_open_finding_count",
  ]) {
    number(result, key, name, { integer: true, minimum: 0 });
  }
  number(result, "required_categories", name, { integer: true, minimum: 1 });
  for (const key of [
    "observed_hold_rate",
    "current_regression_hold_rate",
    "previous_regression_hold_rate",
    "cost_per_attempt_usd",
    "cost_velocity_usd_per_minute",
    "projected_cost_at_attempt_cap_usd",
  ]) {
    if (result[key] !== null) number(result, key, name, { minimum: 0 });
  }
  nullableNumber(result, "resilience_delta", name);
  nullableString(result, "priority_category", name);
  string(result, "priority_reason", name);
  literal(result, "resilience_direction", [
    "improving",
    "steady",
    "degrading",
    "unavailable",
  ], name);
  literal(result, "priority_source", [
    "orchestrator_decision",
    "coverage_policy",
    "unavailable",
  ], name);
  nullableTimestamp(result, "priority_at", name);
  return result as BirdseyeSecurityPostureReadModel;
};

const decodeBirdseyeCategoryOutcome = (
  value: unknown,
): BirdseyeCategoryOutcomeReadModel => {
  const name = "Birdseye category outcome";
  const result = record(value, name);
  exactKeys(result, [
    "target_version",
    "category",
    "verified_case_count",
    "verified_attempt_count",
    "held_count",
    "exploited_count",
    "review_count",
    "last_evaluated_at",
  ], name);
  for (const key of ["target_version", "category"]) string(result, key, name);
  for (const key of [
    "verified_case_count",
    "verified_attempt_count",
    "held_count",
    "exploited_count",
    "review_count",
  ]) {
    number(result, key, name, { integer: true, minimum: 0 });
  }
  nullableTimestamp(result, "last_evaluated_at", name);
  return result as BirdseyeCategoryOutcomeReadModel;
};

const decodeBirdseyeAgentActivity = (
  value: unknown,
): BirdseyeAgentActivityReadModel => {
  const name = "Birdseye agent activity";
  const result = record(value, name);
  exactKeys(result, [
    "execution_id",
    "parent_execution_id",
    "agent_role",
    "status",
    "phase",
    "attempt_id",
    "category",
    "verdict_state",
    "finding_id",
    "error_code",
    "started_at",
    "finished_at",
    "duration_ms",
  ], name);
  for (const key of ["execution_id", "phase"]) string(result, key, name);
  for (const key of [
    "parent_execution_id",
    "attempt_id",
    "category",
    "verdict_state",
    "finding_id",
    "error_code",
  ]) {
    nullableString(result, key, name);
  }
  literal(result, "agent_role", [
    "orchestrator",
    "red_team",
    "judge",
    "documentation",
  ], name);
  literal(result, "status", ["running", "succeeded", "failed", "skipped"], name);
  timestamp(result, "started_at", name);
  nullableTimestamp(result, "finished_at", name);
  if (result.duration_ms !== null) number(result, "duration_ms", name, { minimum: 0 });
  return result as BirdseyeAgentActivityReadModel;
};

const decodeBirdseyeNode = (value: unknown): BirdseyeNodeReadModel => {
  const name = "Birdseye node";
  const result = record(value, name);
  exactKeys(result, [
    "component_id",
    "name",
    "kind",
    "trust_zone",
    "availability",
    "runtime_state",
    "detail",
    "current_task",
    "heartbeat_at",
    "freshness_seconds",
    "is_fresh",
    "healthy_instances",
    "total_instances",
    "p50_latency_ms",
    "p95_latency_ms",
    "queue_depth",
    "target_access",
  ], name);
  for (const key of [
    "component_id",
    "name",
    "kind",
    "availability",
    "detail",
    "current_task",
    "target_access",
  ]) {
    string(result, key, name);
  }
  literal(result, "trust_zone", [
    "human",
    "untrusted",
    "control",
    "execution",
    "evaluation",
    "governance",
    "data",
    "observability",
    "unclassified",
  ], name);
  literal(result, "runtime_state", [
    "ready",
    "working",
    "waiting",
    "degraded",
    "error",
    "stale",
    "unavailable",
  ], name);
  nullableTimestamp(result, "heartbeat_at", name);
  if (result.freshness_seconds !== null) {
    number(result, "freshness_seconds", name, { minimum: 0 });
  }
  boolean(result, "is_fresh", name);
  number(result, "healthy_instances", name, { integer: true, minimum: 0 });
  number(result, "total_instances", name, { integer: true, minimum: 1 });
  for (const key of ["p50_latency_ms", "p95_latency_ms"]) {
    if (result[key] !== null) number(result, key, name, { minimum: 0 });
  }
  if (result.queue_depth !== null) {
    number(result, "queue_depth", name, { integer: true, minimum: 0 });
  }
  return result as BirdseyeNodeReadModel;
};

const decodeBirdseyeEdge = (value: unknown): BirdseyeEdgeReadModel => {
  const name = "Birdseye edge";
  const result = record(value, name);
  exactKeys(result, [
    "edge_id",
    "source_component_id",
    "target_component_id",
    "contract_name",
    "state",
    "attempt_id",
    "last_event_at",
    "detail",
  ], name);
  for (const key of [
    "edge_id",
    "source_component_id",
    "target_component_id",
    "contract_name",
    "detail",
  ]) {
    string(result, key, name);
  }
  literal(result, "state", ["idle", "active", "complete", "error", "stale", "unavailable"], name);
  nullableString(result, "attempt_id", name);
  nullableTimestamp(result, "last_event_at", name);
  return result as BirdseyeEdgeReadModel;
};

const decodeBirdseyeAttention = (value: unknown): BirdseyeAttentionReadModel => {
  const name = "Birdseye attention";
  const result = record(value, name);
  exactKeys(result, [
    "attention_id",
    "priority",
    "kind",
    "title",
    "detail",
    "continuation",
    "record_type",
    "record_id",
    "route",
    "created_at",
  ], name);
  for (const key of [
    "attention_id",
    "title",
    "detail",
    "continuation",
    "record_type",
    "record_id",
    "route",
  ]) {
    string(result, key, name);
  }
  number(result, "priority", name, { integer: true, minimum: 0 });
  literal(result, "kind", ["integrity", "approval", "finding", "component"], name);
  timestamp(result, "created_at", name);
  return result as BirdseyeAttentionReadModel;
};

const decodeBirdseyeTimeline = (value: unknown): BirdseyeTimelineReadModel => {
  const name = "Birdseye timeline";
  const result = record(value, name);
  exactKeys(result, [
    "cursor",
    "event_type",
    "actor",
    "summary",
    "aggregate_type",
    "aggregate_id",
    "created_at",
  ], name);
  number(result, "cursor", name, { integer: true, minimum: 1 });
  for (const key of [
    "event_type",
    "actor",
    "summary",
    "aggregate_type",
    "aggregate_id",
  ]) {
    string(result, key, name);
  }
  timestamp(result, "created_at", name);
  return result as BirdseyeTimelineReadModel;
};

export const decodeBirdseye: ReadModelDecoder<BirdseyeSnapshotReadModel> = (value) => {
  const name = "Birdseye snapshot";
  const result = record(value, name);
  exactKeys(result, [
    "campaign",
    "instrumentation",
    "security_posture",
    "category_outcomes",
    "agent_activity",
    "nodes",
    "edges",
    "attention",
    "timeline",
    "cursor",
    "as_of",
  ], name);
  result.campaign = result.campaign === null
    ? null
    : decodeBirdseyeCampaign(result.campaign);
  result.instrumentation = decodeBirdseyeInstrumentation(result.instrumentation);
  result.security_posture = decodeBirdseyeSecurityPosture(result.security_posture);
  result.category_outcomes = records(
    result.category_outcomes,
    "Birdseye category outcomes",
    decodeBirdseyeCategoryOutcome,
  );
  result.agent_activity = records(
    result.agent_activity,
    "Birdseye agent activity",
    decodeBirdseyeAgentActivity,
  );
  result.nodes = records(result.nodes, "Birdseye nodes", decodeBirdseyeNode);
  result.edges = records(result.edges, "Birdseye edges", decodeBirdseyeEdge);
  result.attention = records(result.attention, "Birdseye attention", decodeBirdseyeAttention);
  result.timeline = records(result.timeline, "Birdseye timeline", decodeBirdseyeTimeline);
  number(result, "cursor", name, { integer: true, minimum: 0 });
  timestamp(result, "as_of", name);
  return result as BirdseyeSnapshotReadModel;
};

const decodeAudit = (value: unknown): AuditReadModel => {
  const name = "audit";
  const result = record(value, name);
  exactKeys(result, [
    "cursor",
    "event_type",
    "aggregate_type",
    "aggregate_id",
    "actor_user_id",
    "payload",
    "created_at",
  ], name);
  number(result, "cursor", name, { integer: true, minimum: 1 });
  for (const key of ["event_type", "aggregate_type", "aggregate_id"]) string(result, key, name);
  nullableString(result, "actor_user_id", name);
  object(result, "payload", name);
  timestamp(result, "created_at", name);
  return result as AuditReadModel;
};

export const decodeAuditHistory: ReadModelDecoder<AuditReadModel[]> = (value) =>
  records(value, "audit history", decodeAudit);
