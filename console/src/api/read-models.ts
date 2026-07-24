import { isJsonRecord, type JsonRecord, type Principal } from "./contracts";
import type {
  ApprovalReadModel,
  ApprovalDetailReadModel,
  AgentActivityReadModel,
  AgentAssignmentReadModel,
  AgentPromptReadModel,
  AgentReadModel,
  AttackCaseEvidenceReadModel,
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
  EvidenceReadModel,
  EvidenceIntegrityReadModel,
  FindingDetailReadModel,
  FindingHistoryReadModel,
  FindingReadModel,
  FindingVerificationReadModel,
  HostedRunBindingReadModel,
  RegressionDispositionReadModel,
  ReportReadModel,
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
  "hosted_run",
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

const decodeHostedRun = (value: unknown): HostedRunBindingReadModel => {
  const name = "hosted run binding";
  const result = record(value, name);
  exactKeys(result, [
    "configuration_set_sha256",
    "generation_policy_sha256",
    "session_generation",
    "provider_model_call_limit",
    "provider_model_spend_limit_usd",
    "provider_max_retries",
    "provider_max_concurrency",
    "provider_timeout_seconds",
  ], name);
  for (const key of [
    "configuration_set_sha256",
    "generation_policy_sha256",
    "session_generation",
    "provider_model_spend_limit_usd",
  ]) {
    string(result, key, name);
  }
  number(result, "provider_model_call_limit", name, { integer: true, minimum: 1 });
  number(result, "provider_max_retries", name, { integer: true, minimum: 0 });
  if (number(result, "provider_max_concurrency", name, { integer: true }) !== 1) {
    invalid(name);
  }
  number(result, "provider_timeout_seconds", name, { minimum: 0 });
  return result as HostedRunBindingReadModel;
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
  result.hosted_run = result.hosted_run === null ? null : decodeHostedRun(result.hosted_run);
};

export const decodePrincipal: ReadModelDecoder<Principal> = (value) => {
  const name = "principal";
  const result = record(value, name);
  exactKeys(result, [
    "user_id",
    "organization_id",
    "organization_role",
    "organization_permissions",
  ], name);
  for (const key of ["user_id", "organization_id", "organization_role"]) {
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

const decodeAttackCaseEvidence = (value: unknown): AttackCaseEvidenceReadModel => {
  const name = "attack case evidence";
  const result = record(value, name);
  exactKeys(result, [
    "case_id",
    "case_content_sha256",
    "category",
    "attack_class",
    "owasp_mappings",
    "oracle_expectation",
    "corpus_reconciliation",
  ], name);
  string(result, "case_id", name);
  nullableString(result, "case_content_sha256", name);
  nullableString(result, "category", name);
  nullableLiteral(result, "attack_class", ["boundary", "invariant", "regression"], name);
  objectArray(result, "owasp_mappings", name);
  nullableObject(result, "oracle_expectation", name);
  literal(result, "corpus_reconciliation", ["verified", "unavailable"], name);
  return result as AttackCaseEvidenceReadModel;
};

const decodeRegressionDisposition = (value: unknown): RegressionDispositionReadModel => {
  const name = "regression disposition";
  const result = record(value, name);
  exactKeys(result, [
    "disposition_id",
    "state",
    "reason_codes",
    "reproduction_attempted",
    "deterministic_reproduction",
    "passes_for_right_reason",
    "human_approved",
    "admitted",
  ], name);
  for (const key of ["disposition_id", "state"]) string(result, key, name);
  stringArray(result, "reason_codes", name);
  for (const key of [
    "reproduction_attempted",
    "deterministic_reproduction",
    "passes_for_right_reason",
    "human_approved",
    "admitted",
  ]) boolean(result, key, name);
  return result as RegressionDispositionReadModel;
};

const decodeEvidenceIntegrity = (value: unknown): EvidenceIntegrityReadModel => {
  const name = "evidence integrity";
  const result = record(value, name);
  exactKeys(result, [
    "stored_content_sha256",
    "finding_link_sha256",
    "recomputed_content_sha256",
    "evidence_record",
    "finding_link",
    "observability_reconciliation",
    "observability_detail",
  ], name);
  for (const key of [
    "stored_content_sha256",
    "finding_link_sha256",
    "recomputed_content_sha256",
    "observability_detail",
  ]) string(result, key, name);
  literal(result, "evidence_record", ["verified"], name);
  literal(result, "finding_link", ["verified"], name);
  literal(result, "observability_reconciliation", ["unavailable"], name);
  return result as EvidenceIntegrityReadModel;
};

const decodeFindingVerification = (value: unknown): FindingVerificationReadModel => {
  const name = "finding verification";
  const result = record(value, name);
  exactKeys(result, [
    "availability",
    "reason_code",
    "finding_id",
    "campaign_run_id",
    "attempt_id",
    "attack_case",
    "attack_attempt",
    "input_sequence",
    "request_transcript",
    "response_transcript",
    "policy_decision_id",
    "executed_at",
    "trace_id",
    "judge",
    "report_id",
    "minimal_reproduction",
    "reproduction_sha256",
    "regression",
    "integrity",
    "redaction_state",
  ], name);
  literal(result, "availability", ["ready", "unavailable"], name);
  nullableString(result, "reason_code", name);
  string(result, "finding_id", name);
  for (const key of [
    "campaign_run_id",
    "attempt_id",
    "response_transcript",
    "policy_decision_id",
    "trace_id",
    "report_id",
    "reproduction_sha256",
  ]) nullableString(result, key, name);
  nullableTimestamp(result, "executed_at", name);
  const attackCase = nullableObject(result, "attack_case", name);
  result.attack_case = attackCase === null ? null : decodeAttackCaseEvidence(attackCase);
  nullableObject(result, "attack_attempt", name);
  stringArray(result, "input_sequence", name);
  nullableObject(result, "request_transcript", name);
  stringArray(result, "minimal_reproduction", name);
  const judge = nullableObject(result, "judge", name);
  if (judge !== null) {
    exactKeys(judge, [
      "state",
      "confidence",
      "reason_codes",
      "confirmation_source",
      "error_code",
    ], "Judge basis");
    string(judge, "state", "Judge basis");
    nullableNumber(judge, "confidence", "Judge basis");
    if (typeof judge.confidence === "number" && (judge.confidence < 0 || judge.confidence > 1)) {
      invalid("Judge basis");
    }
    stringArray(judge, "reason_codes", "Judge basis");
    nullableLiteral(
      judge,
      "confirmation_source",
      ["oracle", "canary", "calibrated_model", "human"],
      "Judge basis",
    );
    nullableString(judge, "error_code", "Judge basis");
  }
  const regression = nullableObject(result, "regression", name);
  result.regression = regression === null ? null : decodeRegressionDisposition(regression);
  const integrity = nullableObject(result, "integrity", name);
  result.integrity = integrity === null ? null : decodeEvidenceIntegrity(integrity);
  literal(result, "redaction_state", ["synthetic_identifiers_redacted"], name);
  return result as FindingVerificationReadModel;
};

const decodeFindingRecord = (
  value: unknown,
  detail = false,
): FindingReadModel | FindingDetailReadModel => {
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
    ...(detail ? ["verification"] : []),
  ], name);
  for (const key of [
    "finding_id",
    "state",
    "severity",
    "category",
    "target_version",
    "publication_status",
    "source_kind",
    "evidence_provenance",
    "evidence_content_hash",
  ]) {
    string(result, key, name);
  }
  nullableString(result, "campaign_run_id", name);
  nullableString(result, "attempt_id", name);
  literal(result, "evidence_integrity", ["verified"], name);
  literal(result, "execution_profile", ["synthetic", "live"], name);
  result.history = records(result.history, "finding history", decodeFindingHistory);
  if (detail) result.verification = decodeFindingVerification(result.verification);
  return result as FindingReadModel | FindingDetailReadModel;
};

export const decodeFindings: ReadModelDecoder<FindingReadModel[]> = (value) =>
  records(value, "findings", (entry) => decodeFindingRecord(entry) as FindingReadModel);

export const decodeFinding: ReadModelDecoder<FindingDetailReadModel> = (value) =>
  decodeFindingRecord(value, true) as FindingDetailReadModel;

const decodeApproval = (
  value: unknown,
  detail = false,
): ApprovalReadModel | ApprovalDetailReadModel => {
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
    "expired",
    "consumed",
    ...(detail ? ["campaign_run_id", "verification_chain"] : []),
  ]);
  for (const key of ["request_id", "scope_hash", "launcher_user_id"]) string(result, key, name);
  timestamp(result, "expires_at", name);
  timestamp(result, "created_at", name);
  literal(result, "status", ["pending", "approved", "rejected"], name);
  nullableLiteral(result, "decision", ["approved", "rejected"], name);
  nullableString(result, "approver_user_id", name);
  boolean(result, "self_approval_override", name);
  boolean(result, "expired", name);
  boolean(result, "consumed", name);
  nullableTimestamp(result, "decided_at", name);
  if (detail) {
    nullableString(result, "campaign_run_id", name);
    result.verification_chain = records(
      result.verification_chain,
      "approval verification chain",
      decodeFindingVerification,
    );
  }
  return result as ApprovalReadModel | ApprovalDetailReadModel;
};

export const decodeApprovals: ReadModelDecoder<ApprovalReadModel[]> = (value) =>
  records(value, "approvals", (entry) => decodeApproval(entry) as ApprovalReadModel);

export const decodeApprovalDetail: ReadModelDecoder<ApprovalDetailReadModel> = (value) =>
  decodeApproval(value, true) as ApprovalDetailReadModel;

const decodeReport = (value: unknown): ReportReadModel => {
  const name = "report";
  const result = record(value, name);
  exactKeys(result, [
    "schema_version",
    "report_id",
    "finding_id",
    "campaign_run_id",
    "attempt_id",
    "source_case_id",
    "severity",
    "category",
    "description",
    "clinical_impact",
    "minimal_reproduction",
    "reproduction_sha256",
    "observed_behavior",
    "expected_behavior",
    "recommended_remediation",
    "status",
    "fix_validation",
    "evidence_references",
    "publication_state",
    "regression",
    "report_integrity",
    "created_at",
    "verification",
  ], name);
  literal(result, "schema_version", ["1"], name);
  for (const key of [
    "report_id",
    "finding_id",
    "campaign_run_id",
    "attempt_id",
    "source_case_id",
    "category",
    "description",
    "clinical_impact",
    "reproduction_sha256",
    "observed_behavior",
    "expected_behavior",
    "recommended_remediation",
  ]) string(result, key, name);
  literal(result, "severity", ["low", "medium", "high", "critical"], name);
  literal(result, "status", [
    "draft",
    "validated",
    "remediation_pending",
    "fix_pending",
    "fixed",
    "regressed",
  ], name);
  literal(result, "publication_state", [
    "draft_unpublished",
    "blocked_pending_human_approval",
  ], name);
  literal(result, "report_integrity", ["verified"], name);
  stringArray(result, "minimal_reproduction", name);
  stringArray(result, "evidence_references", name);
  const fixValidation = object(result, "fix_validation", name);
  exactKeys(fixValidation, ["state", "summary", "evidence_references"], "fix validation");
  literal(
    fixValidation,
    "state",
    ["not_run", "failed", "passed_for_right_reason"],
    "fix validation",
  );
  string(fixValidation, "summary", "fix validation");
  stringArray(fixValidation, "evidence_references", "fix validation");
  const regression = nullableObject(result, "regression", name);
  result.regression = regression === null ? null : decodeRegressionDisposition(regression);
  timestamp(result, "created_at", name);
  result.verification = decodeFindingVerification(result.verification);
  return result as ReportReadModel;
};

export const decodeReports: ReadModelDecoder<ReportReadModel[]> = (value) =>
  records(value, "reports", decodeReport);

export const decodeReportDetail: ReadModelDecoder<ReportReadModel> = decodeReport;

const decodeTrace = (value: unknown): TraceReadModel => {
  const name = "trace";
  const result = record(value, name);
  exactKeys(result, [
    "request_id",
    "execution_id",
    "parent_execution_id",
    "trace_id",
    "campaign_id",
    "attempt_id",
    "operation",
    "provider",
    "agent_role",
    "execution_mode",
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
    "input_tokens",
    "output_tokens",
    "langfuse_status",
    "request_preview",
    "response_preview",
    "request_sha256",
    "response_sha256",
    "inspection_flags",
    "inspection_owasp_mappings",
  ], name);
  for (const key of ["trace_id", "campaign_id", "operation", "provider", "status", "currency", "langfuse_status"]) string(result, key, name);
  nullableLiteral(result, "agent_role", agentRoles, name);
  nullableLiteral(result, "execution_mode", ["deterministic", "hosted_advisory"], name);
  for (const key of ["request_id", "execution_id", "parent_execution_id", "attempt_id", "method", "destination_host", "relative_path", "error_code", "request_preview", "response_preview", "request_sha256", "response_sha256"]) nullableString(result, key, name);
  nullableNumber(result, "status_code", name);
  timestamp(result, "started_at", name);
  nullableTimestamp(result, "finished_at", name);
  if (result.duration_ms !== null) number(result, "duration_ms", name, { minimum: 0 });
  number(result, "request_bytes", name, { integer: true, minimum: 0 });
  if (result.response_bytes !== null) number(result, "response_bytes", name, { integer: true, minimum: 0 });
  number(result, "measured_cost", name, { minimum: 0 });
  nullableNumber(result, "input_tokens", name);
  nullableNumber(result, "output_tokens", name);
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
    "agent_role",
    "record_kind",
    "measured_cost",
    "currency",
    "request_count",
    "execution_count",
    "attempt_count",
    "confirmed_finding_count",
    "average_cost_per_request",
    "input_tokens",
    "output_tokens",
    "token_observation_count",
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
  nullableLiteral(result, "agent_role", agentRoles, name);
  literal(result, "record_kind", ["campaign", "agent"], name);
  number(result, "measured_cost", name, { minimum: 0 });
  number(result, "request_count", name, { integer: true, minimum: 0 });
  number(result, "execution_count", name, { integer: true, minimum: 0 });
  number(result, "attempt_count", name, { integer: true, minimum: 0 });
  number(result, "confirmed_finding_count", name, { integer: true, minimum: 0 });
  number(result, "average_cost_per_request", name, { minimum: 0 });
  nullableNumber(result, "input_tokens", name);
  nullableNumber(result, "output_tokens", name);
  number(result, "token_observation_count", name, { integer: true, minimum: 0 });
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
    "resolved_model",
    "upstream_provider",
    "prompt_sha256",
    "prompt_version",
    "execution_mode",
    "activation_state",
    "version",
    "configuration_sha256",
    "configured_at",
    "configured_by",
  ], name);
  literal(result, "role", agentRoles, name);
  for (const key of [
    "provider",
    "model",
    "resolved_model",
    "prompt_sha256",
    "prompt_version",
    "configuration_sha256",
  ]) string(result, key, name);
  nullableString(result, "upstream_provider", name);
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
    "p50_duration_ms",
    "p95_duration_ms",
    "langfuse_exported_count",
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
    "langfuse_exported_count",
  ]) number(result, key, name, { integer: true, minimum: 0 });
  number(result, "measured_cost", name, { minimum: 0 });
  nullableNumber(result, "input_tokens", name);
  nullableNumber(result, "output_tokens", name);
  nullableNumber(result, "average_duration_ms", name);
  nullableNumber(result, "p50_duration_ms", name);
  nullableNumber(result, "p95_duration_ms", name);
  nullableTimestamp(result, "last_activity_at", name);
  nullableString(result, "last_status", name);
  nullableString(result, "last_campaign_run_id", name);
  nullableString(result, "last_attempt_id", name);
  return result as AgentReadModel;
};

export const decodeAgents: ReadModelDecoder<AgentReadModel[]> = (value) =>
  records(value, "agents", decodeAgent);

export const decodeAgentPrompt: ReadModelDecoder<AgentPromptReadModel> = (value) => {
  const name = "agent prompt";
  const result = record(value, name);
  exactKeys(result, [
    "role",
    "prompt_version",
    "prompt_sha256",
    "system_prompt",
  ], name);
  literal(result, "role", agentRoles, name);
  for (const key of ["prompt_version", "prompt_sha256", "system_prompt"]) {
    string(result, key, name);
  }
  return result as AgentPromptReadModel;
};

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
    "langfuse_status",
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
    "langfuse_status",
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
  literal(
    result,
    "langfuse_status",
    ["not_attempted", "disabled", "queued", "exported", "error"],
    name,
  );
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
    "confirmed_finding_count",
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
    "confirmed_finding_count",
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
    "execution_count",
    "measured_cost_usd",
    "currency",
    "langfuse_exported_count",
    "langfuse_status",
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
  if (result.execution_count !== null) {
    number(result, "execution_count", name, { integer: true, minimum: 0 });
  }
  if (result.measured_cost_usd !== null) {
    number(result, "measured_cost_usd", name, { minimum: 0 });
  }
  nullableString(result, "currency", name);
  if (result.langfuse_exported_count !== null) {
    number(result, "langfuse_exported_count", name, { integer: true, minimum: 0 });
  }
  nullableString(result, "langfuse_status", name);
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
