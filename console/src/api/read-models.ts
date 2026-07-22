import { isJsonRecord, type JsonRecord, type Principal } from "./contracts";
import type {
  ApprovalReadModel,
  AttackSurfaceReadModel,
  AttemptReadModel,
  AuditReadModel,
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
    "campaign_run_id",
    "attempt_id",
    "evidence_content_hash",
  ]) {
    string(result, key, name);
  }
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
    "decided_at",
  ]);
  for (const key of ["request_id", "scope_hash", "launcher_user_id"]) string(result, key, name);
  timestamp(result, "expires_at", name);
  timestamp(result, "created_at", name);
  literal(result, "status", ["pending", "approved", "rejected"], name);
  nullableLiteral(result, "decision", ["approved", "rejected"], name);
  nullableString(result, "approver_user_id", name);
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
  exactKeys(result, ["trace_id", "operation", "status", "started_at", "duration_ms"], name);
  for (const key of ["trace_id", "operation", "status"]) string(result, key, name);
  timestamp(result, "started_at", name);
  number(result, "duration_ms", name, { minimum: 0 });
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
    "recorded_at",
  ], name);
  for (const key of ["accounting_id", "campaign_id", "provider", "currency"]) {
    string(result, key, name);
  }
  number(result, "measured_cost", name, { minimum: 0 });
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
  exactKeys(result, ["component_id", "name", "kind", "availability", "heartbeat_at"], name);
  for (const key of ["component_id", "name", "kind", "availability"]) string(result, key, name);
  timestamp(result, "heartbeat_at", name);
  return result as ComponentReadModel;
};

export const decodeComponents: ReadModelDecoder<ComponentReadModel[]> = (value) =>
  records(value, "components", decodeComponent);

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
