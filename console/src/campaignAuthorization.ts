import type { JsonRecord } from "./api/contracts";
import type {
  CampaignTemplateReadModel,
  HostedRunBindingReadModel,
  SafetyCapsReadModel,
} from "./types";

export type ExactWorkloadCaps = Pick<
  SafetyCapsReadModel,
  "logical_case_limit" | "physical_request_limit" | "target_retries_per_turn"
> & {
  logical_case_limit: number;
  physical_request_limit: number;
  target_retries_per_turn: number;
};

export interface CampaignCapSelection {
  budget_usd: number;
  max_attempts_per_run: number;
  target_requests_per_second: number;
  run_timeout_seconds: number;
}

export interface CampaignAuthorizationPayload extends JsonRecord {
  target_id: string;
  target_version: string;
  surface_id: string;
  surface_version: string;
  corpus_id: string;
  corpus_hash: string;
  execution_profile: "synthetic" | "live";
  caps: SafetyCapsReadModel;
  run_nonce: string;
  hosted_run: HostedRunBindingReadModel;
  expires_in_seconds: number;
}

export const AUTHORIZATION_EXECUTION_MARGIN_SECONDS = 300;
export const MAX_AUTHORIZATION_EXPIRY_SECONDS = 3_600;

const positiveFinite = (value: number) => Number.isFinite(value) && value > 0;
const positiveSafeInteger = (value: number) =>
  Number.isSafeInteger(value) && value > 0;
const sha256 = (value: string) => /^[a-f0-9]{64}$/.test(value);

/**
 * Give an approved run five minutes of bounded queue/start overhead beyond its
 * exact timeout. Flooring plus one makes the resulting expiry strictly greater
 * than timeout + margin, including for fractional timeout values.
 */
export const authorizationExpirySeconds = (runTimeoutSeconds: number): number | null => {
  if (!positiveFinite(runTimeoutSeconds)) return null;
  const expiresInSeconds = Math.floor(runTimeoutSeconds)
    + AUTHORIZATION_EXECUTION_MARGIN_SECONDS
    + 1;
  return expiresInSeconds <= MAX_AUTHORIZATION_EXPIRY_SECONDS
    ? expiresInSeconds
    : null;
};

/**
 * Return the exact workload envelope only when the server derived it from the
 * selected immutable corpus.
 *
 * `maximum_caps` is a target ceiling and is deliberately not used as workload data.
 * Exact physical-count authorization admits no retry expansion beyond the reviewed
 * workload manifest.
 */
export const exactWorkloadCaps = (
  template: CampaignTemplateReadModel,
): ExactWorkloadCaps | null => {
  const workload = template.workload_caps;
  if (workload === null) return null;
  const logicalCaseLimit = workload.logical_case_limit;
  const physicalRequestLimit = workload.physical_request_limit;
  const targetRetriesPerTurn = workload.target_retries_per_turn;
  if (
    !positiveSafeInteger(logicalCaseLimit)
    || !positiveSafeInteger(physicalRequestLimit)
    || !Number.isSafeInteger(targetRetriesPerTurn)
    || logicalCaseLimit !== template.case_count
    || physicalRequestLimit < logicalCaseLimit
    || targetRetriesPerTurn !== 0
  ) {
    return null;
  }

  return {
    logical_case_limit: logicalCaseLimit,
    physical_request_limit: physicalRequestLimit,
    target_retries_per_turn: targetRetriesPerTurn,
  };
};

export const campaignAuthorizationBlocker = ({
  template,
  selection,
  runNonce,
}: {
  template: CampaignTemplateReadModel | null;
  selection: CampaignCapSelection;
  runNonce: string;
}): string | null => {
  if (template === null) {
    return "server-supplied immutable corpus and campaign template data";
  }
  if (
    !template.target_id.trim()
    || !template.target_version.trim()
    || !template.surface_id.trim()
    || !template.surface_version.trim()
  ) {
    return "an exact server-supplied target and surface binding";
  }
  if (
    !template.corpus_id.trim()
    || !sha256(template.corpus_hash)
    || !positiveSafeInteger(template.case_count)
  ) {
    return "a validated immutable corpus identity, hash, and case count";
  }

  const targetPolicy = template.target_policy;
  if (
    targetPolicy === null
    || !targetPolicy.exact_host.trim()
    || targetPolicy.allowlisted_hosts.length === 0
    || !targetPolicy.allowlisted_hosts.includes(targetPolicy.exact_host)
  ) {
    return "the exact target host bound into a server-supplied allowlist";
  }
  if (
    targetPolicy.synthetic_data_only !== true
    || !targetPolicy.synthetic_data_attestation_ref.trim()
  ) {
    return "a server-verified synthetic-data-only assertion and attestation";
  }

  const workloadCaps = exactWorkloadCaps(template);
  if (workloadCaps === null) {
    return "an exact server-derived workload case and physical-request envelope";
  }

  const maximum = template.maximum_caps;
  if (
    maximum.logical_case_limit === null
    || maximum.physical_request_limit === null
    || maximum.target_retries_per_turn === null
    || !positiveFinite(maximum.budget_usd)
    || !positiveSafeInteger(maximum.max_attempts_per_run)
    || !positiveFinite(maximum.target_requests_per_second)
    || !positiveFinite(maximum.run_timeout_seconds)
    || !positiveSafeInteger(maximum.logical_case_limit)
    || !positiveSafeInteger(maximum.physical_request_limit)
    || !Number.isSafeInteger(maximum.target_retries_per_turn)
    || maximum.target_retries_per_turn < 0
  ) {
    return "complete finite server-supplied target ceilings";
  }
  if (
    workloadCaps.logical_case_limit > maximum.logical_case_limit
    || workloadCaps.logical_case_limit > maximum.max_attempts_per_run
    || workloadCaps.physical_request_limit > maximum.physical_request_limit
    || workloadCaps.target_retries_per_turn > maximum.target_retries_per_turn
  ) {
    return "exact workload caps that fit every server-supplied target ceiling";
  }

  if (template.hosted_run === null) {
    return "a staged server-owned four-role configuration set";
  }
  if (runNonce.trim().length < 16) {
    return "a fresh run nonce of at least 16 characters";
  }
  if (
    !positiveFinite(selection.budget_usd)
    || selection.budget_usd > maximum.budget_usd
  ) {
    return "a positive requested budget within the target ceiling";
  }
  if (
    !positiveSafeInteger(selection.max_attempts_per_run)
    || selection.max_attempts_per_run !== workloadCaps.logical_case_limit
  ) {
    return "an exact maximum-attempt abort limit equal to the workload case count";
  }
  if (
    !positiveFinite(selection.target_requests_per_second)
    || selection.target_requests_per_second > maximum.target_requests_per_second
  ) {
    return "a positive requested target rate within the target ceiling";
  }
  if (
    !positiveFinite(selection.run_timeout_seconds)
    || selection.run_timeout_seconds > maximum.run_timeout_seconds
  ) {
    return "a positive requested timeout within the target ceiling";
  }
  if (authorizationExpirySeconds(selection.run_timeout_seconds) === null) {
    return `a timeout that leaves more than ${AUTHORIZATION_EXECUTION_MARGIN_SECONDS} seconds `
      + `of execution margin within the ${MAX_AUTHORIZATION_EXPIRY_SECONDS}-second authorization window`;
  }
  return null;
};

export const buildCampaignAuthorizationPayload = ({
  template,
  selection,
  runNonce,
}: {
  template: CampaignTemplateReadModel;
  selection: CampaignCapSelection;
  runNonce: string;
}): CampaignAuthorizationPayload | null => {
  if (campaignAuthorizationBlocker({ template, selection, runNonce }) !== null) {
    return null;
  }
  const workloadCaps = exactWorkloadCaps(template);
  const expiresInSeconds = authorizationExpirySeconds(selection.run_timeout_seconds);
  if (
    workloadCaps === null
    || template.hosted_run === null
    || expiresInSeconds === null
  ) return null;

  return {
    target_id: template.target_id,
    target_version: template.target_version,
    surface_id: template.surface_id,
    surface_version: template.surface_version,
    corpus_id: template.corpus_id,
    corpus_hash: template.corpus_hash,
    execution_profile: template.execution_profile,
    caps: {
      ...selection,
      ...workloadCaps,
    },
    run_nonce: runNonce.trim(),
    hosted_run: template.hosted_run,
    expires_in_seconds: expiresInSeconds,
  };
};
