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

const positiveFinite = (value: number) => Number.isFinite(value) && value > 0;

/**
 * Return the exact workload envelope only when the server-owned target ceiling is
 * demonstrably bound to the selected immutable corpus.
 *
 * `maximum_caps` is not treated as a source of convenient UI defaults. Its logical
 * count must equal the immutable template's case count, and its physical request cap
 * must describe a whole number of target turns under the declared retry policy. A
 * missing or incoherent field leaves the campaign unavailable rather than inventing
 * an authorization value in the browser.
 */
export const exactWorkloadCaps = (
  template: CampaignTemplateReadModel,
): ExactWorkloadCaps | null => {
  const logicalCaseLimit = template.maximum_caps.logical_case_limit;
  const physicalRequestLimit = template.maximum_caps.physical_request_limit;
  const targetRetriesPerTurn = template.maximum_caps.target_retries_per_turn;
  if (
    logicalCaseLimit === null
    || physicalRequestLimit === null
    || targetRetriesPerTurn === null
    || !Number.isSafeInteger(logicalCaseLimit)
    || !Number.isSafeInteger(physicalRequestLimit)
    || !Number.isSafeInteger(targetRetriesPerTurn)
    || logicalCaseLimit !== template.case_count
    || logicalCaseLimit < 1
    || physicalRequestLimit < 1
    || targetRetriesPerTurn < 0
  ) {
    return null;
  }

  const retryFactor = targetRetriesPerTurn + 1;
  if (
    !Number.isSafeInteger(retryFactor)
    || physicalRequestLimit % retryFactor !== 0
    || physicalRequestLimit / retryFactor < logicalCaseLimit
  ) {
    return null;
  }

  return {
    logical_case_limit: logicalCaseLimit,
    physical_request_limit: physicalRequestLimit,
    target_retries_per_turn: targetRetriesPerTurn,
  };
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
  const workloadCaps = exactWorkloadCaps(template);
  const maximum = template.maximum_caps;
  if (
    workloadCaps === null
    || template.hosted_run === null
    || runNonce.trim().length < 16
    || !positiveFinite(selection.budget_usd)
    || !positiveFinite(selection.max_attempts_per_run)
    || !positiveFinite(selection.target_requests_per_second)
    || !positiveFinite(selection.run_timeout_seconds)
    || !Number.isSafeInteger(selection.max_attempts_per_run)
    || selection.budget_usd > maximum.budget_usd
    || selection.max_attempts_per_run > maximum.max_attempts_per_run
    || selection.max_attempts_per_run < workloadCaps.logical_case_limit
    || selection.target_requests_per_second > maximum.target_requests_per_second
    || selection.run_timeout_seconds > maximum.run_timeout_seconds
  ) {
    return null;
  }

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
    expires_in_seconds: 900,
  };
};
