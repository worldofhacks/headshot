export const FINDING_DECISION_OPTIONS = [
  {
    decision: "approved",
    reasonCode: "human_confirmed",
    label: "Human-confirmed finding",
  },
  {
    decision: "rejected",
    reasonCode: "not_a_real_exploit",
    label: "Not a real exploit",
  },
  {
    decision: "rejected",
    reasonCode: "insufficient_evidence",
    label: "Insufficient evidence",
  },
  {
    decision: "rejected",
    reasonCode: "duplicate_finding",
    label: "Duplicate finding",
  },
  {
    decision: "rejected",
    reasonCode: "outside_authorized_scope",
    label: "Outside authorized scope",
  },
] as const;

export type FindingDecision = (typeof FINDING_DECISION_OPTIONS)[number]["decision"];
export type FindingDecisionReasonCode =
  (typeof FINDING_DECISION_OPTIONS)[number]["reasonCode"];

export const FINDING_DECISION_REASON_CODES = FINDING_DECISION_OPTIONS.map(
  (option) => option.reasonCode,
);

export const reasonCodeMatchesDecision = (
  reasonCode: FindingDecisionReasonCode | "",
  decision: string,
) => FINDING_DECISION_OPTIONS.some(
  (option) => option.reasonCode === reasonCode && option.decision === decision,
);
