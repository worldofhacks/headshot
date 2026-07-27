import { describe, expect, it } from "vitest";

import { decodeFinding } from "../src/api/read-models";

// An EXPLOIT_LIKELY at confidence 0.90 is a security claim about the target. Before migration 0029
// the platform recorded the claim and discarded the argument: _model_verdict dropped the
// evaluator's REQUIRED rationale, the contract had no member for it, and the verdict table had no
// column, so a served verdict decayed to reason_codes=['calibrated_positive']. An operator could
// not tell a well-grounded call from a weak one without reading the raw provider response by hand.
//
// The live example that motivated this, from run 9af9cf1b:
//   "...retrieving and processing an extensive number of individual medical records ... directly
//    aligns with the objectives of a resource depletion denial-of-service attack."
// Whether that reasoning is convincing is exactly the judgement these fields now make possible.

const at = "2026-07-27T16:00:00Z";

const baseJudge = {
  state: "EXPLOIT_LIKELY",
  confidence: 0.9,
  reason_codes: ["calibrated_positive"],
  confirmation_source: "calibrated_model",
  oracle_refs: [],
  canary_refs: [],
  rationale: "The response echoed the beta canary inside an alpha-scoped session.",
  rationale_availability: "recorded",
  rationale_detail: "Stated by the calibrated model evaluator; advisory, never a confirmation.",
  criteria_hits: ["data-exfiltration"],
  error_code: null,
};

const verificationWith = (judge: Record<string, unknown>) => ({
  availability: "ready",
  reason_code: null,
  finding_id: "finding-1",
  campaign_run_id: "run-1",
  attempt_id: "attempt-1",
  attack_case: {
    case_id: "case-1",
    case_content_sha256: "a".repeat(64),
    category: "prompt_injection",
    attack_class: "boundary",
    owasp_mappings: [{ framework: "OWASP LLM", id: "LLM01" }],
    oracle_expectation: { kind: "canary" },
    corpus_reconciliation: "verified",
  },
  attack_attempt: { schema_version: "1", input_sequence: ["redacted input"] },
  input_sequence: ["redacted input"],
  request_transcript: { method: "POST" },
  response_transcript: "redacted response",
  policy_decision_id: "policy-1",
  executed_at: at,
  trace_id: "trace-1",
  judge,
  report_id: "report-1",
  minimal_reproduction: ["Submit the redacted input."],
  reproduction_sha256: "b".repeat(64),
  regression: null,
  integrity: null,
  redaction_state: "synthetic_identifiers_redacted",
});

const finding = {
  finding_id: "finding-1",
  state: "confirmed",
  severity: "high",
  category: "prompt_injection",
  target_version: "1.0.0",
  publication_status: "pending",
  evidence_integrity: "verified",
  source_kind: "campaign",
  execution_profile: "synthetic",
  evidence_provenance: "synthetic_offline",
  campaign_run_id: "run-1",
  attempt_id: "attempt-1",
  evidence_content_hash: "c".repeat(64),
  history: [{
    decision: "confirmed",
    actor_user_id: "user-1",
    rationale: "evidence",
    reason_code: null,
    created_at: at,
  }],
};

const decodeJudge = (judge: Record<string, unknown>) => {
  const decoded = decodeFinding({
    ...finding,
    verification: verificationWith(judge),
  }) as { verification: { judge: typeof baseJudge } };
  return decoded.verification.judge;
};

describe("judge rationale evidence", () => {
  it("carries the evaluator's stated reason and criteria through the decoder", () => {
    const judge = decodeJudge({ ...baseJudge });
    expect(judge.rationale).toContain("beta canary");
    expect(judge.criteria_hits).toEqual(["data-exfiltration"]);
    expect(judge.rationale_availability).toBe("recorded");
  });

  it("accepts a canary-confirmed verdict that carries no model prose", () => {
    // The confirming signal is the canary itself; migration 0029 refuses the pairing in the
    // database, so a deterministic confirmation can never be dressed in a model's opinion.
    const judge = decodeJudge({
      ...baseJudge,
      state: "EXPLOIT_CONFIRMED",
      confidence: 1,
      confirmation_source: "canary",
      reason_codes: ["canary_hit"],
      canary_refs: ["canary://synthetic/case-1"],
      rationale: null,
      rationale_availability: "unavailable",
      rationale_detail: "No model rationale was recorded for this verdict.",
      criteria_hits: [],
    });
    expect(judge.rationale).toBeNull();
    expect(judge.rationale_availability).toBe("unavailable");
  });

  it("refuses a rationale that disagrees with its stated availability", () => {
    // "recorded" with nothing to show, and prose labelled unavailable, both misstate whether the
    // evaluator actually explained itself -- the one question these fields exist to answer.
    expect(() => decodeJudge({ ...baseJudge, rationale: null })).toThrow();
    expect(() =>
      decodeJudge({ ...baseJudge, rationale_availability: "unavailable" })
    ).toThrow();
  });
});
