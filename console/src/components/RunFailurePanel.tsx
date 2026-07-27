import { shortId, time } from "./Analytics";

export interface RunFailureView {
  stage: string;
  error_code: string;
  attempt_id: string | null;
  execution_id: string | null;
  agent_role: string | null;
  provider: string | null;
  model: string | null;
  retryable: boolean | null;
  retries_remaining: number | null;
  occurred_at: string;
  operator_summary: string;
}

export function RunFailurePanel({ failure }: { failure: RunFailureView }) {
  const retryState = failure.retryable === null
    ? "Unknown"
    : failure.retryable
      ? failure.retries_remaining === null
        ? "Retryable"
        : `Retryable · ${failure.retries_remaining} remaining`
      : "Not retryable";
  return (
    <section
      className="state-notice state-error run-failure-panel"
      role="alert"
      aria-label="Run failure"
    >
      <span className="state-kicker mono">FAILED</span>
      <div className="evidence-stack">
        <strong>{failure.operator_summary}</strong>
        <dl className="detail-grid">
          <div>
            <dt>Stage</dt>
            <dd>{failure.stage}</dd>
          </div>
          <div>
            <dt>Error</dt>
            <dd className="mono">{failure.error_code}</dd>
          </div>
          <div>
            <dt>Retry</dt>
            <dd>{retryState}</dd>
          </div>
          <div>
            <dt>Attempt</dt>
            <dd className="mono">{shortId(failure.attempt_id)}</dd>
          </div>
          <div>
            <dt>Execution</dt>
            <dd className="mono">{shortId(failure.execution_id)}</dd>
          </div>
          <div>
            <dt>Occurred</dt>
            <dd className="mono">{time(failure.occurred_at)}</dd>
          </div>
        </dl>
        {(failure.agent_role || failure.provider || failure.model) && (
          <p className="data-note">
            {[failure.agent_role, failure.provider, failure.model].filter(Boolean).join(" · ")}
          </p>
        )}
      </div>
    </section>
  );
}
