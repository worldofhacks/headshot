import { Fragment, useRef, useState } from "react";

import {
  count,
  MetricStrip,
  money,
  shortId,
  time,
} from "./Analytics";
import { AdversarialText } from "./AdversarialText";
import { ExpandableEvidence, PromptTranscript } from "./ExpandableEvidence";
import { StateNotice } from "./ResourceView";
import { ApiClientError, type ApiClient } from "../api/client";
import type { Principal } from "../api/contracts";
import { RESOURCE_PATHS } from "../api/paths";
import { decodeEvidence, decodeProviderCallEvidence } from "../api/read-models";
import type {
  ProviderCallEvidenceReadModel,
  ProviderCallReadModel,
  EvidenceReadModel,
} from "../types";
import { PERMISSIONS } from "../types";

const tokenValue = (value: number | null) => value === null ? "—" : count(value);

const callCost = (call: ProviderCallReadModel) => {
  if (call.measured_cost_usd === null) {
    return call.accounting_status === "pending" ? "Pending" : "Unavailable";
  }
  return call.accounting_status === "partial"
    ? `${money(call.measured_cost_usd)} known`
    : money(call.measured_cost_usd);
};

const callStatusTone = (call: ProviderCallReadModel) => (
  call.status === "succeeded"
    ? "success"
    : call.status === "in_flight"
      ? ""
      : "failure"
);

const langfuseProjection = (call: ProviderCallReadModel) => {
  if (call.langfuse_verified_at !== null) {
    return `Agent query-back verified · ${time(call.langfuse_verified_at)}`;
  }
  if (call.langfuse_status === "queued") return "Queued for Langfuse projection";
  if (call.langfuse_status === "error") return "Langfuse projection error";
  if (call.langfuse_status === "disabled") return "Langfuse disabled";
  if (call.langfuse_status === "not_attempted") return "Langfuse not attempted";
  return "Projected · per-call query-back pending";
};

type AttemptEvidenceState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ready"; evidence: EvidenceReadModel }
  | { status: "unavailable"; detail: string };

function AttemptTargetPayloadDisclosure({
  call,
  client,
}: {
  call: ProviderCallReadModel;
  client: ApiClient;
}) {
  const [state, setState] = useState<AttemptEvidenceState>({ status: "idle" });
  const [requested, setRequested] = useState(false);

  if (call.attempt_id === null) {
    return (
      <p className="data-note provider-call-evidence-note">
        This call is not associated with a durable attempt id, so the exact target payload
        cannot be joined from attempt evidence.
      </p>
    );
  }

  if (call.agent_role !== "red_team") {
    return (
      <p className="data-note provider-call-evidence-note">
        This role does not dispatch target traffic.
      </p>
    );
  }

  const load = async () => {
    if (requested) return;
    setRequested(true);
    setState({ status: "loading" });
    try {
      const envelope = await client.read<unknown>(RESOURCE_PATHS.evidence(call.attempt_id ?? ""));
      if (envelope.state !== "ready" && envelope.state !== "stale" && envelope.state !== "degraded") {
        setState({
          status: "unavailable",
          detail: envelope.detail
            ?? envelope.reason_code
            ?? "No attempt evidence was available for this attempt.",
        });
        return;
      }
      if (envelope.data === null) {
        setState({ status: "unavailable", detail: "Attempt evidence was not returned." });
        return;
      }
      const decoded = decodeEvidence(envelope.data);
      setState({ status: "ready", evidence: decoded });
    } catch {
      setState({ status: "unavailable", detail: "Attempt evidence could not be requested." });
    }
  };

  const evidenceLabel = "Prompt sent to target";

  return (
    <ExpandableEvidence
      title={evidenceLabel}
      meta={`attempt ${call.attempt_id}`}
      onToggle={(open) => {
        if (open) void load();
      }}
    >
      {state.status === "idle" && (
        <p className="data-note provider-call-evidence-note">
          Expand to load the exact attempt-level target payload for this call.
        </p>
      )}
      {state.status === "loading" && (
        <StateNotice
          state="loading"
          detail="Requesting target payload from attempt evidence."
        />
      )}
      {state.status === "unavailable" && (
        <StateNotice state="unavailable" detail={state.detail} />
      )}
      {state.status === "ready" && (
        <div className="evidence-stack">
          {state.evidence.request_transcript === null
            ? (
              <StateNotice
                state="empty"
                detail="No target request transcript was recorded for this attempt yet."
              />
            )
            : (
              <ExpandableEvidence title="Target request transcript" meta="from attempt evidence">
                <AdversarialText>{JSON.stringify(state.evidence.request_transcript, null, 2)}</AdversarialText>
              </ExpandableEvidence>
            )}
          {state.evidence.response_transcript === null
            ? null
            : (
              <ExpandableEvidence title="Target response" meta="from attempt evidence">
                <AdversarialText>{state.evidence.response_transcript}</AdversarialText>
              </ExpandableEvidence>
            )}
        </div>
      )}
    </ExpandableEvidence>
  );
}

function roleBehaviorNote(role: ProviderCallReadModel["agent_role"]) {
  if (role === "judge") {
    return (
      <StateNotice
        state="empty"
        detail="Judge role runs adjudication, not target dispatch. Its OpenRouter call does not hit the live target."
      />
    );
  }
  if (role === "red_team") {
    return (
      <StateNotice
        state="empty"
        detail="Red Team target payload is shown under the linked attempt evidence row below."
      />
    );
  }
  return null;
}

type ProviderCallEvidenceState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ready"; evidence: ProviderCallEvidenceReadModel }
  | { status: "unavailable"; detail: string }
  | { status: "error"; reason: string };

function ProviderCallResponseEvidence({
  response,
}: {
  response: NonNullable<ProviderCallEvidenceReadModel["response"]>;
}) {
  return (
    <div className="evidence-stack">
      <dl className="detail-grid">
        <div>
          <dt>Response SHA-256</dt>
          <dd className="mono">{response.sha256}</dd>
        </div>
        <div>
          <dt>Recorded characters</dt>
          <dd className="mono">{count(response.text.length)}</dd>
        </div>
        <div>
          <dt>Bound</dt>
          <dd>
            {response.truncated
              ? "Truncated at the recorded storage bound"
              : "Complete recorded response"}
          </dd>
        </div>
      </dl>
      <AdversarialText>{response.text}</AdversarialText>
    </div>
  );
}

export function ProviderCallEvidenceDisclosure({
  call,
  client,
  principal,
}: {
  call: ProviderCallReadModel;
  client?: ApiClient;
  principal?: Principal;
}) {
  const [state, setState] = useState<ProviderCallEvidenceState>({ status: "idle" });
  const requested = useRef(false);

  if (client === undefined || principal === undefined) {
    return (
      <p className="data-note provider-call-evidence-note">
        Prompt and response evidence is unavailable here: this ledger was rendered without an
        authenticated client and organization principal, so no evidence read can be authorized.
      </p>
    );
  }
  if (!principal.organization_permissions.includes(PERMISSIONS.evidenceRead)) {
    return (
      <StateNotice
        state="unavailable"
        detail="Exact prompt and provider response contents require the org:evidence:read permission."
      />
    );
  }

  // A physical call that has not terminalized has no provider_call_events row yet, so the
  // evidence route correctly finds nothing. Reporting that as "no evidence record" told
  // operators the evidence was missing when it was merely not written yet -- and it showed up
  // almost exclusively on red_team, whose calls run an order of magnitude longer than any other
  // role and so spend far longer in flight. Name the real state instead, and issue no request.
  if (call.status === "in_flight") {
    return (
      <ExpandableEvidence
        title="Prompt & response"
        meta={`physical #${call.physical_sequence} · in flight`}
      >
        <StateNotice
          state="loading"
          detail="This physical call has not returned yet. Its sent prompt and recorded response become readable once the provider responds and the terminal event is written."
        />
      </ExpandableEvidence>
    );
  }

  const load = async () => {
    if (requested.current) return;
    requested.current = true;
    setState({ status: "loading" });
    try {
      const envelope = await client.read<unknown>(
        RESOURCE_PATHS.providerCallEvidence(call.invocation_id),
      );
      if (
        !["ready", "stale", "degraded"].includes(envelope.state)
        || envelope.data === null
      ) {
        setState({
          status: "unavailable",
          detail: envelope.detail
            ?? envelope.reason_code
            ?? "The server returned no evidence record for this physical call.",
        });
        return;
      }
      const evidence = decodeProviderCallEvidence(envelope.data);
      if (
        evidence.invocation_id !== call.invocation_id
        || evidence.agent_role !== call.agent_role
        || evidence.physical_sequence !== call.physical_sequence
      ) {
        setState({ status: "error", reason: "evidence_identity_mismatch" });
        return;
      }
      setState({ status: "ready", evidence });
    } catch (error: unknown) {
      setState({
        status: "error",
        reason: error instanceof ApiClientError ? error.code : "invalid_response_contract",
      });
    }
  };

  return (
    <ExpandableEvidence
      title="Prompt & response"
      meta={`physical #${call.physical_sequence} · permission-gated`}
      onToggle={(open) => {
        if (open) void load();
      }}
    >
      {state.status === "idle" && (
        <p className="data-note provider-call-evidence-note">
          Expand to request the exact sent prompt and the recorded provider response for this
          physical call.
        </p>
      )}
      {state.status === "loading" && (
        <StateNotice
          state="loading"
          detail="Waiting for an authenticated server response."
        />
      )}
      {state.status === "unavailable" && (
        <StateNotice state="unavailable" detail={state.detail} />
      )}
      {state.status === "error" && (
        <StateNotice
          state="error"
          reason={state.reason}
          detail="The recorded prompt and response evidence could not be read for this physical call. Reload the view to request it again."
        />
      )}
      {state.status === "ready" && (
        <div className="evidence-stack">
          {roleBehaviorNote(call.agent_role)}
          {state.evidence.prompt === null
            ? (
              <StateNotice
                state="empty"
                detail="No prompt snapshot was recorded for this execution."
              />
            )
            : (
              <PromptTranscript
                promptVersion={state.evidence.prompt.system_prompt_version}
                promptSha256={state.evidence.prompt.system_prompt_sha256}
                transcriptSha256={state.evidence.prompt.transcript_sha256}
                systemPrompt={state.evidence.prompt.system_prompt_content}
                messages={state.evidence.prompt.provider_messages}
                redactions={state.evidence.prompt.redactions}
              />
            )}
          {state.evidence.response === null
            ? (
              <StateNotice
                state="empty"
                detail="No provider response was recorded for this physical call."
              />
            )
            : <ProviderCallResponseEvidence response={state.evidence.response} />}
          <AttemptTargetPayloadDisclosure call={call} client={client} />
        </div>
      )}
    </ExpandableEvidence>
  );
}

export interface ProviderCallLedgerProps {
  calls: ProviderCallReadModel[];
  limit?: number;
  showSummary?: boolean;
  emptyLabel?: string;
  client?: ApiClient;
  principal?: Principal;
}

export function ProviderCallLedger({
  calls,
  limit,
  showSummary = true,
  emptyLabel = "No OpenRouter physical calls have been recorded for this campaign.",
  client,
  principal,
}: ProviderCallLedgerProps) {
  if (calls.length === 0) {
    return <StateNotice state="empty" detail={emptyLabel} />;
  }
  const ordered = [...calls].sort((left, right) =>
    right.started_at.localeCompare(left.started_at)
  );
  const visible = limit === undefined ? ordered : ordered.slice(0, limit);
  const measured = calls.filter((call) => call.measured_cost_usd !== null);
  const knownSpend = measured.reduce(
    (total, call) => total + (call.measured_cost_usd ?? 0),
    0,
  );
  const retries = calls.filter((call) => call.physical_sequence > 1).length;
  const verified = calls.filter((call) => call.langfuse_verified_at !== null).length;

  return (
    <div className="provider-call-ledger">
      {showSummary && (
        <MetricStrip label="OpenRouter physical-call summary" values={[
          {
            label: "Physical calls",
            value: count(calls.length),
            note: `${count(retries)} retry call${retries === 1 ? "" : "s"}`,
          },
          {
            label: "Measured provider spend",
            value: money(knownSpend),
            note: `${count(measured.length)} calls with measured cost`,
          },
          {
            label: "Langfuse parent verified",
            value: count(verified),
            note: `${count(calls.length - verified)} without parent query-back proof`,
          },
          {
            label: "In flight / failed",
            value: `${count(calls.filter((call) => call.status === "in_flight").length)} / ${count(calls.filter((call) => !["in_flight", "succeeded"].includes(call.status)).length)}`,
            note: "Durable OpenRouter event status",
          },
        ]} />
      )}
      <div className="table-scroll" tabIndex={0}>
        <table
          className="record-table provider-call-table"
          aria-label="OpenRouter physical provider call ledger"
        >
          <thead>
            <tr>
              <th>Attempt</th>
              <th>Agent / call</th>
              <th>Status</th>
              <th>Requested → served model</th>
              <th>Configured → served upstream</th>
              <th>Provider request</th>
              <th>Latency</th>
              <th>Input / output / reasoning</th>
              <th>Measured cost</th>
              <th>Langfuse locator</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((call) => (
              <Fragment key={call.invocation_id}>
                <tr>
                  <td
                    className="mono"
                    title={call.attempt_id ?? "Campaign-scoped execution"}
                  >
                    {call.attempt_id === null ? "campaign" : shortId(call.attempt_id)}
                  </td>
                  <td>
                    <strong>{call.agent_role.replace("_", " ")}</strong>
                    <small className="table-subline mono">physical #{call.physical_sequence}</small>
                    <small className="table-subline mono">
                      {call.agent_role === "red_team"
                        ? "sends target request"
                        : "no live target dispatch"}
                    </small>
                  </td>
                  <td>
                    <span className={`telemetry-status ${callStatusTone(call)}`}>
                      {call.status.replaceAll("_", " ")}
                    </span>
                    {call.error_code !== null && (
                      <small className="table-subline failure-text">{call.error_code}</small>
                    )}
                  </td>
                  <td className="mono" title={`${call.requested_model} → ${call.returned_model ?? "pending"}`}>
                    {call.requested_model}
                    <small className="table-subline">→ {call.returned_model ?? "pending"}</small>
                  </td>
                  <td className="mono">
                    {call.configured_upstream}
                    <small className="table-subline">→ {call.upstream_provider ?? "pending"}</small>
                  </td>
                  <td className="mono" title={call.provider_request_id ?? "Not returned yet"}>
                    {call.provider_request_id === null
                      ? "Pending"
                      : shortId(call.provider_request_id)}
                  </td>
                  <td className="mono">
                    {call.duration_ms === null
                      ? "Running"
                      : `${Math.round(call.duration_ms).toLocaleString()} ms`}
                  </td>
                  <td className="mono">
                    {tokenValue(call.input_tokens)} / {tokenValue(call.output_tokens)} / {tokenValue(call.reasoning_tokens)}
                  </td>
                  <td className="mono">{callCost(call)}</td>
                  <td
                    className="mono"
                    title={`${call.trace_id} · ${call.langfuse_attempt_label ?? "campaign"} · ${call.langfuse_observation_name}`}
                  >
                    <span>{call.langfuse_observation_name}</span>
                    <small className="table-subline">
                      trace {shortId(call.trace_id)} · {langfuseProjection(call)}
                    </small>
                  </td>
                </tr>
                <tr className="provider-call-evidence-row">
                  <td className="provider-call-evidence" colSpan={10}>
                    <ProviderCallEvidenceDisclosure
                      call={call}
                      client={client}
                      principal={principal}
                    />
                  </td>
                </tr>
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
      {visible.length < calls.length && (
        <p className="data-note">
          Showing the newest {count(visible.length)} of {count(calls.length)} physical calls.
        </p>
      )}
      <p className="data-note">
        PostgreSQL is authoritative for calls, tokens, latency, request identity, and measured
        cost. The Langfuse locator identifies the projected child span; “parent verified” means
        the logical agent observation passed remote query-back, not that Headshot inferred a
        second cost record.
      </p>
    </div>
  );
}
