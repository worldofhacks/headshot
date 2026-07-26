import { useRef, useState } from "react";

import { ApiClientError, type ApiClient } from "../api/client";
import type { CommandAcknowledgement } from "../api/contracts";

const unavailableMessage = (reasonCode: string | undefined): string => {
  switch (reasonCode) {
    case "provider_credentials_runner_unverified":
      return "Runner has not verified all four hosted provider bindings.";
    case "four_role_hosted_runtime_required":
      return "A complete hosted four-LLM configuration is required.";
    case "hosted_runtime_not_composed":
      return "The private Runner is not composed for hosted four-LLM execution.";
    case "runner_heartbeat_stale":
    case "runner_execution_composition_missing":
      return "The private Runner is not ready to accept this campaign.";
    default:
      return reasonCode
        ? `Server refused this action: ${reasonCode.replaceAll("_", " ")}.`
        : "The server connection for this action is not ready.";
  }
};

const failureMessage = (error: unknown): string => {
  if (error instanceof ApiClientError && error.status === 403) {
    return "Backend denied this identity or exact scope (403). Refresh the session and verify that the original Operator is launching a separately approved request.";
  }
  if (error instanceof ApiClientError && error.status === 401) {
    return "Authentication expired. Sign in again before retrying.";
  }
  return "The command was not acknowledged. No state change was assumed.";
};

export function CommandButton({
  client,
  path,
  payload,
  label,
  allowed,
  unavailableReason,
  destructive = false,
  onAcknowledged,
}: {
  client: ApiClient;
  path: string;
  payload: object;
  label: string;
  allowed: boolean;
  unavailableReason?: string;
  destructive?: boolean;
  onAcknowledged?: (acknowledgement: CommandAcknowledgement) => void;
}) {
  const [state, setState] = useState<"idle" | "sending" | "acknowledged" | "unavailable" | "conflict" | "error">(
    "idle",
  );
  const [acknowledgement, setAcknowledgement] = useState<string | null>(null);
  const [detail, setDetail] = useState<string | null>(null);
  const action = useRef<{ identity: string; idempotencyKey: string } | null>(null);

  const execute = async () => {
    setState("sending");
    setAcknowledgement(null);
    setDetail(null);
    try {
      const identity = `${path}\n${JSON.stringify(payload)}`;
      if (action.current?.identity !== identity) {
        action.current = { identity, idempotencyKey: globalThis.crypto.randomUUID() };
      }
      const response = await client.command(
        path,
        payload,
        undefined,
        action.current.idempotencyKey,
      );
      if (response.status === "unavailable") {
        setDetail(unavailableMessage(response.reason_code));
        setState("unavailable");
        return;
      }
      if (response.status === "conflict") {
        setDetail(
          response.reason_code
            ? `Server rejected this immutable request: ${response.reason_code.replaceAll("_", " ")}.`
            : "Server rejected an immutable or idempotency conflict.",
        );
        setState("conflict");
        return;
      }
      setAcknowledgement(response.acknowledgement_id ?? null);
      setState("acknowledged");
      onAcknowledged?.(response);
    } catch (error) {
      setDetail(failureMessage(error));
      setState("error");
    }
  };

  return (
    <div className="command-control">
      <button
        type="button"
        className={`button ${destructive ? "button-danger" : "button-primary"}`}
        disabled={!allowed || state === "sending"}
        onClick={() => void execute()}
        title={!allowed ? unavailableReason : undefined}
      >
        {state === "sending" ? "Waiting for server…" : label}
      </button>
      {!allowed && <span className="command-note">Requires: {unavailableReason || "permission required"}</span>}
      {state === "acknowledged" && (
        <span className="command-note success">
          Server acknowledged{acknowledgement ? ` · ${acknowledgement}` : ""}. Refreshing state.
        </span>
      )}
      {state === "unavailable" && <span className="command-note">{detail}</span>}
      {state === "conflict" && <span className="command-note error">{detail}</span>}
      {state === "error" && <span className="command-note error">{detail}</span>}
    </div>
  );
}
