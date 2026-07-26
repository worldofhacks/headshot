import { useRef, useState } from "react";

import type { ApiClient } from "../api/client";
import type { CommandAcknowledgement } from "../api/contracts";

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
  // The server always says WHY it refused — a reason_code on an unavailable/conflict response, or
  // an ApiClientError message on a 4xx. Discarding both left every refusal rendering as the same
  // "not acknowledged", which is indistinguishable from a network failure.
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
        setDetail(response.reason_code ?? null);
        setState("unavailable");
        return;
      }
      if (response.status === "conflict") {
        setDetail(response.reason_code ?? null);
        setState("conflict");
        return;
      }
      setAcknowledgement(response.acknowledgement_id ?? null);
      setState("acknowledged");
      onAcknowledged?.(response);
    } catch (error) {
      setDetail(error instanceof Error ? error.message : null);
      setState("error");
    }
  };

  // Built as whole strings, not JSX interpolation: `{a}{cond ? b : ""}{c}` renders as separate
  // text nodes, which breaks exact-text matching and fragments the message for assistive tech.
  const suffix = detail ? `: ${detail}` : "";

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
      {state === "unavailable" && (
        <span className="command-note">{`The server is not ready for this action${suffix}.`}</span>
      )}
      {state === "conflict" && (
        <span className="command-note error">{`Server rejected an immutable or idempotency conflict${suffix}.`}</span>
      )}
      {state === "error" && (
        <span className="command-note error">{`The command was not acknowledged${suffix}.`}</span>
      )}
    </div>
  );
}
