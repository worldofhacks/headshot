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
  const action = useRef<{ identity: string; idempotencyKey: string } | null>(null);

  const execute = async () => {
    setState("sending");
    setAcknowledgement(null);
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
        setState("unavailable");
        return;
      }
      if (response.status === "conflict") {
        setState("conflict");
        return;
      }
      setAcknowledgement(response.acknowledgement_id ?? null);
      setState("acknowledged");
      onAcknowledged?.(response);
    } catch {
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
      {!allowed && <span className="command-note">Unavailable: {unavailableReason || "permission required"}</span>}
      {state === "acknowledged" && (
        <span className="command-note success">
          Server acknowledged{acknowledgement ? ` · ${acknowledgement}` : ""}. Refreshing state.
        </span>
      )}
      {state === "unavailable" && <span className="command-note">Server reported this dependency unavailable.</span>}
      {state === "conflict" && <span className="command-note error">Server rejected an immutable or idempotency conflict.</span>}
      {state === "error" && <span className="command-note error">The command was not acknowledged.</span>}
    </div>
  );
}
