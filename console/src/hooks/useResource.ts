import { useCallback, useEffect, useState } from "react";

import { ApiClientError, type ApiClient } from "../api/client";
import type { ResourceEnvelope, ResourceResult } from "../api/contracts";
import type { ReadModelDecoder } from "../api/read-models";

export interface ResourceController<T> {
  result: ResourceResult<T>;
  refresh: () => void;
}

function decodeReadyData<T>(
  envelope: ResourceEnvelope<unknown>,
  decode: ReadModelDecoder<T>,
): ResourceEnvelope<T> {
  if (!["ready", "stale", "degraded"].includes(envelope.state)) {
    return envelope as ResourceEnvelope<T>;
  }
  if (envelope.data === null) throw new Error("Invalid response contract");
  return { ...envelope, data: decode(envelope.data) };
}

export function useResource<T>(
  client: ApiClient,
  path: string,
  decode: ReadModelDecoder<T>,
): ResourceController<T> {
  const [revision, setRevision] = useState(0);
  const [result, setResult] = useState<ResourceResult<T>>({ state: "loading", data: null });
  const refresh = useCallback(() => setRevision((value) => value + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setResult({ state: "loading", data: null });
    client
      .read<unknown>(path, controller.signal)
      .then((envelope) => {
        if (!active) return;
        try {
          setResult(decodeReadyData(envelope, decode));
        } catch {
          setResult({
            state: "error",
            data: null,
            reason_code: "invalid_response_contract",
          });
        }
      })
      .catch((error: unknown) => {
        if (active && !controller.signal.aborted) {
          setResult({
            state: "error",
            data: null,
            reason_code: error instanceof ApiClientError ? error.code : "request_failed",
          });
        }
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [client, path, decode, revision]);

  return { result, refresh };
}
