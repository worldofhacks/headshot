import { useCallback, useEffect, useRef, useState } from "react";

import { ApiClientError, type ApiClient } from "../api/client";
import type { ResourceEnvelope, ResourceResult } from "../api/contracts";
import type { ReadModelDecoder } from "../api/read-models";

export interface ResourceController<T> {
  result: ResourceResult<T>;
  refresh: () => void;
}

export interface ResourceOptions {
  pollIntervalMs?: number;
}

export const LIVE_RESOURCE_POLL_INTERVAL_MS = 5_000;

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
  options: ResourceOptions = {},
): ResourceController<T> {
  const [revision, setRevision] = useState(0);
  const [result, setResult] = useState<ResourceResult<T>>({ state: "loading", data: null });
  const refresh = useCallback(() => setRevision((value) => value + 1), []);
  const pollIntervalMs = options.pollIntervalMs;
  const resourceIdentity = useRef({ client, path });

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    let pollTimeout: number | null = null;
    if (
      resourceIdentity.current.client !== client
      || resourceIdentity.current.path !== path
    ) {
      resourceIdentity.current = { client, path };
      setResult({ state: "loading", data: null });
    }

    const schedulePoll = () => {
      if (
        active
        && pollIntervalMs !== undefined
        && Number.isFinite(pollIntervalMs)
        && pollIntervalMs > 0
      ) {
        pollTimeout = window.setTimeout(() => void load(), pollIntervalMs);
      }
    };
    const load = async () => {
      try {
        const envelope = await client.read<unknown>(path, controller.signal);
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
      } catch (error: unknown) {
        if (active && !controller.signal.aborted) {
          setResult({
            state: "error",
            data: null,
            reason_code: error instanceof ApiClientError ? error.code : "request_failed",
          });
        }
      } finally {
        schedulePoll();
      }
    };
    void load();

    return () => {
      active = false;
      controller.abort();
      if (pollTimeout !== null) window.clearTimeout(pollTimeout);
    };
  }, [client, path, decode, pollIntervalMs, revision]);

  return { result, refresh };
}
