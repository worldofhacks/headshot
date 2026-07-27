import { useCallback, useEffect, useRef, useState } from "react";

import { ApiClientError, type ApiClient } from "../api/client";
import type { ResourceEnvelope, ResourceResult } from "../api/contracts";
import type { ReadModelDecoder } from "../api/read-models";
import {
  useLiveDataContext,
  type LiveConnectionState,
} from "../live/LiveDataContext";

export interface ResourceController<T> {
  result: ResourceResult<T>;
  refresh: () => void;
  freshness: {
    state: LiveConnectionState | "snapshot";
    refreshing: boolean;
    stale: boolean;
    lastUpdatedAt: string | null;
    lastEventAt: string | null;
  };
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
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<string | null>(null);
  const refresh = useCallback(() => setRevision((value) => value + 1), []);
  const live = useLiveDataContext();
  const fallbackPolling = live !== null
    && (live.connectionState === "reconnecting" || live.connectionState === "stale");
  const pollIntervalMs = live === null
    ? options.pollIntervalMs
    : fallbackPolling
      ? LIVE_RESOURCE_POLL_INTERVAL_MS
      : options.pollIntervalMs;
  const resourceIdentity = useRef({ client, path });
  const lastSuccessful = useRef<ResourceResult<T> | null>(null);
  const identityChanged = resourceIdentity.current.client !== client
    || resourceIdentity.current.path !== path;

  useEffect(() => {
    if (live === null) return;
    return live.registerResource(path, refresh);
  }, [live?.registerResource, path, refresh]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    let pollTimeout: number | null = null;
    if (identityChanged) {
      resourceIdentity.current = { client, path };
      lastSuccessful.current = null;
      setLastUpdatedAt(null);
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
      setRefreshing(true);
      try {
        const envelope = await client.read<unknown>(path, controller.signal);
        if (!active) return;
        try {
          const decoded = decodeReadyData(envelope, decode);
          if (
            decoded.state === "ready"
            || decoded.state === "empty"
            || (
              (decoded.state === "stale" || decoded.state === "degraded")
              && decoded.data !== null
            )
          ) {
            lastSuccessful.current = decoded;
            setLastUpdatedAt(decoded.as_of ?? new Date().toISOString());
            setResult(decoded);
          } else if (lastSuccessful.current !== null) {
            setResult({
              ...lastSuccessful.current,
              state: decoded.state === "error" ? "stale" : decoded.state,
              reason_code: decoded.reason_code,
              detail: decoded.detail,
            } as ResourceResult<T>);
          } else {
            setResult(decoded);
          }
        } catch {
          setResult(lastSuccessful.current === null
            ? {
                state: "error",
                data: null,
                reason_code: "invalid_response_contract",
              }
            : {
                ...lastSuccessful.current,
                state: "degraded",
                reason_code: "invalid_response_contract",
              } as ResourceResult<T>);
        }
      } catch (error: unknown) {
        if (active && !controller.signal.aborted) {
          const reasonCode = error instanceof ApiClientError ? error.code : "request_failed";
          setResult(lastSuccessful.current === null
            ? {
                state: "error",
                data: null,
                reason_code: reasonCode,
              }
            : {
                ...lastSuccessful.current,
                state: "stale",
                reason_code: reasonCode,
              } as ResourceResult<T>);
        }
      } finally {
        if (active) setRefreshing(false);
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

  const freshnessState = refreshing && live !== null
    ? "reconciling"
    : live?.connectionState ?? "snapshot";
  const visibleResult: ResourceResult<T> = identityChanged
    ? { state: "loading", data: null }
    : result;

  return {
    result: visibleResult,
    refresh,
    freshness: {
      state: freshnessState,
      refreshing,
      stale: visibleResult.state === "stale" || freshnessState === "stale",
      lastUpdatedAt: identityChanged ? null : lastUpdatedAt,
      lastEventAt: live?.lastEventAt ?? null,
    },
  };
}
