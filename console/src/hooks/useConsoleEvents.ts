import { useEffect, useRef, useState } from "react";

import type { ResourceResult } from "../api/contracts";
import {
  applyOrderedEvent,
  buildStreamRequest,
  readEventStream,
  type ConsoleEvent,
  type OrderedEventState,
} from "../api/stream";
import { useLiveDataContext } from "../live/LiveDataContext";

export type StreamConnectionState =
  | "live"
  | "reconnecting"
  | "reconciling"
  | "unavailable";

interface StandaloneConsoleEventOptions {
  enabled?: boolean;
  onActivity?: () => void;
  onConnectionState?: (state: StreamConnectionState) => void;
  onEvent?: (event: ConsoleEvent) => void;
}

const reconnectDelay = (signal: AbortSignal) =>
  new Promise<void>((resolve) => {
    if (signal.aborted) return resolve();
    const timeout = window.setTimeout(resolve, 1_500);
    signal.addEventListener(
      "abort",
      () => {
        window.clearTimeout(timeout);
        resolve();
      },
      { once: true },
    );
  });

export function useStandaloneConsoleEvents(
  getToken: () => Promise<string | null>,
  onReconcile: () => void,
  options: StandaloneConsoleEventOptions = {},
): ResourceResult<ConsoleEvent[]> {
  const [result, setResult] = useState<ResourceResult<ConsoleEvent[]>>({
    state: "loading",
    data: null,
  });
  const ordered = useRef<OrderedEventState>({ cursor: 0, events: [] });
  const reconcile = useRef(onReconcile);
  const callbacks = useRef(options);
  reconcile.current = onReconcile;
  callbacks.current = options;

  useEffect(() => {
    if (options.enabled === false) return;
    const controller = new AbortController();
    let reconcileTimer: number | null = null;
    const scheduleReconcile = () => {
      if (reconcileTimer !== null) window.clearTimeout(reconcileTimer);
      reconcileTimer = window.setTimeout(() => {
        reconcileTimer = null;
        reconcile.current();
      }, 100);
    };

    const connect = async () => {
      while (!controller.signal.aborted) {
        callbacks.current.onConnectionState?.("reconnecting");
        let unavailable = false;
        let gap = false;
        try {
          const request = await buildStreamRequest({
            getToken,
            cursor: ordered.current.cursor,
            signal: controller.signal,
          });
          const response = await fetch(request.url, request.init);
          callbacks.current.onConnectionState?.("live");
          await readEventStream(response, (event) => {
            if (event.event === "heartbeat") return;
            callbacks.current.onEvent?.(event);
            if (event.event === "unavailable" && event.cursor === null) {
              unavailable = true;
              callbacks.current.onConnectionState?.("unavailable");
              const candidate = event.data?.reason_code;
              const reason =
                typeof candidate === "string" && /^[a-z0-9][a-z0-9_:-]{0,127}$/i.test(candidate)
                  ? candidate
                  : "event_stream_unavailable";
              setResult({ state: "unavailable", data: null, reason_code: reason });
              return;
            }
            if (event.event === "snapshot") {
              scheduleReconcile();
              if (event.cursor === null) {
                ordered.current = {
                  cursor: ordered.current.cursor,
                  events: [...ordered.current.events, event].slice(-200),
                };
                setResult({
                  state: "ready",
                  data: ordered.current.events,
                  cursor: ordered.current.cursor,
                });
                return;
              }
            }
            if (event.event === "gap") {
              gap = true;
              callbacks.current.onConnectionState?.("reconciling");
              ordered.current = { cursor: 0, events: [] };
              setResult({ state: "degraded", data: [], reason_code: "event_cursor_gap" });
              scheduleReconcile();
              return;
            }
            const next = applyOrderedEvent(ordered.current, event);
            if (next.kind === "gap") {
              gap = true;
              callbacks.current.onConnectionState?.("reconciling");
              ordered.current = { cursor: 0, events: [] };
              setResult({
                state: "degraded",
                data: [],
                reason_code: "event_cursor_gap",
              });
              scheduleReconcile();
              return;
            }
            ordered.current = { cursor: next.cursor, events: next.events };
            setResult({ state: "ready", data: next.events, cursor: next.cursor });
            scheduleReconcile();
          }, () => callbacks.current.onActivity?.());
          if (!gap && !unavailable && ordered.current.events.length === 0) {
            setResult({ state: "empty", data: [] });
          }
        } catch {
          if (!controller.signal.aborted) {
            callbacks.current.onConnectionState?.("unavailable");
            setResult({
              state: "unavailable",
              data: null,
              reason_code: "event_stream_unavailable",
            });
          }
        }
        if (!controller.signal.aborted && !unavailable && !gap) {
          callbacks.current.onConnectionState?.("reconnecting");
        }
        await reconnectDelay(controller.signal);
      }
    };

    void connect();
    return () => {
      controller.abort();
      if (reconcileTimer !== null) window.clearTimeout(reconcileTimer);
    };
  }, [getToken, options.enabled]);

  return result;
}

export function useConsoleEvents(
  getToken: () => Promise<string | null>,
  onReconcile: () => void,
): ResourceResult<ConsoleEvent[]> {
  const live = useLiveDataContext();
  const standalone = useStandaloneConsoleEvents(
    getToken,
    onReconcile,
    { enabled: live === null },
  );
  return live?.events ?? standalone;
}
