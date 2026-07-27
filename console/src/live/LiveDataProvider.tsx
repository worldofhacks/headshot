import {
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  affectedResourceRoots,
  type ConsoleEvent,
} from "../api/stream";
import {
  useStandaloneConsoleEvents,
  type StreamConnectionState,
} from "../hooks/useConsoleEvents";
import {
  LiveDataContext,
  type LiveConnectionState,
} from "./LiveDataContext";

const RECONCILE_DEBOUNCE_MS = 100;
export const LIVE_DATA_STALE_AFTER_MS = 15_000;

interface RegisteredResource {
  path: string;
  refresh: () => void;
}

interface LiveDataProviderProps {
  children: ReactNode;
  getToken: () => Promise<string | null>;
  scopeKey: string;
}

function rootOf(path: string): string {
  const pathname = path.split("?", 1)[0] ?? path;
  return pathname.split("/", 1)[0] ?? pathname;
}

export function LiveDataProvider({
  children,
  getToken,
  scopeKey,
}: LiveDataProviderProps) {
  const resources = useRef(new Map<number, RegisteredResource>());
  const nextRegistrationId = useRef(0);
  const pendingRoots = useRef(new Set<string>());
  const pendingBroadReconciliation = useRef(false);
  const reconcileTimer = useRef<number | null>(null);
  const staleTimer = useRef<number | null>(null);
  const previousScopeKey = useRef(scopeKey);
  const transportState = useRef<StreamConnectionState>("reconnecting");
  const [connectionState, setConnectionState] = useState<LiveConnectionState>("reconnecting");
  const [lastEventAt, setLastEventAt] = useState<string | null>(null);
  const [lastReconciledAt, setLastReconciledAt] = useState<string | null>(null);

  const registerResource = useCallback((path: string, refresh: () => void) => {
    const registrationId = nextRegistrationId.current;
    nextRegistrationId.current += 1;
    resources.current.set(registrationId, { path, refresh });
    return () => {
      resources.current.delete(registrationId);
    };
  }, []);

  const markStreamActivity = useCallback(() => {
    const observedAt = new Date().toISOString();
    setLastEventAt(observedAt);
    if (transportState.current === "live") setConnectionState("live");
    if (staleTimer.current !== null) window.clearTimeout(staleTimer.current);
    staleTimer.current = window.setTimeout(() => {
      setConnectionState("stale");
    }, LIVE_DATA_STALE_AFTER_MS);
  }, []);

  const setTransportConnectionState = useCallback((state: StreamConnectionState) => {
    transportState.current = state;
    if (state === "live") {
      setConnectionState("live");
      markStreamActivity();
    }
    if (state === "reconnecting" || state === "unavailable") {
      setConnectionState((current) => current === "stale" ? current : "reconnecting");
    }
    if (state === "reconciling") setConnectionState("reconciling");
  }, [markStreamActivity]);

  const flushReconciliation = useCallback(() => {
    reconcileTimer.current = null;
    const broad = pendingBroadReconciliation.current;
    const roots = pendingRoots.current;
    pendingBroadReconciliation.current = false;
    pendingRoots.current = new Set<string>();

    for (const resource of resources.current.values()) {
      if (broad || roots.has(rootOf(resource.path))) resource.refresh();
    }
    setLastReconciledAt(new Date().toISOString());
    setConnectionState(
      transportState.current === "live" ? "live" : "reconnecting",
    );
  }, []);

  const scheduleReconciliation = useCallback((event: ConsoleEvent | null) => {
    const roots = event === null ? null : affectedResourceRoots(event);
    if (roots === null) {
      pendingBroadReconciliation.current = true;
      pendingRoots.current.clear();
    } else if (!pendingBroadReconciliation.current) {
      for (const root of roots) pendingRoots.current.add(root);
    }
    setConnectionState("reconciling");
    if (reconcileTimer.current !== null) window.clearTimeout(reconcileTimer.current);
    reconcileTimer.current = window.setTimeout(
      flushReconciliation,
      RECONCILE_DEBOUNCE_MS,
    );
  }, [flushReconciliation]);

  const events = useStandaloneConsoleEvents(
    getToken,
    () => undefined,
    {
      onActivity: markStreamActivity,
      onConnectionState: setTransportConnectionState,
      onEvent: scheduleReconciliation,
    },
  );

  useEffect(() => {
    if (previousScopeKey.current === scopeKey) return;
    previousScopeKey.current = scopeKey;
    scheduleReconciliation(null);
  }, [scopeKey, scheduleReconciliation]);

  useEffect(() => () => {
    if (reconcileTimer.current !== null) window.clearTimeout(reconcileTimer.current);
    if (staleTimer.current !== null) window.clearTimeout(staleTimer.current);
  }, []);

  const value = useMemo(() => ({
    events,
    connectionState,
    lastEventAt,
    lastReconciledAt,
    registerResource,
  }), [
    events,
    connectionState,
    lastEventAt,
    lastReconciledAt,
    registerResource,
  ]);

  return <LiveDataContext.Provider value={value}>{children}</LiveDataContext.Provider>;
}
