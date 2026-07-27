import { createContext, useContext } from "react";

import type { ResourceResult } from "../api/contracts";
import type { ConsoleEvent } from "../api/stream";

export type LiveConnectionState = "live" | "reconnecting" | "reconciling" | "stale";

export interface LiveDataContextValue {
  events: ResourceResult<ConsoleEvent[]>;
  connectionState: LiveConnectionState;
  lastEventAt: string | null;
  lastReconciledAt: string | null;
  registerResource: (path: string, refresh: () => void) => () => void;
}

export const LiveDataContext = createContext<LiveDataContextValue | null>(null);

export function useLiveDataContext(): LiveDataContextValue | null {
  return useContext(LiveDataContext);
}
