import { useEffect, useState } from "react";

import { useLiveDataContext } from "../live/LiveDataContext";

function ageLabel(timestamp: string | null, now: number): string | null {
  if (timestamp === null) return null;
  const elapsedSeconds = Math.max(0, Math.floor((now - Date.parse(timestamp)) / 1_000));
  if (elapsedSeconds < 5) return "updated now";
  if (elapsedSeconds < 60) return `updated ${elapsedSeconds}s ago`;
  return `updated ${Math.floor(elapsedSeconds / 60)}m ago`;
}

const stateLabel = {
  live: "Live",
  reconnecting: "Reconnecting",
  reconciling: "Reconciling",
  stale: "Stale",
} as const;

export function FreshnessBadge({
  serverStatus,
  systemState,
}: {
  serverStatus: string;
  systemState: string;
}) {
  const live = useLiveDataContext();
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    let active = true;
    let timer: number | null = null;
    const update = () => {
      if (!active) return;
      setNow(Date.now());
      timer = window.setTimeout(update, 1_000);
    };
    timer = window.setTimeout(update, 1_000);
    return () => {
      active = false;
      if (timer !== null) window.clearTimeout(timer);
    };
  }, []);

  const connectionState = live?.connectionState ?? "reconnecting";
  const freshness = ageLabel(live?.lastEventAt ?? null, now);
  const semanticState = connectionState === "live" ? systemState : "degraded";

  return (
    <span
      className={`connection-chip connection-${semanticState}`}
      role="status"
      aria-live="polite"
    >
      <span className={`status-dot ${connectionState === "live" ? "live" : "idle"}`} />
      {stateLabel[connectionState]}
      {freshness ? ` · ${freshness}` : ""}
      {` · Server snapshot ${serverStatus}`}
    </span>
  );
}
