import { ApiClientError } from "./client";
import { isJsonRecord, type JsonRecord } from "./contracts";

export interface ConsoleEvent {
  cursor: number | null;
  event: string;
  data: JsonRecord | null;
}

export interface OrderedEventState {
  cursor: number;
  events: ConsoleEvent[];
}

export type OrderedEventResult =
  | ({ kind: "applied" | "duplicate" } & OrderedEventState)
  | ({ kind: "gap"; expectedCursor: number } & OrderedEventState);

interface StreamRequestOptions {
  origin?: string;
  getToken: () => Promise<string | null>;
  cursor?: number | null;
  signal?: AbortSignal;
}

function streamOrigin(value?: string): string {
  const fallback = typeof window === "undefined" ? "http://localhost" : window.location.origin;
  const url = new URL(value ?? fallback);
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.pathname !== "/" && url.pathname !== "")
  ) {
    throw new ApiClientError("Invalid application origin", "invalid_origin");
  }
  return url.origin;
}

export async function buildStreamRequest(options: StreamRequestOptions): Promise<{
  url: string;
  init: RequestInit & { headers: Record<string, string> };
}> {
  let credential: string | null;
  try {
    credential = await options.getToken();
  } catch {
    throw new ApiClientError("Authentication unavailable", "authentication_unavailable");
  }
  if (!credential) throw new ApiClientError("Authentication required", "unauthenticated", 401);
  const headers: Record<string, string> = {
    Accept: "text/event-stream",
    Authorization: `Bearer ${credential}`,
  };
  if (options.cursor !== null && options.cursor !== undefined) {
    if (!Number.isSafeInteger(options.cursor) || options.cursor < 0) {
      throw new ApiClientError("Invalid stream cursor", "invalid_cursor");
    }
    headers["Last-Event-ID"] = String(options.cursor);
  }
  return {
    url: `${streamOrigin(options.origin)}/api/v1/events`,
    init: {
      method: "GET",
      headers,
      signal: options.signal,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
    },
  };
}

export function parseEventStream(text: string): ConsoleEvent[] {
  const frames: ConsoleEvent[] = [];
  for (const block of text.replace(/\r\n/g, "\n").split("\n\n")) {
    if (!block.trim()) continue;
    let id: number | null = null;
    let event = "message";
    const data: string[] = [];
    let meaningful = false;
    for (const line of block.split("\n")) {
      if (line.startsWith(":")) continue;
      const separator = line.indexOf(":");
      const field = separator === -1 ? line : line.slice(0, separator);
      const raw = separator === -1 ? "" : line.slice(separator + 1).replace(/^ /, "");
      if (field === "id" && /^\d+$/.test(raw)) {
        id = Number(raw);
        meaningful = true;
      }
      if (field === "event" && raw) {
        event = raw;
        meaningful = true;
      }
      if (field === "data") {
        data.push(raw);
        meaningful = true;
      }
    }
    if (!meaningful) continue;
    let parsed: JsonRecord | null = null;
    if (data.length > 0) {
      try {
        const value: unknown = JSON.parse(data.join("\n"));
        parsed = isJsonRecord(value) ? value : null;
      } catch {
        parsed = null;
      }
    }
    frames.push({ cursor: id, event, data: parsed });
  }
  return frames;
}

export function applyOrderedEvent(
  state: OrderedEventState,
  incoming: ConsoleEvent,
  maxEvents = 200,
): OrderedEventResult {
  if (incoming.cursor === null) {
    return { kind: "applied", cursor: state.cursor, events: state.events };
  }
  if (incoming.cursor <= state.cursor) {
    return { kind: "duplicate", cursor: state.cursor, events: state.events };
  }
  if (
    state.cursor !== 0 &&
    incoming.event !== "snapshot" &&
    incoming.cursor !== state.cursor + 1
  ) {
    return {
      kind: "gap",
      expectedCursor: state.cursor + 1,
      cursor: state.cursor,
      events: state.events,
    };
  }
  return {
    kind: "applied",
    cursor: incoming.cursor,
    events: [...state.events, incoming].slice(-maxEvents),
  };
}

export async function readEventStream(
  response: Response,
  onEvent: (event: ConsoleEvent) => void,
): Promise<void> {
  if (!response.ok || !response.body) {
    throw new ApiClientError("Event stream unavailable", "stream_unavailable", response.status);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let pending = "";
  const maximumPendingBytes = 262_144;
  while (true) {
    const { done, value } = await reader.read();
    pending += decoder.decode(value, { stream: !done });
    if (pending.length > maximumPendingBytes) {
      await reader.cancel();
      throw new ApiClientError("Event stream frame too large", "stream_frame_too_large");
    }
    const normalized = pending.replace(/\r\n/g, "\n");
    const boundary = normalized.lastIndexOf("\n\n");
    if (boundary >= 0) {
      for (const event of parseEventStream(normalized.slice(0, boundary + 2))) onEvent(event);
      pending = normalized.slice(boundary + 2);
    }
    if (done) {
      if (pending.trim()) {
        for (const event of parseEventStream(`${pending}\n\n`)) onEvent(event);
      }
      return;
    }
  }
}
