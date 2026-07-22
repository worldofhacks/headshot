import { describe, expect, it } from "vitest";

import {
  applyOrderedEvent,
  buildStreamRequest,
  parseEventStream,
  type ConsoleEvent,
} from "../src/api/stream";

describe("authenticated console event stream", () => {
  it("uses a bearer header and never a token query parameter", async () => {
    const request = await buildStreamRequest({
      origin: "https://headshot.test",
      getToken: async () => "stream-session-secret",
      cursor: 41,
    });

    expect(request.url).toBe("https://headshot.test/api/v1/events");
    expect(request.url).not.toContain("stream-session-secret");
    expect(request.init.headers).toMatchObject({
      Authorization: "Bearer stream-session-secret",
      "Last-Event-ID": "41",
    });
    expect(request.init.credentials).toBe("omit");
    expect(request.init.headers).not.toHaveProperty("Origin");
  });

  it("parses snapshot, delta, and heartbeat frames without interpreting payload HTML", () => {
    const frames = parseEventStream(
      "id: 12\nevent: delta\ndata: {\"kind\":\"attempt\",\"text\":\"<img src=x onerror=alert(1)>\"}\n\n" +
        "event: heartbeat\ndata: {}\n\n",
    );

    expect(frames).toEqual([
      {
        cursor: 12,
        event: "delta",
        data: { kind: "attempt", text: "<img src=x onerror=alert(1)>" },
      },
      { cursor: null, event: "heartbeat", data: {} },
    ]);
  });

  it("detects cursor gaps and requests reconciliation", () => {
    const state = { cursor: 8, events: [] as ConsoleEvent[] };
    const result = applyOrderedEvent(state, {
      cursor: 10,
      event: "delta",
      data: { kind: "attempt" },
    });

    expect(result.kind).toBe("gap");
    expect(result.expectedCursor).toBe(9);
  });

  it("ignores comment heartbeats and accepts the server's initial retained cursor", () => {
    expect(parseEventStream(": heartbeat\n\n")).toEqual([]);
    expect(
      applyOrderedEvent({ cursor: 0, events: [] }, {
        cursor: 27,
        event: "audit.delta",
        data: { aggregate_id: "server-record" },
      }).kind,
    ).toBe("applied");
  });
});
