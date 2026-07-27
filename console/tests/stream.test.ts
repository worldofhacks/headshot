import { describe, expect, it } from "vitest";

import {
  affectedResourceRoots,
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

  it("accepts non-contiguous increasing organization-filtered cursors", () => {
    const state = { cursor: 8, events: [] as ConsoleEvent[] };
    const result = applyOrderedEvent(state, {
      cursor: 10,
      event: "delta",
      data: { kind: "attempt" },
    });

    expect(result.kind).toBe("applied");
    expect(result.cursor).toBe(10);
  });

  it("requests reconciliation only for an explicit server gap event", () => {
    const result = applyOrderedEvent(
      { cursor: 8, events: [] },
      { cursor: 10, event: "gap", data: { earliest_cursor: 10 } },
    );

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

  it("maps known event families and safely broadens unknown events", () => {
    expect(affectedResourceRoots({
      cursor: 1,
      event: "campaign.started",
      data: { aggregate_type: "campaign_run" },
    })).toEqual(expect.arrayContaining(["campaigns", "attempts", "costs", "traces"]));
    expect(affectedResourceRoots({
      cursor: 2,
      event: "finding.documented",
      data: { aggregate_type: "finding" },
    })).toEqual(expect.arrayContaining(["findings", "reports", "coverage"]));
    expect(affectedResourceRoots({
      cursor: 3,
      event: "future_domain.changed",
      data: { aggregate_type: "future_domain" },
    })).toBeNull();
  });
});
