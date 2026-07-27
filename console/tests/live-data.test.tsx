import { act, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import {
  LIVE_RESOURCE_POLL_INTERVAL_MS,
  useResource,
} from "../src/hooks/useResource";
import { useLiveDataContext } from "../src/live/LiveDataContext";
import {
  LIVE_DATA_STALE_AFTER_MS,
  LiveDataProvider,
} from "../src/live/LiveDataProvider";

const decodeRevision = (value: unknown) => value as { revision: number };

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

function ResourceProbe({
  client,
  label,
  path,
}: {
  client: ApiClient;
  label: string;
  path: string;
}) {
  const resource = useResource<{ revision: number }>(
    client,
    path,
    decodeRevision,
  );
  return (
    <output data-testid={label} data-state={resource.result.state}>
      {resource.result.data?.revision ?? "loading"}
    </output>
  );
}

function FreshnessProbe() {
  const live = useLiveDataContext();
  return <output data-testid="freshness">{live?.connectionState ?? "missing"}</output>;
}

describe("shell live data provider", () => {
  it("maintains one stream and invalidates every matching consumer", async () => {
    const encoder = new TextEncoder();
    let streamController: ReadableStreamDefaultController<Uint8Array> | null = null;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        streamController = controller;
      },
    });
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(body, {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const revisions = new Map<string, number>();
    const read = vi.fn(async (path: string) => {
      const revision = (revisions.get(path) ?? 0) + 1;
      revisions.set(path, revision);
      return { state: "ready" as const, data: { revision } };
    });
    const client = { read, command: vi.fn() } as unknown as ApiClient;

    const view = render(
      <LiveDataProvider getToken={async () => "fixture-session"} scopeKey="live:">
        <ResourceProbe client={client} label="campaign-a" path="campaigns" />
        <ResourceProbe client={client} label="campaign-b" path="campaigns" />
        <ResourceProbe client={client} label="findings" path="findings" />
      </LiveDataProvider>,
    );

    await waitFor(() => expect(screen.getByTestId("campaign-a").textContent).not.toBe("loading"));
    await waitFor(() => expect(screen.getByTestId("findings").textContent).not.toBe("loading"));
    const campaignReadsBefore = read.mock.calls.filter(([path]) => path === "campaigns").length;
    const findingReadsBefore = read.mock.calls.filter(([path]) => path === "findings").length;

    await act(async () => {
      streamController?.enqueue(new TextEncoder().encode(
        'id: 1\nevent: campaign.started\ndata: {"aggregate_type":"campaign_run"}\n\n',
      ));
    });

    await waitFor(() => {
      expect(read.mock.calls.filter(([path]) => path === "campaigns").length)
        .toBe(campaignReadsBefore + 2);
    });
    expect(read.mock.calls.filter(([path]) => path === "findings").length)
      .toBe(findingReadsBefore);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await act(async () => {
      streamController?.enqueue(encoder.encode(
        'id: 2\nevent: gap\ndata: {"earliest_cursor":2}\n\n',
      ));
    });
    await waitFor(() => {
      expect(read.mock.calls.filter(([path]) => path === "findings").length)
        .toBeGreaterThan(findingReadsBefore);
    });

    view.unmount();
    streamController?.close();
  });

  it("moves from live to stale when the stream has no activity", async () => {
    vi.useFakeTimers();
    let streamController: ReadableStreamDefaultController<Uint8Array> | null = null;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        streamController = controller;
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response(body, {
          status: 200,
          headers: { "content-type": "text/event-stream" },
        }),
      ),
    );

    const view = render(
      <LiveDataProvider getToken={async () => "fixture-session"} scopeKey="live:">
        <FreshnessProbe />
      </LiveDataProvider>,
    );

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(screen.getByTestId("freshness").textContent).toBe("live");
    await act(async () => {
      vi.advanceTimersByTime(LIVE_DATA_STALE_AFTER_MS);
    });
    expect(screen.getByTestId("freshness").textContent).toBe("stale");

    view.unmount();
    streamController?.close();
  });

  it("polls every five seconds after a rejected stream and retains last-good data", async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockRejectedValue(new Error("stream rejected")),
    );
    const read = vi.fn()
      .mockResolvedValueOnce({
        state: "ready" as const,
        data: { revision: 1 },
        as_of: "2026-07-26T20:00:00Z",
      })
      .mockRejectedValue(new Error("resource unavailable"));
    const client = { read, command: vi.fn() } as unknown as ApiClient;
    const view = render(
      <LiveDataProvider getToken={async () => "fixture-session"} scopeKey="runs:">
        <ResourceProbe client={client} label="campaigns" path="campaigns" />
        <FreshnessProbe />
      </LiveDataProvider>,
    );

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(read).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("campaigns").textContent).toBe("1");
    expect(screen.getByTestId("freshness").textContent).toBe("reconnecting");

    await act(async () => {
      vi.advanceTimersByTime(LIVE_RESOURCE_POLL_INTERVAL_MS - 1);
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(read).toHaveBeenCalledTimes(1);

    await act(async () => {
      vi.advanceTimersByTime(1);
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(read).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId("campaigns").textContent).toBe("1");
    expect(screen.getByTestId("campaigns").getAttribute("data-state")).toBe("stale");

    view.unmount();
  });

  it("reconciles immediately on reconnect and cancels fallback polling", async () => {
    vi.useFakeTimers();
    let streamController: ReadableStreamDefaultController<Uint8Array> | null = null;
    const liveBody = new ReadableStream<Uint8Array>({
      start(controller) {
        streamController = controller;
      },
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockRejectedValueOnce(new Error("initial disconnect"))
      .mockResolvedValueOnce(
        new Response(liveBody, {
          status: 200,
          headers: { "content-type": "text/event-stream" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    const read = vi.fn(async () => ({
      state: "ready" as const,
      data: { revision: read.mock.calls.length },
    }));
    const client = { read, command: vi.fn() } as unknown as ApiClient;
    const view = render(
      <LiveDataProvider getToken={async () => "fixture-session"} scopeKey="runs:">
        <ResourceProbe client={client} label="campaigns" path="campaigns" />
        <FreshnessProbe />
      </LiveDataProvider>,
    );

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(read).toHaveBeenCalledTimes(1);

    await act(async () => {
      vi.advanceTimersByTime(1_499);
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(read).toHaveBeenCalledTimes(1);

    await act(async () => {
      vi.advanceTimersByTime(1);
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId("freshness").textContent).toBe("live");
    expect(read).toHaveBeenCalledTimes(2);
    const readsAfterReconnect = read.mock.calls.length;

    await act(async () => {
      vi.advanceTimersByTime(LIVE_RESOURCE_POLL_INTERVAL_MS);
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(read).toHaveBeenCalledTimes(readsAfterReconnect);

    view.unmount();
    streamController?.close();
  });

  it("treats heartbeat bytes as activity and resets the stale deadline", async () => {
    vi.useFakeTimers();
    let streamController: ReadableStreamDefaultController<Uint8Array> | null = null;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        streamController = controller;
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response(body, {
          status: 200,
          headers: { "content-type": "text/event-stream" },
        }),
      ),
    );
    const view = render(
      <LiveDataProvider getToken={async () => "fixture-session"} scopeKey="runs:">
        <FreshnessProbe />
      </LiveDataProvider>,
    );

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(screen.getByTestId("freshness").textContent).toBe("live");

    await act(async () => {
      vi.advanceTimersByTime(LIVE_DATA_STALE_AFTER_MS - 1_000);
      streamController?.enqueue(new TextEncoder().encode(": heartbeat\n\n"));
      await Promise.resolve();
      await Promise.resolve();
    });
    await act(async () => {
      vi.advanceTimersByTime(LIVE_DATA_STALE_AFTER_MS - 1);
    });
    expect(screen.getByTestId("freshness").textContent).toBe("live");
    await act(async () => {
      vi.advanceTimersByTime(1);
    });
    expect(screen.getByTestId("freshness").textContent).toBe("stale");

    view.unmount();
    streamController?.close();
  });

  it("targets campaign and scoped observability resources without refreshing findings", async () => {
    let streamController: ReadableStreamDefaultController<Uint8Array> | null = null;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        streamController = controller;
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response(body, {
          status: 200,
          headers: { "content-type": "text/event-stream" },
        }),
      ),
    );
    const read = vi.fn(async (path: string) => ({
      state: "ready" as const,
      data: { revision: read.mock.calls.filter(([candidate]) => candidate === path).length },
    }));
    const client = { read, command: vi.fn() } as unknown as ApiClient;
    const view = render(
      <LiveDataProvider getToken={async () => "fixture-session"} scopeKey="runs:">
        <ResourceProbe
          client={client}
          label="campaign-operations"
          path="campaigns/run-1/operations"
        />
        <ResourceProbe client={client} label="traces" path="traces?campaign_id=run-1" />
        <ResourceProbe client={client} label="costs" path="costs?campaign_id=run-1" />
        <ResourceProbe
          client={client}
          label="agent-activity"
          path="agent-activity?campaign_id=run-1"
        />
        <ResourceProbe client={client} label="findings" path="findings" />
        <FreshnessProbe />
      </LiveDataProvider>,
    );

    await waitFor(() => expect(screen.getByTestId("freshness").textContent).toBe("live"));
    await waitFor(() => expect(screen.getByTestId("campaign-operations").textContent)
      .not.toBe("loading"));
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    const operationReadsBefore = read.mock.calls
      .filter(([path]) => path === "campaigns/run-1/operations").length;
    const traceReadsBefore = read.mock.calls
      .filter(([path]) => path === "traces?campaign_id=run-1").length;
    const costReadsBefore = read.mock.calls
      .filter(([path]) => path === "costs?campaign_id=run-1").length;
    const activityReadsBefore = read.mock.calls
      .filter(([path]) => path === "agent-activity?campaign_id=run-1").length;
    const findingReadsBefore = read.mock.calls
      .filter(([path]) => path === "findings").length;

    await act(async () => {
      streamController?.enqueue(new TextEncoder().encode(
        'id: 1\nevent: campaign.started\ndata: {"aggregate_type":"campaign_run"}\n\n',
      ));
    });
    await waitFor(() => {
      expect(read.mock.calls.filter(([path]) => path === "campaigns/run-1/operations").length)
        .toBe(operationReadsBefore + 1);
      expect(read.mock.calls.filter(([path]) => path === "traces?campaign_id=run-1").length)
        .toBe(traceReadsBefore + 1);
      expect(read.mock.calls.filter(([path]) => path === "costs?campaign_id=run-1").length)
        .toBe(costReadsBefore + 1);
      expect(read.mock.calls.filter(([path]) => path === "agent-activity?campaign_id=run-1").length)
        .toBe(activityReadsBefore + 1);
    });
    expect(read.mock.calls.filter(([path]) => path === "findings").length)
      .toBe(findingReadsBefore);

    view.unmount();
    streamController?.close();
  });

  it("keeps one stream across scope reconciliation and aborts it before replacement", async () => {
    const controllers: Array<ReadableStreamDefaultController<Uint8Array>> = [];
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async () => {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controllers.push(controller);
        },
      });
      return new Response(body, {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const getToken = vi.fn(async () => "fixture-session");
    const first = render(
      <LiveDataProvider getToken={getToken} scopeKey="runs:">
        <FreshnessProbe />
      </LiveDataProvider>,
    );

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const firstSignal = fetchMock.mock.calls[0]?.[1]?.signal;
    expect(firstSignal?.aborted).toBe(false);
    first.rerender(
      <LiveDataProvider getToken={getToken} scopeKey="findings:">
        <FreshnessProbe />
      </LiveDataProvider>,
    );
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    first.unmount();
    expect(firstSignal?.aborted).toBe(true);

    const second = render(
      <LiveDataProvider getToken={getToken} scopeKey="runs:">
        <FreshnessProbe />
      </LiveDataProvider>,
    );
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    const secondSignal = fetchMock.mock.calls[1]?.[1]?.signal;
    expect(firstSignal?.aborted).toBe(true);
    expect(secondSignal?.aborted).toBe(false);
    second.unmount();
    expect(secondSignal?.aborted).toBe(true);
  });
});
