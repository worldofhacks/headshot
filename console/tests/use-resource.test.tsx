import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import { useResource } from "../src/hooks/useResource";

afterEach(() => {
  vi.useRealTimers();
});

describe("live resource polling", () => {
  it("refreshes at the requested interval without blanking ready data", async () => {
    vi.useFakeTimers();
    const read = vi.fn(async () => ({
      state: "ready" as const,
      data: [{ revision: read.mock.calls.length }],
    }));
    const client = {
      read,
      command: vi.fn(),
    } as unknown as ApiClient;
    const decode = (value: unknown) => value as Array<{ revision: number }>;

    const { result, unmount } = renderHook(() =>
      useResource(client, "live-ledger", decode, { pollIntervalMs: 5_000 }),
    );
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(read).toHaveBeenCalledTimes(1);
    expect(result.current.result).toMatchObject({
      state: "ready",
      data: [{ revision: 1 }],
    });

    await act(async () => {
      vi.advanceTimersByTime(5_000);
      expect(result.current.result.state).toBe("ready");
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(read).toHaveBeenCalledTimes(2);
    expect(result.current.result).toMatchObject({
      state: "ready",
      data: [{ revision: 2 }],
    });
    unmount();
  });

  it("does not install a timer for one-shot resources", async () => {
    vi.useFakeTimers();
    const read = vi.fn(async () => ({ state: "empty" as const, data: null }));
    const client = {
      read,
      command: vi.fn(),
    } as unknown as ApiClient;
    const decode = (value: unknown) => value;

    const { unmount } = renderHook(() =>
      useResource(client, "static-ledger", decode),
    );
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(read).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
    unmount();
  });

  it("preserves the last valid snapshot when a refresh fails", async () => {
    vi.useFakeTimers();
    const read = vi.fn()
      .mockResolvedValueOnce({
        state: "ready" as const,
        data: [{ revision: 1 }],
        as_of: "2026-07-26T20:00:00Z",
      })
      .mockRejectedValueOnce(new Error("network unavailable"));
    const client = {
      read,
      command: vi.fn(),
    } as unknown as ApiClient;
    const decode = (value: unknown) => value as Array<{ revision: number }>;

    const { result, unmount } = renderHook(() =>
      useResource(client, "live-ledger", decode, { pollIntervalMs: 5_000 }),
    );
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(result.current.freshness.lastUpdatedAt).toBe("2026-07-26T20:00:00Z");

    await act(async () => {
      vi.advanceTimersByTime(5_000);
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(result.current.result).toMatchObject({
      state: "stale",
      data: [{ revision: 1 }],
      reason_code: "request_failed",
    });
    expect(result.current.freshness).toMatchObject({
      state: "snapshot",
      refreshing: false,
      stale: true,
      lastUpdatedAt: "2026-07-26T20:00:00Z",
    });
    unmount();
  });

  it("does not expose data from the previous resource identity", async () => {
    let resolveSecond: ((value: {
      state: "ready";
      data: Array<{ scope: string }>;
    }) => void) | null = null;
    const read = vi.fn(async (path: string) => {
      if (path === "campaigns/old") {
        return { state: "ready" as const, data: [{ scope: "old" }] };
      }
      return new Promise<{
        state: "ready";
        data: Array<{ scope: string }>;
      }>((resolve) => {
        resolveSecond = resolve;
      });
    });
    const client = { read, command: vi.fn() } as unknown as ApiClient;
    const decode = (value: unknown) => value as Array<{ scope: string }>;
    const { result, rerender } = renderHook(
      ({ path }) => useResource(client, path, decode),
      { initialProps: { path: "campaigns/old" } },
    );
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(result.current.result.data).toEqual([{ scope: "old" }]);

    rerender({ path: "campaigns/new" });
    expect(result.current.result).toEqual({ state: "loading", data: null });
    expect(result.current.freshness.lastUpdatedAt).toBeNull();

    await act(async () => {
      resolveSecond?.({ state: "ready", data: [{ scope: "new" }] });
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(result.current.result.data).toEqual([{ scope: "new" }]);
  });
});
