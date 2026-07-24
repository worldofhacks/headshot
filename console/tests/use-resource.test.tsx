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
});
