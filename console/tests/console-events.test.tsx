import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useConsoleEvents } from "../src/hooks/useConsoleEvents";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("console stream control events", () => {
  it("maps a cursorless unavailable control event to typed unavailable", async () => {
    const getToken = vi.fn(async () => "fixture-session");
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response(
          'event: unavailable\ndata: {"reason_code":"event_repository_missing"}\n\n',
          { status: 200, headers: { "content-type": "text/event-stream" } },
        ),
      ),
    );

    const { result } = renderHook(() =>
      useConsoleEvents(getToken, vi.fn()),
    );

    await waitFor(() => expect(result.current.state).toBe("unavailable"));
    expect(result.current).toEqual({
      state: "unavailable",
      data: null,
      reason_code: "event_repository_missing",
    });
  });

  it("still reconciles a cursorless snapshot", async () => {
    const reconcile = vi.fn();
    const getToken = vi.fn(async () => "fixture-session");
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response('event: snapshot\ndata: {"state":"empty"}\n\n', {
          status: 200,
          headers: { "content-type": "text/event-stream" },
        }),
      ),
    );

    const { result } = renderHook(() =>
      useConsoleEvents(getToken, reconcile),
    );

    await waitFor(() => expect(result.current.state).toBe("ready"));
    expect(reconcile).toHaveBeenCalled();
  });
});
