import { describe, expect, it, vi } from "vitest";

import { ApiClientError, createApiClient } from "../src/api/client";

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

describe("same-origin API client", () => {
  it("retrieves a fresh Clerk token for every protected request", async () => {
    const getToken = vi
      .fn<() => Promise<string | null>>()
      .mockResolvedValueOnce("first-secret-token")
      .mockResolvedValueOnce("second-secret-token");
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse({ state: "empty", data: null }),
    );
    const client = createApiClient({
      origin: "https://headshot.test",
      getToken,
      fetchImpl,
    });

    await client.read("campaigns");
    await client.read("findings");

    expect(getToken).toHaveBeenCalledTimes(2);
    expect(fetchImpl).toHaveBeenNthCalledWith(
      1,
      "https://headshot.test/api/v1/campaigns",
      expect.objectContaining({
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        headers: expect.objectContaining({ Authorization: "Bearer first-secret-token" }),
      }),
    );
    expect(fetchImpl).toHaveBeenNthCalledWith(
      2,
      "https://headshot.test/api/v1/findings",
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: "Bearer second-secret-token" }),
      }),
    );
  });

  it("adds a client idempotency key to commands and waits for server acknowledgement", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse({ acknowledgement_id: "ack_server", status: "accepted" }, 202),
    );
    const client = createApiClient({
      origin: "https://headshot.test",
      getToken: async () => "short-lived-token",
      fetchImpl,
      createIdempotencyKey: () => "idem-client-test-0001", // gitleaks:allow -- deterministic test nonce
    });

    const ack = await client.command("campaigns/campaign-id/abort", { reason: "operator" });

    expect(ack).toEqual({ acknowledgement_id: "ack_server", status: "accepted" });
    expect(fetchImpl).toHaveBeenCalledWith(
      "https://headshot.test/api/v1/campaigns/campaign-id/abort",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ reason: "operator" }),
        headers: expect.objectContaining({
          Authorization: "Bearer short-lived-token",
          "Idempotency-Key": "idem-client-test-0001", // gitleaks:allow -- deterministic test nonce
        }),
      }),
    );
  });

  it("rejects paths that could exfiltrate a bearer token cross-origin", async () => {
    const client = createApiClient({
      origin: "https://headshot.test",
      getToken: async () => "never-leak-me",
      fetchImpl: vi.fn<typeof fetch>(),
    });

    await expect(client.read("https://attacker.invalid/collect")).rejects.toThrow(
      "Invalid API path",
    );
  });

  it("does not include bearer tokens or authorization headers in errors", async () => {
    const secret = "high-value-session-token";
    const client = createApiClient({
      origin: "https://headshot.test",
      getToken: async () => secret,
      fetchImpl: vi.fn<typeof fetch>().mockRejectedValue(new Error(`network ${secret}`)),
    });

    let error: unknown;
    try {
      await client.read("principal");
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(ApiClientError);
    expect(String(error)).not.toContain(secret);
    expect(JSON.stringify(error)).not.toMatch(/authorization|bearer|token/i);
  });

  it("preserves a typed unavailable command acknowledgement", async () => {
    const client = createApiClient({
      origin: "https://headshot.test",
      getToken: async () => "short-lived-credential",
      fetchImpl: vi.fn<typeof fetch>().mockResolvedValue(
        jsonResponse({ status: "unavailable", reason_code: "runner_missing" }, 503),
      ),
    });

    await expect(client.command("campaigns", { authorization_request_id: "request-id" }))
      .resolves.toEqual({ status: "unavailable", reason_code: "runner_missing" });
  });

  it("rejects legacy command acknowledgement fields", async () => {
    const client = createApiClient({
      origin: "https://headshot.test",
      getToken: async () => "short-lived-credential",
      fetchImpl: vi.fn<typeof fetch>().mockResolvedValue(
        jsonResponse({ command_id: "legacy-id", status: "accepted" }, 202),
      ),
    });

    await expect(client.command("campaigns", { authorization_request_id: "request-id" }))
      .rejects.toThrow("Invalid server response");
  });
});
