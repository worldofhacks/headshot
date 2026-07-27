import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import type { Principal } from "../src/api/contracts";
import { ProviderCallLedger } from "../src/components/ProviderCallLedger";
import { CostsScreen, TracesScreen } from "../src/screens/ObservabilityScreens";
import type { ProviderCallReadModel } from "../src/types";
import { PERMISSIONS } from "../src/types";

afterEach(cleanup);

// Regression cover for a wiring defect: the ledger owned a correct permission-gated
// prompt/response disclosure, but Traces, Costs and Run Operations each rendered it without an
// ApiClient or Principal. Every screen therefore reported the evidence "unavailable" and the
// requirement was unreachable in the product while every component-level test still passed.
// These tests assert the screens actually supply both, so the disclosure is reachable.

const call: ProviderCallReadModel = {
  invocation_id: "a".repeat(64),
  event_id: "b".repeat(64),
  campaign_id: "campaign-1",
  attempt_id: "attempt-1",
  execution_id: "execution-1",
  parent_execution_id: "execution-parent",
  agent_role: "judge",
  physical_sequence: 2,
  provider: "openrouter",
  requested_model: "google/gemini-2.5-pro",
  configured_upstream: "google-vertex",
  returned_model: "google/gemini-2.5-pro",
  upstream_provider: "Google Vertex",
  provider_request_id: "openrouter-request-2",
  status: "succeeded",
  error_code: null,
  input_tokens: 530,
  output_tokens: 137,
  reasoning_tokens: 752,
  cost_measurement_state: "measured",
  accounting_status: "measured",
  measured_cost_usd: 0.012173,
  currency: "USD",
  started_at: "2026-07-27T09:00:00Z",
  finished_at: "2026-07-27T09:00:10Z",
  duration_ms: 10_000,
  trace_id: "trace-1",
  langfuse_observation_name: "provider.attempt.2",
  langfuse_attempt_label: "attempt:attempt-1",
  langfuse_status: "exported",
  langfuse_verified_at: "2026-07-27T09:00:12Z",
};

const principalWith = (permissions: string[]): Principal => ({
  user_id: "user-operator",
  organization_id: "org-headshot",
  organization_role: "org:operator",
  organization_permissions: permissions,
});

/** Route reads by path so one mock serves a whole screen. Evidence is matched first because the
 * evidence path is nested under the provider-calls prefix. */
const screenClient = () => {
  const read = vi.fn(async (path: string) => {
    if (path.includes("/evidence")) {
      throw new Error("evidence must not be read before the disclosure is expanded");
    }
    if (path.includes("provider-calls")) {
      return { state: "ready" as const, data: [structuredClone(call)] };
    }
    return { state: "ready" as const, data: [] };
  });
  return { read, command: vi.fn() } as unknown as ApiClient & {
    read: ReturnType<typeof vi.fn>;
  };
};

const evidenceReads = (client: { read: ReturnType<typeof vi.fn> }) =>
  client.read.mock.calls.filter(([path]) => String(path).includes("/evidence"));

describe("provider call evidence disclosure wiring", () => {
  it("exposes the permission-gated disclosure on the Traces screen", async () => {
    const client = screenClient();

    render(
      <TracesScreen
        client={client}
        principal={principalWith([PERMISSIONS.consoleRead, PERMISSIONS.evidenceRead])}
      />,
    );

    expect(await screen.findByText("Prompt & response")).toBeTruthy();
    // Collapsed: no evidence request may be issued until an operator expands it.
    expect(evidenceReads(client)).toHaveLength(0);
  });

  it("exposes the permission-gated disclosure on the Costs screen", async () => {
    const client = screenClient();

    render(
      <CostsScreen
        client={client}
        principal={principalWith([PERMISSIONS.consoleRead, PERMISSIONS.evidenceRead])}
      />,
    );

    expect(await screen.findByText("Prompt & response")).toBeTruthy();
    expect(evidenceReads(client)).toHaveLength(0);
  });

  it("withholds the disclosure from a principal without org:evidence:read", async () => {
    const client = screenClient();

    render(
      <TracesScreen client={client} principal={principalWith([PERMISSIONS.consoleRead])} />,
    );

    // The ledger still renders; only the evidence disclosure is withheld.
    expect(await screen.findByText("provider.attempt.2")).toBeTruthy();
    expect(screen.queryByText("Prompt & response")).toBeNull();
    expect(
      screen.getByText(/require the org:evidence:read permission/),
    ).toBeTruthy();
    expect(evidenceReads(client)).toHaveLength(0);
  });

  it("reports evidence unavailable when a screen renders without a principal", async () => {
    const client = screenClient();

    render(<TracesScreen client={client} />);

    expect(await screen.findByText("provider.attempt.2")).toBeTruthy();
    expect(screen.queryByText("Prompt & response")).toBeNull();
    await waitFor(() => {
      expect(
        screen.getByText(/rendered without an authenticated client and organization principal/),
      ).toBeTruthy();
    });
    expect(evidenceReads(client)).toHaveLength(0);
  });
});

describe("a physical call still in flight", () => {
  // red_team calls average ~90s and have run to ~11 minutes, so they sit in flight far longer
  // than any other role. The evidence route has no provider_call_events row to find until the
  // call terminalizes, and reporting that as "no evidence record" read as data loss.
  const inFlight: ProviderCallReadModel = {
    ...call,
    agent_role: "red_team",
    physical_sequence: 1,
    status: "in_flight",
    langfuse_observation_name: "provider.attempt.1",
    returned_model: null,
    upstream_provider: null,
    provider_request_id: null,
    finished_at: null,
    duration_ms: null,
    input_tokens: null,
    output_tokens: null,
    reasoning_tokens: null,
    measured_cost_usd: null,
    cost_measurement_state: "not_observed",
    accounting_status: "pending",
    langfuse_status: "not_attempted",
    langfuse_verified_at: null,
  };

  it("names the in-flight state and issues no evidence request", async () => {
    const client = screenClient();

    render(
      <ProviderCallLedger
        calls={[inFlight]}
        client={client}
        principal={principalWith([PERMISSIONS.consoleRead, PERMISSIONS.evidenceRead])}
      />,
    );

    expect(await screen.findByText("Prompt & response")).toBeTruthy();
    expect(screen.getByText(/has not returned yet/)).toBeTruthy();
    expect(screen.queryByText(/no evidence record/)).toBeNull();
    expect(evidenceReads(client)).toHaveLength(0);
  });
});
