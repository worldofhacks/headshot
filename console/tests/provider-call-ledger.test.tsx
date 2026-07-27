import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import type { Principal } from "../src/api/contracts";
import { RESOURCE_PATHS } from "../src/api/paths";
import {
  decodeProviderCallEvidence,
  decodeProviderCalls,
} from "../src/api/read-models";
import { ProviderCallLedger } from "../src/components/ProviderCallLedger";
import type {
  ProviderCallEvidenceReadModel,
  ProviderCallReadModel,
} from "../src/types";
import { PERMISSIONS } from "../src/types";

afterEach(cleanup);

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

const systemPrompt = "Judge the recorded evidence independently.";
const responseText = "The exact recorded provider response for physical call two.";
const evidence: ProviderCallEvidenceReadModel = {
  invocation_id: call.invocation_id,
  campaign_run_id: call.campaign_id,
  attempt_id: call.attempt_id,
  agent_role: "judge",
  physical_sequence: call.physical_sequence,
  status: call.status,
  error_code: null,
  prompt: {
    system_prompt_version: "judge-v2",
    system_prompt_sha256: "c".repeat(64),
    system_prompt_content: systemPrompt,
    provider_messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: "Evaluate this synthetic attempt." },
    ],
    transcript_sha256: "d".repeat(64),
    redactions: [{
      path: "$.provider_messages[1].content.authorization",
      reason: "authorization_header",
      replacement: "[REDACTED:AUTHORIZATION]",
    }],
  },
  response: {
    text: responseText,
    truncated: false,
    sha256: "e".repeat(64),
  },
};

const principalWith = (permissions: string[]): Principal => ({
  user_id: "user-operator",
  organization_id: "org-headshot",
  organization_role: "org:operator",
  organization_permissions: permissions,
});

const evidenceClient = (payload: ProviderCallEvidenceReadModel | null) => ({
  read: vi.fn(async () => ({
    state: "ready" as const,
    data: payload === null ? null : structuredClone(payload),
  })),
  command: vi.fn(),
}) as unknown as ApiClient & { read: ReturnType<typeof vi.fn> };

const disclosure = () => {
  const details = screen.getByText("Prompt & response").closest("details");
  if (details === null) throw new Error("The prompt and response disclosure did not render.");
  return details;
};

const setDisclosureOpen = (details: HTMLElement, open: boolean) => {
  (details as HTMLDetailsElement).open = open;
  fireEvent(details, new Event("toggle"));
};

describe("OpenRouter provider call read model", () => {
  it("strictly decodes durable call facts and deterministic Langfuse locators", () => {
    expect(decodeProviderCalls([structuredClone(call)])).toEqual([call]);
    expect(() => decodeProviderCalls([{
      ...structuredClone(call),
      langfuse_observation_name: "provider.attempt.1",
    }])).toThrow("Invalid provider call read model");
  });

  it("renders per-call identity, usage, cost, retry sequence, and Langfuse correlation", () => {
    render(<ProviderCallLedger calls={[call]} />);

    expect(screen.getByLabelText("OpenRouter physical-call summary")).toBeTruthy();
    expect(screen.getByText("1 retry call")).toBeTruthy();
    expect(screen.getAllByText("$0.0122")).toHaveLength(2);
    const ledger = screen.getByRole("table", {
      name: "OpenRouter physical provider call ledger",
    });
    expect(within(ledger).getByText("physical #2")).toBeTruthy();
    expect(within(ledger).getByText("google/gemini-2.5-pro")).toBeTruthy();
    expect(ledger.textContent).toContain("Google Vertex");
    expect(within(ledger).getByText("provider.attempt.2")).toBeTruthy();
    expect(within(ledger).getByText(/Agent query-back verified/)).toBeTruthy();
  });

  it("preserves an in-flight invocation without fabricating tokens or cost", () => {
    const inFlight: ProviderCallReadModel = {
      ...call,
      event_id: null,
      physical_sequence: 1,
      status: "in_flight",
      returned_model: null,
      upstream_provider: null,
      provider_request_id: null,
      input_tokens: null,
      output_tokens: null,
      reasoning_tokens: null,
      cost_measurement_state: "pending",
      accounting_status: "pending",
      measured_cost_usd: null,
      finished_at: null,
      duration_ms: null,
      langfuse_observation_name: "provider.attempt.1",
      langfuse_status: "queued",
      langfuse_verified_at: null,
    };

    expect(decodeProviderCalls([structuredClone(inFlight)])).toEqual([inFlight]);
    render(<ProviderCallLedger calls={[inFlight]} />);
    expect(screen.getByText("Running")).toBeTruthy();
    expect(screen.getAllByText("Pending")).toHaveLength(2);
  });
});

describe("per-call prompt and response evidence", () => {
  it("strictly decodes the evidence contract and tolerates absent prompt or response", () => {
    expect(decodeProviderCallEvidence(structuredClone(evidence))).toEqual(evidence);
    const withoutContent = { ...structuredClone(evidence), prompt: null, response: null };
    expect(decodeProviderCallEvidence(structuredClone(withoutContent))).toEqual(withoutContent);
    expect(() => decodeProviderCallEvidence({
      ...structuredClone(evidence),
      unsupported_field: "reject",
    })).toThrow("Invalid provider call evidence");
    expect(() => decodeProviderCallEvidence({
      ...structuredClone(evidence),
      response: { text: responseText, truncated: false, sha256: "not-a-digest" },
    })).toThrow("Invalid provider call evidence");
  });

  it("fetches once on first expand, caches across collapse, and shows the exact response", async () => {
    const client = evidenceClient(evidence);
    render(
      <ProviderCallLedger
        calls={[call]}
        client={client}
        principal={principalWith([PERMISSIONS.evidenceRead])}
      />,
    );

    expect(client.read).not.toHaveBeenCalled();
    const details = disclosure();
    setDisclosureOpen(details, true);

    await waitFor(() => {
      expect(client.read).toHaveBeenCalledWith(
        RESOURCE_PATHS.providerCallEvidence(call.invocation_id),
      );
    });
    expect(await screen.findByText("judge-v2")).toBeTruthy();
    expect(screen.getByText(responseText)).toBeTruthy();
    expect(screen.getByText("Complete recorded response")).toBeTruthy();

    setDisclosureOpen(details, false);
    setDisclosureOpen(details, true);
    await waitFor(() => {
      expect(screen.getByText(responseText)).toBeTruthy();
    });
    expect(client.read).toHaveBeenCalledTimes(1);
  });

  it("never requests evidence without org:evidence:read", () => {
    const client = evidenceClient(evidence);
    render(
      <ProviderCallLedger
        calls={[call]}
        client={client}
        principal={principalWith([PERMISSIONS.consoleRead])}
      />,
    );

    expect(screen.queryByText("Prompt & response")).toBeNull();
    expect(screen.getByText(/org:evidence:read/)).toBeTruthy();
    expect(client.read).not.toHaveBeenCalled();
  });

  it("never reconstructs an absent prompt snapshot or provider response", async () => {
    const client = evidenceClient({
      ...structuredClone(evidence),
      prompt: null,
      response: null,
    });
    render(
      <ProviderCallLedger
        calls={[call]}
        client={client}
        principal={principalWith([PERMISSIONS.evidenceRead])}
      />,
    );

    setDisclosureOpen(disclosure(), true);

    expect(
      await screen.findByText("No prompt snapshot was recorded for this execution."),
    ).toBeTruthy();
    expect(
      screen.getByText("No provider response was recorded for this physical call."),
    ).toBeTruthy();
    expect(screen.queryByText("judge-v2")).toBeNull();
    expect(client.read).toHaveBeenCalledTimes(1);
  });

  it("renders the disclosure as unavailable when no authenticated client is wired", () => {
    render(<ProviderCallLedger calls={[call]} />);

    expect(screen.queryByText("Prompt & response")).toBeNull();
    expect(
      screen.getByText(/rendered without an authenticated client and organization principal/),
    ).toBeTruthy();
  });
});
