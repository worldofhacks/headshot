import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import { decodeAgentPromptSnapshot } from "../src/api/read-models";
import { RESOURCE_PATHS } from "../src/api/paths";
import { ExecutionPromptEvidence } from "../src/screens/RunOperationsScreen";
import type {
  AgentActivityReadModel,
  AgentPromptSnapshotReadModel,
} from "../src/types";

const at = "2026-07-26T22:00:00Z";
const systemPrompt = "Judge the evidence independently.";
const execution = {
  execution_id: "execution-1",
  campaign_run_id: "campaign-1",
  attempt_id: "attempt-1",
  agent_role: "judge",
  status: "succeeded",
  provider: "openrouter",
  model: "judge-model",
} as unknown as AgentActivityReadModel;
const snapshot: AgentPromptSnapshotReadModel = {
  execution_id: execution.execution_id,
  campaign_run_id: execution.campaign_run_id,
  attempt_id: execution.attempt_id,
  agent_role: execution.agent_role,
  system_prompt_version: "judge-v2",
  system_prompt_sha256: "a".repeat(64),
  system_prompt_content: systemPrompt,
  provider_messages: [
    { role: "system", content: systemPrompt },
    { role: "user", content: "Evaluate this synthetic response." },
  ],
  transcript_sha256: "b".repeat(64),
  redactions: [{
    path: "$.provider_messages[1].content.authorization",
    reason: "authorization_header",
    replacement: "[REDACTED:AUTHORIZATION]",
  }],
  created_at: at,
};

describe("immutable execution prompt snapshots", () => {
  it("strictly decodes ordered messages and bounded redaction metadata", () => {
    expect(decodeAgentPromptSnapshot(structuredClone(snapshot))).toEqual(snapshot);
    expect(() => decodeAgentPromptSnapshot({
      ...structuredClone(snapshot),
      provider_messages: [
        { role: "user", content: "out of order" },
        { role: "system", content: systemPrompt },
      ],
    })).toThrow("Invalid agent prompt snapshot");
    expect(() => decodeAgentPromptSnapshot({
      ...structuredClone(snapshot),
      unsupported_field: "reject",
    })).toThrow("Invalid agent prompt snapshot");
  });

  it("does not fetch until an evidence-authorized operator expands the disclosure", async () => {
    const client = {
      read: vi.fn(async () => ({ state: "ready" as const, data: snapshot })),
      command: vi.fn(),
    } as unknown as ApiClient;
    render(
      <ExecutionPromptEvidence
        client={client}
        execution={execution}
        canReadEvidence
      />,
    );

    expect(client.read).not.toHaveBeenCalled();
    const details = screen.getByText("Immutable prompt snapshot").closest("details");
    expect(details).not.toBeNull();
    details!.open = true;
    fireEvent(details!, new Event("toggle"));

    await waitFor(() => {
      expect(client.read).toHaveBeenCalledWith(
        RESOURCE_PATHS.agentPromptSnapshot(execution.execution_id),
        expect.any(AbortSignal),
      );
    });
    expect(await screen.findByText("judge-v2")).not.toBeNull();
    expect(details!.open).toBe(true);
    expect(screen.getByText("Exact system prompt").closest("details")?.open).toBe(false);
  });

  it("does not request prompt data without org:evidence:read", () => {
    const client = {
      read: vi.fn(),
      command: vi.fn(),
    } as unknown as ApiClient;
    render(
      <ExecutionPromptEvidence
        client={client}
        execution={execution}
        canReadEvidence={false}
      />,
    );

    expect(screen.getByText(/org:evidence:read/)).not.toBeNull();
    expect(client.read).not.toHaveBeenCalled();
  });
});
