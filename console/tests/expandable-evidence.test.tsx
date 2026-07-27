import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import {
  ExpandableEvidence,
  PromptTranscript,
} from "../src/components/ExpandableEvidence";

describe("expandable evidence", () => {
  it("keeps dense evidence collapsed unless explicitly opened", () => {
    render(
      <ExpandableEvidence title="Attempt prompt" meta="judge">
        exact prompt
      </ExpandableEvidence>,
    );

    const details = screen.getByText("Attempt prompt").closest("details");
    expect(details?.hasAttribute("open")).toBe(false);
    expect(screen.getByText("exact prompt")).not.toBeNull();
  });

  it("renders immutable prompt identities and explicit redactions", () => {
    render(
      <PromptTranscript
        promptVersion="judge-v2"
        promptSha256={"a".repeat(64)}
        transcriptSha256={"b".repeat(64)}
        systemPrompt="Judge the evidence independently."
        messages={[
          {
            role: "system",
            content: "Judge the evidence independently.",
          },
          {
            role: "user",
            content: "Authorization: [REDACTED]",
          },
        ]}
        redactions={[{
          path: "$.provider_messages[1].content.authorization",
          reason: "authorization_header",
          replacement: "[REDACTED:AUTHORIZATION]",
        }]}
      />,
    );

    expect(screen.getByText("judge-v2")).not.toBeNull();
    expect(screen.getAllByText("Judge the evidence independently.")).toHaveLength(2);
    expect(screen.getByText(/authorization_header/)).not.toBeNull();
    expect(screen.getByText("Exact system prompt").closest("details")?.open).toBe(false);
    expect(screen.getByText("Bounded redaction metadata").closest("details")?.open).toBe(false);

    // Every sent message is a SIBLING of the system prompt, not nested under a wrapper, and its
    // summary names the role and size. Operators reported seeing "only system prompts" when the
    // body-bearing message sat two levels deeper behind the bare label "2. user".
    const userMessage = screen.getByText("Message 2 · user");
    expect(userMessage.closest("details")?.open).toBe(false);
    expect(
      userMessage.closest("details")?.parentElement?.closest("details"),
    ).toBeNull();
    expect(screen.getByText("Sent payload")).not.toBeNull();
  });

  it("shows and copies each exact full prompt hash through an accessible control", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const promptHash = "0123456789abcdef".repeat(4);
    const transcriptHash = "fedcba9876543210".repeat(4);

    render(
      <PromptTranscript
        promptVersion="judge-v2"
        promptSha256={promptHash}
        transcriptSha256={transcriptHash}
        systemPrompt="Judge the evidence independently."
        messages={[]}
        redactions={[]}
      />,
    );

    const promptHashCode = screen.getByLabelText(`System prompt SHA-256: ${promptHash}`);
    const transcriptHashCode = screen.getByLabelText(`Transcript SHA-256: ${transcriptHash}`);
    expect(promptHashCode.textContent).toBe(promptHash);
    expect(transcriptHashCode.textContent).toBe(transcriptHash);
    expect(promptHashCode.closest("dd")?.classList.contains("prompt-hash-value")).toBe(true);

    const promptHashField = promptHashCode.closest("dd");
    if (promptHashField === null) throw new Error("Prompt hash field was not rendered");
    fireEvent.click(within(promptHashField).getByRole("button", {
      name: "Copy System prompt SHA-256",
    }));
    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith(promptHash);
      expect(within(promptHashField).getByRole("button", {
        name: "System prompt SHA-256 copied",
      })).toBeTruthy();
    });
  });
});
