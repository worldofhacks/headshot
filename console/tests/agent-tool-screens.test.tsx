import { describe, expect, it } from "vitest";

import { selectAgentPromptIdentity } from "../src/screens/AgentToolScreens";

const assignment = (
  configurationSha256: string,
  promptVersion: string | null,
  promptSha256: string | null,
) => ({
  configuration_sha256: configurationSha256,
  prompt_version: promptVersion,
  prompt_sha256: promptSha256,
});

describe("agent prompt identity selection", () => {
  it("prefers and labels the active served identity when active and staged prompts coexist", () => {
    const selected = selectAgentPromptIdentity({
      active_assignment: assignment("a".repeat(64), "1", "b".repeat(64)),
      staged_assignment: assignment("c".repeat(64), "2", "d".repeat(64)),
    });

    expect(selected).toEqual({
      source: "active",
      version: "1",
      sha256: "b".repeat(64),
      configurationSha256: "a".repeat(64),
    });
  });

  it("uses a distinctly staged identity only when no active prompt identity exists", () => {
    const selected = selectAgentPromptIdentity({
      active_assignment: assignment("a".repeat(64), null, null),
      staged_assignment: assignment("c".repeat(64), "2", "d".repeat(64)),
    });

    expect(selected?.source).toBe("staged");
    expect(selected?.configurationSha256).toBe("c".repeat(64));
  });
});
