import { describe, expect, it } from "vitest";

import { RESOURCE_PATHS } from "../src/api/paths";
import { selectAgentPromptIdentity } from "../src/screens/AgentToolScreens";

const assignment = (
  configurationSha256: string,
  promptVersion: string | null,
  promptSha256: string | null,
  executionMode: "deterministic" | "hosted_advisory" = "hosted_advisory",
) => ({
  configuration_sha256: configurationSha256,
  prompt_version: promptVersion,
  prompt_sha256: promptSha256,
  execution_mode: executionMode,
});

describe("agent prompt identity selection", () => {
  it("uses a hash-bound same-origin path for hosted prompts", () => {
    const path = RESOURCE_PATHS.agentPrompt(
      "judge",
      "1",
      "a".repeat(64),
      "b".repeat(64),
    );

    expect(path).toBe(
      `agent-prompts/judge/1/${"a".repeat(64)}/${"b".repeat(64)}`,
    );
    expect(path).not.toContain("?");
  });

  it("prefers and labels the active hosted identity when active and staged prompts coexist", () => {
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

  it("never presents a deterministic role prompt as the agent identity", () => {
    const selected = selectAgentPromptIdentity({
      active_assignment: assignment(
        "a".repeat(64),
        "1",
        "b".repeat(64),
        "deterministic",
      ),
      staged_assignment: assignment("c".repeat(64), "2", "d".repeat(64)),
    });

    expect(selected?.source).toBe("staged");
    expect(selected?.configurationSha256).toBe("c".repeat(64));
  });
});
