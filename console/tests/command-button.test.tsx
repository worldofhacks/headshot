import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import type { CommandAcknowledgement } from "../src/api/contracts";
import { CommandButton } from "../src/components/CommandButton";

describe("non-optimistic command controls", () => {
  it("does not announce or refresh state until the server acknowledges", async () => {
    let acknowledge!: (value: CommandAcknowledgement) => void;
    const pending = new Promise<CommandAcknowledgement>((resolve) => {
      acknowledge = resolve;
    });
    const onAcknowledged = vi.fn();
    const client: ApiClient = {
      read: vi.fn(),
      command: vi.fn().mockReturnValue(pending),
    };

    render(
      <CommandButton
        client={client}
        path="campaigns/run-id/abort"
        payload={{ reason: "operator_abort" }}
        label="Abort campaign"
        allowed
        onAcknowledged={onAcknowledged}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Abort campaign" }));

    expect((screen.getByRole("button", { name: "Waiting for server…" }) as HTMLButtonElement).disabled)
      .toBe(true);
    expect(onAcknowledged).not.toHaveBeenCalled();
    expect(screen.queryByText(/Server acknowledged/)).toBeNull();

    acknowledge({ acknowledgement_id: "ack-server", status: "accepted" });
    expect(await screen.findByText(/Server acknowledged · ack-server/)).toBeTruthy();
    expect(onAcknowledged).toHaveBeenCalledTimes(1);
  });

  it("reuses one idempotency key after an ambiguous response failure", async () => {
    const command = vi
      .fn<ApiClient["command"]>()
      .mockRejectedValueOnce(new Error("ambiguous transport failure"))
      .mockResolvedValueOnce({ acknowledgement_id: "ack-replayed", status: "completed" });
    const client: ApiClient = { read: vi.fn(), command };

    render(
      <CommandButton
        client={client}
        path="campaign-authorization-requests/request-id/decisions"
        payload={{ decision: "approved" }}
        label="Approve exact scope"
        allowed
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Approve exact scope" }));
    expect(await screen.findByText("The command was not acknowledged.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Approve exact scope" }));
    expect(await screen.findByText(/Server acknowledged · ack-replayed/)).toBeTruthy();

    expect(command).toHaveBeenCalledTimes(2);
    const firstKey = command.mock.calls[0]?.[3];
    const secondKey = command.mock.calls[1]?.[3];
    expect(firstKey).toMatch(/^[0-9a-f-]{36}$/);
    expect(secondKey).toBe(firstKey);
  });
});
