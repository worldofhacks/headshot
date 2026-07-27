import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client";
import type { Principal } from "../src/api/contracts";
import { RESOURCE_PATHS } from "../src/api/paths";
import { RunsWorkspace } from "../src/screens/Workspaces";
import { PERMISSIONS } from "../src/types";

describe("runs workspace navigation", () => {
  it("opens the target registry directly without loading pilot-run campaign data", async () => {
    const read = vi.fn(async () => ({ state: "empty" as const, data: null }));
    const client = { read, command: vi.fn() } as unknown as ApiClient;
    const principal: Principal = {
      user_id: "user-1",
      organization_id: "org-1",
      organization_role: "org:operator",
      organization_permissions: [PERMISSIONS.consoleRead],
    };

    render(
      <RunsWorkspace
        client={client}
        principal={principal}
        entityId={null}
        getToken={async () => "session"}
        view="targets"
        onViewChange={vi.fn()}
      />,
    );

    expect(await screen.findByRole("heading", { name: "Targets" })).not.toBeNull();
    expect(screen.queryByRole("heading", { name: "Pilot runs" })).toBeNull();
    await waitFor(() => {
      expect(read).toHaveBeenCalledWith(RESOURCE_PATHS.targetCatalog, expect.any(AbortSignal));
      expect(read).toHaveBeenCalledWith(RESOURCE_PATHS.targets, expect.any(AbortSignal));
    });
    expect(read).not.toHaveBeenCalledWith(RESOURCE_PATHS.campaigns, expect.anything());
  });
});
