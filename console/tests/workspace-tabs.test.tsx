import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { WorkspaceTabs } from "../src/components/WorkspaceTabs";

describe("workspace tabs", () => {
  it("announces selection and delegates navigation", () => {
    const onChange = vi.fn();
    render(
      <WorkspaceTabs
        label="Observability view"
        active="traces"
        onChange={onChange}
        tabs={[
          { id: "traces", label: "Traces", count: 3 },
          { id: "costs", label: "Costs" },
        ]}
      />,
    );

    const traces = screen.getByRole("tab", { name: "Traces 3" });
    const costs = screen.getByRole("tab", { name: "Costs" });
    expect(traces.getAttribute("aria-selected")).toBe("true");
    expect(traces.getAttribute("tabindex")).toBe("0");
    expect(costs.getAttribute("tabindex")).toBe("-1");
    fireEvent.click(costs);
    expect(onChange).toHaveBeenCalledWith("costs");
  });

  it("supports roving focus with arrows, Home, and End", () => {
    const onChange = vi.fn();
    render(
      <WorkspaceTabs
        label="System view"
        active="agents"
        onChange={onChange}
        tabs={[
          { id: "agents", label: "Agents" },
          { id: "tooling", label: "Tool inventory" },
          { id: "configuration", label: "Configuration" },
        ]}
      />,
    );

    const agents = screen.getByRole("tab", { name: "Agents" });
    const tooling = screen.getByRole("tab", { name: "Tool inventory" });
    const configuration = screen.getByRole("tab", { name: "Configuration" });
    agents.focus();

    fireEvent.keyDown(agents, { key: "ArrowRight" });
    expect(document.activeElement).toBe(tooling);
    expect(onChange).toHaveBeenLastCalledWith("tooling");

    fireEvent.keyDown(tooling, { key: "End" });
    expect(document.activeElement).toBe(configuration);
    expect(onChange).toHaveBeenLastCalledWith("configuration");

    fireEvent.keyDown(configuration, { key: "ArrowRight" });
    expect(document.activeElement).toBe(agents);
    expect(onChange).toHaveBeenLastCalledWith("agents");

    fireEvent.keyDown(agents, { key: "End" });
    fireEvent.keyDown(configuration, { key: "Home" });
    expect(document.activeElement).toBe(agents);
    expect(onChange).toHaveBeenLastCalledWith("agents");
  });
});
