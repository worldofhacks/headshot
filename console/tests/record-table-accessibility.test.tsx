import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { RecordTable } from "../src/components/ResourceView";

describe("selectable record table", () => {
  it("uses one tab stop, supports row navigation, and activates with the keyboard", () => {
    const onSelect = vi.fn();
    const view = render(
      <RecordTable
        data={[
          { record_id: "one", label: "First" },
          { record_id: "two", label: "Second" },
          { record_id: "three", label: "Third" },
        ]}
        identityKeys={["record_id"]}
        columns={[
          { key: "record_id", label: "Record" },
          { key: "label", label: "Label" },
        ]}
        onSelect={onSelect}
      />,
    );

    const first = screen.getByText("First").closest("tr") as HTMLTableRowElement;
    const second = screen.getByText("Second").closest("tr") as HTMLTableRowElement;
    const third = screen.getByText("Third").closest("tr") as HTMLTableRowElement;
    expect(first.tabIndex).toBe(0);
    expect(second.tabIndex).toBe(-1);
    expect(third.tabIndex).toBe(-1);
    expect(view.container.querySelector(".table-scroll")?.getAttribute("tabindex")).toBeNull();

    first.focus();
    fireEvent.keyDown(first, { key: "ArrowDown" });
    expect(document.activeElement).toBe(second);
    expect(second.tabIndex).toBe(0);

    fireEvent.keyDown(second, { key: "End" });
    expect(document.activeElement).toBe(third);
    fireEvent.keyDown(third, { key: "Enter" });
    expect(onSelect).toHaveBeenLastCalledWith({
      record_id: "three",
      label: "Third",
    });

    fireEvent.keyDown(third, { key: "Home" });
    expect(document.activeElement).toBe(first);
    fireEvent.keyDown(first, { key: " " });
    expect(onSelect).toHaveBeenLastCalledWith({
      record_id: "one",
      label: "First",
    });
  });
});
