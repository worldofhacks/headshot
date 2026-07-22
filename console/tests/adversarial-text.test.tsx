import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AdversarialText } from "../src/components/AdversarialText";

describe("adversarial evidence rendering", () => {
  it("renders hostile markup as inert text", () => {
    const payload = '<img src="x" onerror="alert(1)"><script>throw 1</script>';
    const { container } = render(<AdversarialText>{payload}</AdversarialText>);

    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toBe(payload);
  });
});
