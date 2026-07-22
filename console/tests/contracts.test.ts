import { describe, expect, it } from "vitest";

import { decodeResourceEnvelope } from "../src/api/contracts";

describe("resource envelopes", () => {
  it.each(["ready", "empty", "unavailable", "stale", "degraded", "error"])(
    "accepts the backend %s state",
    (state) => {
      expect(decodeResourceEnvelope({ state, data: null }).state).toBe(state);
    },
  );

  it("rejects unknown states instead of treating them as ready", () => {
    expect(() => decodeResourceEnvelope({ state: "nominal", data: {} })).toThrow(
      "Invalid resource envelope",
    );
  });
});
