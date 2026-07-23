import { expect, test } from "@playwright/test";

test("direct routes and browser history restore authoritative screens", async ({ page }) => {
  await page.goto("/coverage");
  await expect(page.getByRole("heading", { name: "Coverage", exact: true, level: 1 })).toBeVisible();
  await expect(page.getByText("Verified attempts", { exact: true }).first()).toBeVisible();

  await page.getByRole("button", { name: "Targets", exact: true }).click();
  await expect(page).toHaveURL(/\/targets$/);
  await expect(page.getByRole("heading", { name: "Targets", exact: true, level: 1 })).toBeVisible();

  await page.goBack();
  await expect(page).toHaveURL(/\/coverage$/);
  await expect(page.getByRole("heading", { name: "Coverage", exact: true, level: 1 })).toBeVisible();

  await page.goto("/findings/server-record");
  await expect(page.getByRole("heading", { name: "Findings", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Risk distribution", exact: true })).toBeVisible();
});

test("390px navigation exposes every screen without application overflow", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/live");
  await expect(page.getByRole("heading", { name: "Live operations" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Birdseye" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(page.getByText("Security posture", { exact: true })).toBeVisible();

  await page.getByRole("tab", { name: "Attempt stream" }).click();
  await expect(page.getByRole("button", { name: "Request rerun authorization" })).toBeEnabled();
  const firstEvent = page.locator(".event-record").first();
  await expect(firstEvent).toBeVisible();
  expect((await firstEvent.boundingBox())?.height).toBeGreaterThanOrEqual(36);

  await page.getByRole("button", { name: "Targets", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Targets", exact: true })).toBeVisible();
  await page.getByText("Browser Test Target", { exact: true }).click();
  await expect(page.getByLabel("Budget USD")).toHaveValue("1");
  await expect(page.getByLabel("Maximum attempts")).toHaveValue("9");
  await expect(page.getByLabel("Target requests / second")).toHaveValue("1");
  await expect(page.getByLabel("Run timeout seconds")).toHaveValue("900");
  await expect(page.getByRole("button", { name: "Request exact campaign authorization" })).toBeEnabled();

  await page.getByRole("button", { name: "More", exact: true }).click();
  await page.getByRole("button", { name: "Configuration", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Configuration", exact: true })).toBeVisible();

  const hasOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth,
  );
  expect(hasOverflow).toBe(false);
});

test("browser boundary has no console errors or external asset requests", async ({ page }) => {
  const errors: string[] = [];
  const external: string[] = [];
  const protectedRequests: Array<{ url: string; authorization?: string }> = [];
  const fontRequests: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin !== "http://127.0.0.1:4174") external.push(request.url());
    if (url.pathname.startsWith("/api/v1/")) {
      protectedRequests.push({
        url: request.url(),
        authorization: request.headers().authorization,
      });
    }
    if (request.resourceType() === "font") fontRequests.push(request.url());
  });

  await page.goto("/live");
  await expect(page.getByRole("heading", { name: "Live operations" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Security posture" })).toBeVisible();
  await page.evaluate(() => document.fonts.ready);

  expect(errors).toEqual([]);
  expect(external).toEqual([]);
  expect(fontRequests.length).toBeGreaterThan(0);
  expect(protectedRequests.length).toBeGreaterThan(0);
  for (const request of protectedRequests) {
    expect(request.authorization?.startsWith("Bearer ")).toBe(true);
    const names = [...new URL(request.url).searchParams.keys()];
    expect(names.some((name) => /auth|bearer|jwt|session|token/i.test(name))).toBe(false);
  }
});

test("trace and cost screens visualize measured Langfuse-correlated telemetry", async ({ page }) => {
  await page.goto("/traces");
  await expect(page.getByRole("heading", { name: "Traces", exact: true, level: 1 })).toBeVisible();
  await expect(page.getByRole("img", { name: "Target request latency over time" })).toBeVisible();
  await expect(page.getByText("89%").first()).toBeVisible();
  await expect(page.getByText("Token usage is unavailable", { exact: false })).toBeVisible();
  await page.getByRole("listitem").nth(7).click();
  await expect(page.getByText("Transport error: upstream_unavailable")).toBeVisible();

  await page.getByRole("button", { name: "Costs", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Costs", exact: true, level: 1 })).toBeVisible();
  await expect(page.getByText("Campaign spend", { exact: true })).toBeVisible();
  await expect(page.getByText("$0.0900").first()).toBeVisible();
  await expect(page.getByRole("table", { name: "Campaign accounting records" })).toBeVisible();

  const hasOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth,
  );
  expect(hasOverflow).toBe(false);
});
