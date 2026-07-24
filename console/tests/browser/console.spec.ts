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

test("spec(T-F18a:AC-1) desktop and mobile expose one canonical Coverage route", async ({ page }) => {
  await page.goto("/live");
  const desktop = page.locator(".sidebar nav");
  const desktopCoverage = desktop.getByText("Coverage & Regression", { exact: true });

  await expect(desktopCoverage).toHaveCount(1);
  await expect(desktop.getByText("Resilience", { exact: true })).toHaveCount(0);
  await desktopCoverage.click();
  await expect(page).toHaveURL(/\/coverage$/);

  await page.setViewportSize({ width: 390, height: 844 });
  const mobile = page.locator(".mobile-nav");
  await mobile.getByText("More", { exact: true }).click();
  const mobileCoverage = mobile.getByText("Coverage & Regression", { exact: true });

  await expect(mobileCoverage).toHaveCount(1);
  await expect(mobile.getByText("Resilience", { exact: true })).toHaveCount(0);
  await mobileCoverage.click();
  await expect(page).toHaveURL(/\/coverage$/);
});

test("spec(T-F18a:AC-2) resilience replaces to Coverage without a history loop", async ({ page }) => {
  await page.goto("/live");
  await page.goto("/resilience?window=30d#latest-regression");

  await expect(page).toHaveURL(/\/coverage$/);
  await expect(page.getByRole("heading", { name: "Coverage", exact: true, level: 1 })).toBeVisible();

  await page.goBack();
  await expect(page).toHaveURL(/\/live$/);
  await page.goForward();
  await expect(page).toHaveURL(/\/coverage$/);
});

test("spec(T-F18a:AC-3) invalid route families replace-normalize to Live", async ({ page }) => {
  await page.goto("/live");
  for (const invalidPath of [
    "/unknown?next=/findings#fragment",
    "/findings/%E0%A4%A?next=/findings#fragment",
    "/live/attempt-1/extra?next=/findings#fragment",
    "/resilience/extra?next=/findings#fragment",
    "/coverage/case-1?next=/findings#fragment",
  ]) {
    await page.evaluate((path) => {
      window.history.pushState(null, "", path);
      window.dispatchEvent(new PopStateEvent("popstate"));
    }, invalidPath);

    await expect(page).toHaveURL(/\/live$/);
    await expect(page.getByRole("heading", { name: "Live operations", exact: true })).toBeVisible();
  }
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
