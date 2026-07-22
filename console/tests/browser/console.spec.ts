import { expect, test } from "@playwright/test";

test("direct routes and browser history restore authoritative screens", async ({ page }) => {
  await page.goto("/coverage");
  await expect(page.getByRole("heading", { name: "Coverage", exact: true, level: 1 })).toBeVisible();
  await expect(page.getByText("browser_fixture_dependency").first()).toBeVisible();

  await page.getByRole("button", { name: "Targets", exact: true }).click();
  await expect(page).toHaveURL(/\/targets$/);
  await expect(page.getByRole("heading", { name: "Targets", exact: true, level: 1 })).toBeVisible();

  await page.goBack();
  await expect(page).toHaveURL(/\/coverage$/);
  await expect(page.getByRole("heading", { name: "Coverage", exact: true, level: 1 })).toBeVisible();

  await page.goto("/findings/server-record");
  await expect(page.getByRole("heading", { name: "Findings", exact: true })).toBeVisible();
  await expect(page.getByText("browser_fixture_dependency").first()).toBeVisible();
});

test("390px navigation exposes every screen without application overflow", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/live");
  await expect(page.getByRole("heading", { name: "Live operations" })).toBeVisible();

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
  await expect(page.getByText("snapshot", { exact: true })).toBeVisible();
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
