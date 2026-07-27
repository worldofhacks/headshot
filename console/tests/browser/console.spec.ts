import { expect, test, type Page } from "@playwright/test";

const primaryLabels = [
  "Runs",
  "Findings",
  "Coverage",
  "Approvals",
  "Observability",
  "System",
] as const;

const expectNoPageOverflow = async (page: Page) => {
  expect(await page.evaluate(
    () => document.documentElement.scrollWidth <= window.innerWidth,
  )).toBe(true);
};

test("exact six primary groups preserve legacy routes and expose Run operations first", async ({
  page,
}) => {
  await page.goto("/runs");
  await expect(page.getByRole("heading", {
    name: "Run operations",
    exact: true,
    level: 1,
  })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Operations", exact: true }))
    .toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("heading", { name: "Case progress", exact: true }))
    .toBeVisible();
  await expect(page.getByRole("heading", {
    name: "Execution accounting",
    exact: true,
  })).toBeVisible();
  await expect(page.getByText("Physical target requests", { exact: true })).toBeVisible();
  await expect(page.getByText("Provider calls", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Abort selected campaign", exact: true }))
    .toBeEnabled();

  const primary = page.getByLabel("Primary navigation");
  await expect(primary.getByRole("button")).toHaveCount(6);
  expect(await primary.locator(".nav-item > span:not(.nav-badge)").allTextContents())
    .toEqual(primaryLabels);
  await expect(primary.getByRole("button", { name: "Runs", exact: true }))
    .toHaveAttribute("aria-current", "page");

  await page.goto("/reports/browser-report-prompt-injection");
  await expect(page.getByRole("heading", { name: "Reports", exact: true, level: 1 }))
    .toBeVisible();
  await expect(page.getByRole("tab", { name: "Reports", exact: true }))
    .toHaveAttribute("aria-selected", "true");
  await expect(primary.getByRole("button", { name: "Findings", exact: true }))
    .toHaveAttribute("aria-current", "page");
  await expect(page.getByRole("heading", {
    name: "Vulnerability report",
    exact: true,
  })).toBeVisible();

  await page.goto("/targets");
  await expect(page.getByRole("heading", { name: "Targets", exact: true, level: 1 }))
    .toBeVisible();
  await expect(page.getByRole("tab", { name: "Targets", exact: true }))
    .toHaveAttribute("aria-selected", "true");
  await expect(primary.getByRole("button", { name: "Runs", exact: true }))
    .toHaveAttribute("aria-current", "page");

  await page.goto("/agents");
  await expect(page.getByRole("heading", {
    name: "Agent operations",
    exact: true,
    level: 1,
  })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Agents", exact: true }))
    .toHaveAttribute("aria-selected", "true");
  await expect(primary.getByRole("button", { name: "System", exact: true }))
    .toHaveAttribute("aria-current", "page");

  await page.goto("/tooling");
  await expect(page.getByRole("heading", {
    name: "Tool inventory",
    exact: true,
    level: 1,
  })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Tool inventory", exact: true }))
    .toHaveAttribute("aria-selected", "true");

  await page.goto("/config");
  await expect(page.getByRole("heading", {
    name: "Configuration",
    exact: true,
    level: 1,
  })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Configuration", exact: true }))
    .toHaveAttribute("aria-selected", "true");

  await page.goto("/live/browser-attempt-2");
  await expect(page.getByRole("heading", {
    name: "Run operations",
    exact: true,
    level: 1,
  })).toBeVisible();
  await expect(page).toHaveURL(/\/live\/browser-attempt-2$/);
  await expect(page.locator("details[open]").filter({
    has: page.getByText("Attempt 3", { exact: true }),
  })).toHaveCount(1);
});

test("390px grouped navigation has no overflow and supports keyboard tabs", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/runs");
  await expect(page.getByRole("heading", { name: "Run operations", exact: true }))
    .toBeVisible();
  await expectNoPageOverflow(page);

  const operations = page.getByRole("tab", { name: "Operations", exact: true });
  const targets = page.getByRole("tab", { name: "Targets", exact: true });
  await expect(operations).toHaveAttribute("tabindex", "0");
  await expect(targets).toHaveAttribute("tabindex", "-1");
  await operations.focus();
  await page.keyboard.press("ArrowRight");
  await expect(page).toHaveURL(/\/targets$/);
  await expect(page.getByRole("heading", { name: "Targets", exact: true }))
    .toBeVisible();
  await expect(page.getByRole("tab", { name: "Targets", exact: true }))
    .toHaveAttribute("aria-selected", "true");
  await expectNoPageOverflow(page);

  await page.getByRole("tab", { name: "Targets", exact: true }).focus();
  await page.keyboard.press("ArrowLeft");
  await expect(page).toHaveURL(/\/runs$/);
  await expect(page.getByRole("heading", { name: "Run operations", exact: true }))
    .toBeVisible();

  await page.getByRole("button", { name: "System", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Agent operations", exact: true }))
    .toBeVisible();

  const agents = page.getByRole("tab", { name: "Agents", exact: true });
  await agents.focus();
  await page.keyboard.press("End");
  await expect(page).toHaveURL(/\/config$/);
  await expect(page.getByRole("heading", { name: "Configuration", exact: true }))
    .toBeVisible();
  await expect(page.getByRole("tab", { name: "Configuration", exact: true }))
    .toHaveAttribute("aria-selected", "true");
  await expectNoPageOverflow(page);
});

test("attempt and prompt evidence are keyboard expandable and prompt loading is lazy", async ({
  page,
}) => {
  const promptRequests: string[] = [];
  page.on("request", (request) => {
    if (/\/api\/v1\/agent-executions\/[^/]+\/prompt-snapshot$/.test(
      new URL(request.url()).pathname,
    )) {
      promptRequests.push(request.url());
    }
  });

  await page.goto("/runs");
  await expect(page.getByRole("heading", { name: "Run operations", exact: true }))
    .toBeVisible();
  const attempt = page.locator("details.event-record").filter({
    has: page.getByText("Attempt 4", { exact: true }),
  }).first();
  await expect(attempt).not.toHaveAttribute("open", "");
  expect(promptRequests).toEqual([]);

  const attemptSummary = attempt.locator(":scope > summary");
  await attemptSummary.focus();
  await page.keyboard.press("Enter");
  await expect(attempt).toHaveAttribute("open", "");

  const execution = attempt.locator("details.event-record").filter({
    has: page.getByText("red team execution", { exact: true }),
  }).first();
  await expect(execution).not.toHaveAttribute("open", "");
  await execution.locator(":scope > summary").focus();
  await page.keyboard.press("Enter");
  await expect(execution).toHaveAttribute("open", "");

  const prompt = execution.locator("details.event-record").filter({
    has: page.getByText("Immutable prompt snapshot", { exact: true }),
  }).first();
  await expect(prompt).not.toHaveAttribute("open", "");
  expect(promptRequests).toEqual([]);

  await prompt.locator(":scope > summary").focus();
  await page.keyboard.press("Enter");
  await expect(prompt).toHaveAttribute("open", "");
  await expect(page.getByText("browser-fixture-v1", { exact: true })).toBeVisible();
  await expect.poll(() => promptRequests.length).toBeGreaterThan(0);

  const systemPromptText =
    "Operate as the red_team for a synthetic browser fixture. Enforce the approved target and safety scope.";
  const exactSystemPrompt = prompt.locator("details.event-record").filter({
    has: page.getByText("Exact system prompt", { exact: true }),
  }).first();
  const exactSystemPromptContent = exactSystemPrompt.getByText(
    systemPromptText,
    { exact: true },
  );
  await expect(exactSystemPromptContent).toHaveCount(1);
  await expect(exactSystemPromptContent).toBeHidden();
  await expect(exactSystemPrompt).not.toHaveAttribute("open", "");
  await exactSystemPrompt.locator(":scope > summary").focus();
  await page.keyboard.press("Enter");
  await expect(exactSystemPromptContent).toBeVisible();

  const orderedMessages = prompt.locator("details.event-record").filter({
    has: page.getByText("Ordered provider messages", { exact: true }),
  }).first();
  await expect(orderedMessages).not.toHaveAttribute("open", "");
  await expect(page.getByText("Bounded redaction metadata", { exact: true })).toBeVisible();
  expect(promptRequests.length).toBeGreaterThan(0);
});

test("Traces and Costs use the selected campaign scope through grouped navigation", async ({
  page,
}) => {
  await page.goto("/runs");
  await expect(page.getByRole("heading", { name: "Run operations", exact: true }))
    .toBeVisible();

  const traceRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/api/v1/traces"
      && url.searchParams.get("campaign_id") === "browser-campaign-gamma";
  });
  await page.getByLabel("Primary navigation")
    .getByRole("button", { name: "Observability", exact: true })
    .click();
  await traceRequest;
  await expect(page).toHaveURL(/\/observability\/browser-campaign-gamma$/);
  await expect(page.getByRole("heading", { name: "Traces", exact: true, level: 1 }))
    .toBeVisible();
  await expect(page.getByRole("tab", { name: "Traces", exact: true }))
    .toHaveAttribute("aria-selected", "true");

  const costRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/api/v1/costs"
      && url.searchParams.get("campaign_id") === "browser-campaign-gamma";
  });
  await page.getByRole("tab", { name: "Costs", exact: true }).click();
  await costRequest;
  await expect(page).toHaveURL(/\/costs\/browser-campaign-gamma$/);
  await expect(page.getByRole("heading", { name: "Costs", exact: true, level: 1 }))
    .toBeVisible();
  await expect(page.getByRole("tab", { name: "Costs", exact: true }))
    .toHaveAttribute("aria-selected", "true");

  await page.goto("/traces");
  await expect(page.getByRole("heading", { name: "Traces", exact: true, level: 1 }))
    .toBeVisible();
  await page.goto("/costs");
  await expect(page.getByRole("heading", { name: "Costs", exact: true, level: 1 }))
    .toBeVisible();
});

test("an explicit campaign outside the bounded list remains the exact operations and observability scope", async ({
  page,
}) => {
  const campaignId = "browser-campaign-outside-bounded-list";
  const operationsRequest = page.waitForRequest((request) => (
    new URL(request.url()).pathname
      === `/api/v1/campaigns/${campaignId}/operations`
  ));

  await page.goto(`/runs/${campaignId}`);
  await operationsRequest;
  await expect(page.getByRole("heading", { name: "Run operations", exact: true }))
    .toBeVisible();
  await expect(page.getByText(
    "Selected campaign metadata is unavailable in the bounded campaign list. Loading the exact campaign-scoped operations projection.",
    { exact: true },
  )).toBeVisible();
  await expect(page.getByLabel("Campaign scope")).toHaveValue(campaignId);
  await expect(page.getByText("browser-…list", { exact: true })).toBeVisible();
  await expect(page.locator(".campaign-state")).toContainText("Unavailable");

  const traceRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/api/v1/traces"
      && url.searchParams.get("campaign_id") === campaignId;
  });
  await page.getByLabel("Primary navigation")
    .getByRole("button", { name: "Observability", exact: true })
    .click();
  await traceRequest;

  const costRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/api/v1/costs"
      && url.searchParams.get("campaign_id") === campaignId;
  });
  await page.getByRole("tab", { name: "Costs", exact: true }).click();
  await costRequest;
  await expect(page).toHaveURL(new RegExp(`/costs/${campaignId}$`));

  const reloadedCostRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/api/v1/costs"
      && url.searchParams.get("campaign_id") === campaignId;
  });
  await page.reload();
  await reloadedCostRequest;
  await expect(page).toHaveURL(new RegExp(`/costs/${campaignId}$`));
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

  await page.goto("/runs");
  await expect(page.getByRole("heading", { name: "Run operations", exact: true }))
    .toBeVisible();
  await expect(page.getByRole("heading", { name: "Case progress", exact: true }))
    .toBeVisible();
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
