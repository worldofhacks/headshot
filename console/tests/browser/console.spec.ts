import { expect, test } from "@playwright/test";

test("direct routes and browser history restore authoritative screens", async ({ page }) => {
  await page.goto("/reports/browser-report-prompt-injection");
  await expect(page.getByRole("heading", { name: "Reports", exact: true, level: 1 })).toBeVisible();
  await expect(page.getByText("Validated drafts", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Vulnerability report", exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Targets", exact: true }).click();
  await expect(page).toHaveURL(/\/targets$/);
  await expect(page.getByRole("heading", { name: "Targets", exact: true, level: 1 })).toBeVisible();

  await page.goBack();
  await expect(page).toHaveURL(/\/reports\/browser-report-prompt-injection$/);
  await expect(page.getByRole("heading", { name: "Reports", exact: true, level: 1 })).toBeVisible();

  await page.goto("/coverage");
  await expect(page.getByRole("heading", {
    name: "Coverage & Regression",
    exact: true,
    level: 1,
  })).toBeVisible();
  await expect(page.getByRole("button", {
    name: "Coverage & Regression",
    exact: true,
  })).toHaveAttribute("aria-current", "page");
  await expect(page.getByText("Verified attempts", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Regression checks", { exact: true }).first()).toBeVisible();

  await page.goto("/findings/server-record");
  await expect(page.getByRole("heading", { name: "Findings", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Risk distribution", exact: true })).toBeVisible();

  await page.goto("/agents");
  await expect(page.getByRole("heading", { name: "Agent operations", exact: true })).toBeVisible();
  await expect(page.getByText("Hosted configured model", { exact: true })).toBeVisible();
  await expect(page.getByText("Hosted configured provider", { exact: true })).toBeVisible();
  await expect(page.getByText("Provider-served model", { exact: true })).toBeVisible();
  await expect(page.getByText("unavailable — no hosted campaign execution recorded", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("heading", {
    name: "Hosted role assignment",
    exact: true,
  })).toBeVisible();
  await expect(page.getByRole("button", {
    name: "Open four-role authorization",
  })).toBeEnabled();
  await expect(page.getByText(/There is no per-role or deterministic fallback/i)).toBeVisible();
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
  await expect(page.getByRole("button", { name: "Disable surface" })).toBeEnabled();
  await expect(page.getByRole("button", {
    name: "Register exact catalog target",
  })).toBeDisabled();
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
  await page.goto("/live");
  await page.getByRole("button", { name: /Orchestrator/ }).click();
  await expect(page.getByText("Campaign p50 / p95", { exact: true })).toBeVisible();
  await expect(page.getByText("4.6 ms / 6.2 ms", { exact: true })).toBeVisible();
  await expect(page.getByText("Campaign known spend", { exact: true })).toBeVisible();
  await expect(
    page.getByText(
      "4 observed · 2 awaiting remote verification",
      { exact: true },
    ),
  ).toBeVisible();

  await page.goto("/agents");
  await expect(page.getByRole("heading", { name: "Agent operations", exact: true })).toBeVisible();
  await expect(page.getByText("4.4 / 6.2 ms", { exact: true })).toBeVisible();
  await expect(
    page.getByText(
      "4 observed · 2 awaiting remote verification",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(page.getByText("Last Langfuse query-back", { exact: true })).toBeVisible();
  const agentLedger = page.getByRole("table");
  await expect(
    agentLedger.getByRole("columnheader", { name: "Accounting", exact: true }),
  ).toBeVisible();
  await expect(agentLedger.getByText("unavailable", { exact: true }).first()).toBeVisible();

  await page.goto("/traces");
  await expect(page.getByRole("heading", { name: "Traces", exact: true, level: 1 })).toBeVisible();
  await expect(page.getByRole("img", { name: "Target request latency over time" })).toBeVisible();
  await expect(page.getByText("77%").first()).toBeVisible();
  await expect(page.getByText("Langfuse observed", { exact: true })).toBeVisible();
  await expect(page.getByText("Awaiting remote verification", { exact: true })).toBeVisible();
  await expect(page.getByText("Black-box target requests", { exact: false })).toBeVisible();
  await page.getByRole("listitem").filter({ hasText: "agent.red_team" }).click();
  await expect(page.getByText("Campaign role p50 / p95", { exact: true })).toBeVisible();
  await expect(page.getByText("6 ms / 8 ms", { exact: true })).toBeVisible();
  await page.getByRole("listitem").nth(7).click();
  await expect(page.getByText("Transport error: upstream_unavailable")).toBeVisible();

  await page.getByRole("button", { name: "Costs", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Costs", exact: true, level: 1 })).toBeVisible();
  await expect(page.getByText("Known measured spend", { exact: true })).toBeVisible();
  await expect(page.getByText("$0.0900").first()).toBeVisible();
  const accounting = page.getByRole("table", {
    name: "Campaign and agent accounting records",
  });
  await expect(accounting).toBeVisible();
  await expect(
    accounting.getByRole("columnheader", { name: "Campaign findings", exact: true }),
  ).toBeVisible();
  await expect(
    accounting.getByRole("columnheader", { name: "Role p50", exact: true }),
  ).toBeVisible();
  await expect(
    accounting.getByRole("columnheader", { name: "Role p95", exact: true }),
  ).toBeVisible();
  const redTeamAccounting = accounting.getByRole("row").filter({ hasText: "red team" });
  await expect(redTeamAccounting).toContainText("6 ms");
  await expect(redTeamAccounting).toContainText("8 ms");
  await expect(redTeamAccounting).toContainText("$0.0000");

  const hasOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth,
  );
  expect(hasOverflow).toBe(false);
});
