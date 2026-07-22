import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/browser",
  testMatch: "**/*.spec.ts",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: "line",
  outputDir: "test-results/browser",
  use: {
    baseURL: "http://127.0.0.1:4174",
    ...devices["Desktop Chrome"],
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "npm run dev:browser",
    url: "http://127.0.0.1:4174/live",
    reuseExistingServer: false,
    timeout: 30_000,
    env: {
      ...process.env,
      VITE_CLERK_PUBLISHABLE_KEY: "pk_test_browser_fixture",
    },
  },
});
