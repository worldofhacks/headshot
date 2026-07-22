import { fileURLToPath } from "node:url";

import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

const browserFixture = (): Plugin => ({
  name: "headshot-browser-fixture",
  configureServer(server) {
    server.middlewares.use((request, response, next) => {
      const path = request.url?.split("?", 1)[0] ?? "";
      if (!path.startsWith("/api/v1/")) return next();
      response.setHeader("Cache-Control", "no-store");
      if (request.headers.authorization !== "Bearer browser-fixture-session") {
        response.statusCode = 401;
        response.setHeader("Content-Type", "application/json");
        response.end('{"detail":"Authentication required"}');
        return;
      }
      if (path === "/api/v1/events") {
        response.statusCode = 200;
        response.setHeader("Content-Type", "text/event-stream");
        if (!request.headers["last-event-id"] || request.headers["last-event-id"] === "0") {
          response.end('event: snapshot\ndata: {"action":"reconcile","state":"empty"}\n\n');
        } else {
          response.end(": heartbeat\n\n");
        }
        return;
      }
      response.setHeader("Content-Type", "application/json");
      if (request.method === "POST") {
        response.statusCode = 503;
        response.end('{"status":"unavailable","reason_code":"browser_fixture_dependency"}');
        return;
      }
      response.statusCode = 200;
      if (path === "/api/v1/principal") {
        response.end(JSON.stringify({
          state: "ready",
          data: {
            user_id: "user_browser_fixture",
            session_id: "session_browser_fixture",
            organization_id: "org_browser_fixture",
            organization_role: "org:operator",
            organization_permissions: [
              "org:console:read",
              "org:findings:read",
              "org:evidence:read",
              "org:campaign:launch",
              "org:campaign:abort",
              "org:campaign:authorize",
              "org:targets:manage",
              "org:config:manage",
              "org:findings:approve",
              "org:findings:resolve",
              "org:audit:read",
            ],
          },
        }));
        return;
      }
      if (path === "/api/v1/campaigns") {
        response.end('{"state":"empty","data":[]}');
        return;
      }
      if (path === "/api/v1/traces") {
        response.end(JSON.stringify({
          state: "ready",
          data: Array.from({ length: 9 }, (_, index) => ({
            request_id: `browser-request-${index}`,
            trace_id: `${String(index + 1).padStart(32, "0")}`,
            campaign_id: index < 5 ? "browser-campaign-alpha" : "browser-campaign-beta",
            attempt_id: `browser-attempt-${index}`,
            operation: "target.http",
            provider: "openemr",
            method: "POST",
            destination_host: "agent-production-9f62.up.railway.app",
            relative_path: "chat",
            status: index === 7 ? "failed" : "succeeded",
            status_code: index === 7 ? 503 : 200,
            error_code: index === 7 ? "upstream_unavailable" : null,
            started_at: `2026-07-22T00:0${index}:00Z`,
            finished_at: `2026-07-22T00:0${index}:01Z`,
            duration_ms: [820, 1110, 940, 1480, 1210, 1750, 1320, 2400, 990][index],
            request_bytes: 320 + index * 17,
            response_bytes: index === 7 ? 64 : 1100 + index * 90,
            measured_cost: 0.01,
            currency: "USD",
            langfuse_status: index === 7 ? "error" : "exported",
          })),
        }));
        return;
      }
      if (path === "/api/v1/costs") {
        response.end(JSON.stringify({
          state: "ready",
          data: [
            {
              accounting_id: "browser-campaign-alpha",
              campaign_id: "browser-campaign-alpha",
              provider: "live_target",
              measured_cost: 0.05,
              currency: "USD",
              request_count: 5,
              attempt_count: 5,
              confirmed_finding_count: 0,
              average_cost_per_request: 0.01,
              budget_usd: 1,
              budget_utilization: 0.05,
              duration_ms: 385000,
              execution_profile: "live",
              started_at: "2026-07-22T00:00:00Z",
              ended_at: "2026-07-22T00:06:25Z",
              recorded_at: "2026-07-22T00:06:25Z",
            },
            {
              accounting_id: "browser-campaign-beta",
              campaign_id: "browser-campaign-beta",
              provider: "live_target",
              measured_cost: 0.04,
              currency: "USD",
              request_count: 4,
              attempt_count: 4,
              confirmed_finding_count: 1,
              average_cost_per_request: 0.01,
              budget_usd: 1,
              budget_utilization: 0.04,
              duration_ms: 260000,
              execution_profile: "live",
              started_at: "2026-07-22T00:07:00Z",
              ended_at: "2026-07-22T00:11:20Z",
              recorded_at: "2026-07-22T00:11:20Z",
            },
          ],
        }));
        return;
      }
      if (path === "/api/v1/targets") {
        response.end(JSON.stringify({
          state: "ready",
          data: [{
            target_id: "browser-target",
            version: "v1",
            content_hash: "sha256:browser-target",
            name: "Browser Test Target",
            adapter_kind: "bruno",
            environment: "test",
            base_url: "https://browser-target.example.test",
            auth_mode: "header",
            credential_configured: true,
            synthetic_data_only: true,
            safety_caps: {
              budget_usd: 1,
              max_attempts_per_run: 9,
              target_requests_per_second: 1,
              run_timeout_seconds: 900,
            },
            lifecycle: "ready",
            allowed_lifecycle_transitions: ["disabled"],
            surfaces: [{
              surface_id: "chat",
              version: "v1",
              target_version: "v1",
              content_hash: "sha256:browser-surface",
              kind: "chat",
              protocol: "https",
              method: "POST",
              relative_path: "/chat",
              trust_boundary: "external",
              authentication_required: true,
              risk: "high",
              owasp_mappings: [],
              oracle_refs: [],
              enabled: true,
              created_at: "2026-07-22T00:00:00Z",
            }],
            campaign_template: {
              target_id: "browser-target",
              target_version: "v1",
              surface_id: "chat",
              surface_version: "v1",
              corpus_id: "browser-corpus",
              corpus_hash: "sha256:browser-corpus",
              execution_profile: "live",
              maximum_caps: {
                budget_usd: 1,
                max_attempts_per_run: 9,
                target_requests_per_second: 1,
                run_timeout_seconds: 900,
              },
            },
            created_at: "2026-07-22T00:00:00Z",
          }],
        }));
        return;
      }
      response.end(
        '{"state":"unavailable","data":null,"reason_code":"browser_fixture_dependency"}',
      );
    });
  },
});

// Same-origin SPA. Development intentionally has no cross-origin API proxy; protected
// requests always target /api/v1 on the current application origin. The browser-test mode
// alone swaps Clerk and API dependencies for deterministic test-only boundaries.
export default defineConfig(({ mode }) => {
  const browserTest = mode === "browser-test";
  const fixture = (name: string) =>
    fileURLToPath(new URL(`./tests/browser/fixtures/${name}`, import.meta.url));
  return {
    plugins: [react(), ...(browserTest ? [browserFixture()] : [])],
    resolve: browserTest
      ? {
          alias: {
            "@clerk/react": fixture("clerk-react.tsx"),
            "@clerk/clerk-js": fixture("clerk-js.ts"),
            "@clerk/ui": fixture("clerk-ui.ts"),
          },
        }
      : undefined,
    server: { port: 5173 },
    // Production source maps disabled: don't ship readable source to the browser / Railway.
    build: {
      outDir: "dist",
      sourcemap: false,
      rollupOptions: {
        output: {
          manualChunks: {
            "clerk-vendor": ["@clerk/clerk-js", "@clerk/react", "@clerk/ui"],
            "react-vendor": ["react", "react-dom"],
          },
        },
      },
    },
  };
});
