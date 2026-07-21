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
