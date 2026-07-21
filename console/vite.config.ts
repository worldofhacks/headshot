import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Headshot Operator Console — static SPA. No backend proxy: every console API is
// PROPOSED today, so the app runs entirely on the built-in Demo scenario + honest
// Integration empty-states (see FINAL_IMPLEMENTATION_HANDOFF.md). When a real
// read-model API lands, add a `server.proxy` entry here.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173 },
  // Production source maps disabled: don't ship readable source to the browser / Railway.
  build: { outDir: "dist", sourcemap: false },
});
