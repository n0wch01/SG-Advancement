import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// Dev: `npm run dev` proxies /v1 to the control plane (SGA_API, default the compose port on this
// machine), so the browser talks to one origin like in production, where the control plane serves
// the built files at /dashboard (SGA_DASHBOARD_DIR).
const api = process.env.SGA_API ?? "http://127.0.0.1:18100";

export default defineConfig({
  base: "/dashboard/",
  plugins: [react()],
  server: { port: 5173, strictPort: true, proxy: { "/v1": { target: api, changeOrigin: false } } },
  build: { outDir: "dist", sourcemap: false },
  test: { environment: "node" },
});
