import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The app is served by the Go binary under /ui/ (embedded build output in dist/).
// In dev (`npm run dev`), Vite serves on :5173 and proxies Connect RPC calls and
// the health check to the Go server on :8080, so the front end talks to the real
// backend. The Connect HTTP/JSON API lives under /turnstile.v1.Turnstile/*.
export default defineConfig({
  plugins: [react()],
  base: "/ui/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/turnstile.v1.Turnstile": "http://localhost:8080",
      "/health": "http://localhost:8080",
    },
  },
});
