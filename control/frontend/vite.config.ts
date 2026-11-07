import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const api = "http://127.0.0.1:8090";

// The API only accepts a state-changing request whose Origin host equals the
// Host it received. Through the dev proxy the browser's Origin is :5173, so it
// is rewritten to the API's own origin.
const proxy = {
  target: api,
  changeOrigin: true,
  configure: (server: { on: (event: "proxyReq", handler: (req: { getHeader: (name: string) => unknown; setHeader: (name: string, value: string) => void }) => void) => void }) => {
    server.on("proxyReq", (req) => {
      if (req.getHeader("origin")) req.setHeader("origin", api);
    });
  },
};

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": proxy,
      "/health": api,
    },
  },
});
