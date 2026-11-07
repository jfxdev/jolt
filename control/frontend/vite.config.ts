import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

const api = "http://127.0.0.1:8090";

// The API only accepts a state-changing request whose Origin host equals the
// Host it received. Through the dev proxy the browser's Origin is :5173, so a
// request from the Vite origin gets its Origin rewritten to the API's own.
const proxy = {
  target: api,
  changeOrigin: true,
  configure: (server: { on: (event: "proxyReq", handler: (req: { getHeader: (name: string) => unknown; setHeader: (name: string, value: string) => void }) => void) => void }) => {
    server.on("proxyReq", (req) => {
      if (req.getHeader("origin")) req.setHeader("origin", api);
    });
  },
};

// Rewriting every Origin would let any page the developer visits make
// state-changing calls to the local API through the proxy. Only requests whose
// Origin matches the Host Vite received (any port) are forwarded.
const sameOriginOnly = (): Plugin => ({
  name: "dev-proxy-same-origin",
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      const origin = req.headers.origin;
      if (origin && (req.url?.startsWith("/api") || req.url?.startsWith("/health"))) {
        let host = "";
        try {
          host = new URL(origin).host;
        } catch {
          // An unparsable Origin never matches.
        }
        if (host !== req.headers.host) {
          res.statusCode = 403;
          res.end("Cross-origin request rejected by the dev proxy");
          return;
        }
      }
      next();
    });
  },
});

export default defineConfig({
  plugins: [react(), tailwindcss(), sameOriginOnly()],
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
