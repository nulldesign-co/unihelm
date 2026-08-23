import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath, URL } from "node:url";

// The build output goes straight into the Rust crate, where `rust-embed` picks
// it up at compile time — the panel ships as one binary with no static dir to
// deploy (spec §4.3).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  build: {
    outDir: "../crates/ferrum-web/ui-dist",
    emptyOutDir: true,
    // The initial route has a 350 KB gzipped budget (spec §3); warn well before
    // that so a heavy import is noticed in the PR that adds it.
    chunkSizeWarningLimit: 900,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8088", changeOrigin: true },
      "/healthz": { target: "http://127.0.0.1:8088", changeOrigin: true },
    },
  },
});
