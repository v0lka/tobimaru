import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Vite config for the Tobimaru SPA. The build output is written into the Go
// embed directory (../internal/api/web/dist) so a `make build` after
// `make web` produces a single binary with the dashboard included.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: {
    outDir: path.resolve(__dirname, "../internal/api/web/dist"),
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        entryFileNames: "assets/[name]-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8080",
        changeOrigin: false,
        secure: false,
      },
    },
  },
});
