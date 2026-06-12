import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  define: {
    // Injected at build time so the background script knows the API endpoint.
    // Override in production: VITE_API_BASE=https://api.nopass.app pnpm build
    __API_BASE__: JSON.stringify(process.env["VITE_API_BASE"] ?? "http://localhost:3001"),
  },
  build: {
    outDir: "dist",
    rollupOptions: {
      input: {
        popup: resolve(__dirname, "src/popup/index.html"),
        background: resolve(__dirname, "src/background/index.ts"),
        content: resolve(__dirname, "src/content/index.ts"),
        "webauthn-inject": resolve(__dirname, "src/webauthn/inject.ts"),
      },
      output: {
        entryFileNames: "[name].js",
        chunkFileNames: "[name].js",
        assetFileNames: "[name].[ext]",
      },
    },
  },
});
