import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "happy-dom",
    globals: true,
    testTimeout: 30_000,
    // e2e specs need a built extension + live API — run via `pnpm test:e2e`
    exclude: ["**/node_modules/**", "e2e/**"],
  },
});
