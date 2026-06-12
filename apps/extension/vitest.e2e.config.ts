import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["e2e/**/*.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
    // Browser + seeded account are shared state — run specs sequentially
    fileParallelism: false,
  },
});
