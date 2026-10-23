import { defineConfig, devices } from "@playwright/test";

// The API under test must run with NOPASS_AUTH_RATE_LIMIT_PER_MIN=1000: every
// test registers and signs in from 127.0.0.1, which exceeds the production
// auth limit (20/min) and makes registration fail with 429 at random.
// Override when another dev server (e.g. from a second checkout) holds 4020
const port = process.env.PLAYWRIGHT_PORT ?? "4020";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false, // Tests share a real server — run sequentially for isolation
  retries: 1,
  workers: 1,
  reporter: "list",
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? `http://localhost:${port}`,
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: `pnpm dev --port ${port}`,
    url: `http://localhost:${port}`,
    reuseExistingServer: !process.env.CI,
    env: {
      NEXT_PUBLIC_API_URL: process.env.E2E_API_URL ?? "http://localhost:4010",
    },
  },
});
