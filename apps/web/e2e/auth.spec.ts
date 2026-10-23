/**
 * E2E tests for authentication flow.
 * Requires the nopass web app running on PLAYWRIGHT_BASE_URL (default: http://localhost:4020)
 * and the API running on http://localhost:4010.
 */
import { test, expect } from "@playwright/test";
import { logIn, registerAccount } from "./helpers";

const PASSWORD = "correct horse battery staple e2e";

function uniqueEmail(label = "auth") {
  return `e2e-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}@playwright.test`;
}

test.describe("Authentication", () => {
  test("register → redirects to vault", async ({ page }) => {
    const email = uniqueEmail("register");
    await registerAccount(page, email, PASSWORD);
  });

  test("login with registered credentials → accesses vault", async ({ page }) => {
    const email = uniqueEmail("login");

    // Register
    await registerAccount(page, email, PASSWORD);

    // Navigate to login (clears session)
    await logIn(page, email, PASSWORD);
    await expect(page).toHaveURL(/\/vault/, { timeout: 30_000 });
  });

  test("wrong password shows error", async ({ page }) => {
    const email = uniqueEmail("wrong-pw");

    await registerAccount(page, email, PASSWORD);

    await logIn(page, email, "wrong password");

    await expect(page).toHaveURL(/\/login/);
    await expect(page.locator('form [role="alert"]')).toBeVisible({ timeout: 15_000 });
  });

  test("visiting /vault when locked redirects to /login", async ({ page }) => {
    await page.goto("/vault");
    await expect(page).toHaveURL(/\/login/);
  });
});
