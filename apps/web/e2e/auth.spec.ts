/**
 * E2E tests for authentication flow.
 * Requires the nopass web app running on PLAYWRIGHT_BASE_URL (default: http://localhost:4020)
 * and the API running on http://localhost:4010.
 */
import { test, expect } from "@playwright/test";

const PASSWORD = "correct horse battery staple e2e";

function uniqueEmail(label = "auth") {
  return `e2e-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}@playwright.test`;
}

test.describe("Authentication", () => {
  test("register → redirects to vault", async ({ page }) => {
    const email = uniqueEmail("register");
    await page.goto("/register");
    await page.fill('input[type="email"]', email);
    await page.fill('input[type="password"]', PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/\/vault/, { timeout: 30_000 });
  });

  test("login with registered credentials → accesses vault", async ({ page }) => {
    const email = uniqueEmail("login");

    // Register
    await page.goto("/register");
    await page.fill('input[type="email"]', email);
    await page.fill('input[type="password"]', PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/\/vault/, { timeout: 30_000 });

    // Navigate to login (clears session)
    await page.goto("/login");
    await page.fill('input[type="email"]', email);
    await page.fill('input[type="password"]', PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/\/vault/, { timeout: 30_000 });
  });

  test("wrong password shows error", async ({ page }) => {
    const email = uniqueEmail("wrong-pw");

    await page.goto("/register");
    await page.fill('input[type="email"]', email);
    await page.fill('input[type="password"]', PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/\/vault/, { timeout: 30_000 });

    await page.goto("/login");
    await page.fill('input[type="email"]', email);
    await page.fill('input[type="password"]', "wrong password");
    await page.click('button[type="submit"]');

    await expect(page).toHaveURL(/\/login/);
    await expect(
      page.locator("text=authentication failed").or(page.locator("p[class*='red']")),
    ).toBeVisible({ timeout: 15_000 });
  });

  test("visiting /vault when locked redirects to /login", async ({ page }) => {
    await page.goto("/vault");
    await expect(page).toHaveURL(/\/login/);
  });
});
