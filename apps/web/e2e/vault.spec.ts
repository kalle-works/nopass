/**
 * E2E tests for vault CRUD operations.
 * Requires the web app + API to be running.
 */
import { test, expect, Page } from "@playwright/test";

const PASSWORD = "vault test password e2e";

// Each test gets a unique email so re-registration doesn't conflict
function uniqueEmail() {
  return `e2e-vault-${Date.now()}-${Math.random().toString(36).slice(2, 7)}@playwright.test`;
}

async function registerAndLogin(page: Page, email: string) {
  await page.goto("/register");
  await page.fill('input[type="email"]', email);
  await page.fill('input[type="password"]', PASSWORD);
  await page.click('button[type="submit"]');
  await expect(page).toHaveURL(/\/vault/, { timeout: 30_000 });
}

async function openNewItemModal(page: Page, type: "Login" | "Note" | "Card" | "Identity" = "Login") {
  await page.click('[data-testid="new-item-btn"]');
  await expect(page.locator('[data-testid="type-picker"]')).toBeVisible({ timeout: 5_000 });
  await page.click(`[data-testid="type-${type.toLowerCase()}"]`);
  await expect(page.locator('input[placeholder="Name"]')).toBeVisible({ timeout: 5_000 });
}

test.describe("Vault CRUD", () => {
  let email: string;

  test.beforeEach(async ({ page }) => {
    email = uniqueEmail();
    await registerAndLogin(page, email);
  });

  test("create a login item → appears in the list", async ({ page }) => {
    await openNewItemModal(page, "Login");

    await page.fill('input[placeholder="Name"]', "GitHub");
    await page.fill('input[placeholder="Username or email"]', "alice");
    await page.fill('input[type="password"]', "super-secret-pass");

    await page.click('button[type="submit"]');

    await expect(page.locator("text=GitHub")).toBeVisible({ timeout: 10_000 });
  });

  test("edit an existing item → updated name visible", async ({ page }) => {
    await openNewItemModal(page, "Login");

    await page.fill('input[placeholder="Name"]', "Twitter");
    await page.fill('input[placeholder="Username or email"]', "alice");
    await page.fill('input[type="password"]', "pass123");
    await page.click('button[type="submit"]');
    await expect(page.locator("text=Twitter")).toBeVisible({ timeout: 10_000 });

    await page.click('button:has-text("Edit")');

    const nameField = page.locator('input[placeholder="Name"]');
    await nameField.fill("");
    await nameField.fill("X (Twitter)");
    await page.click('button[type="submit"]');

    await expect(page.getByText("X (Twitter)", { exact: true })).toBeVisible({ timeout: 10_000 });
    // Use exact match: "Twitter" must not appear as a standalone item name
    await expect(page.getByText("Twitter", { exact: true })).not.toBeVisible({ timeout: 5_000 });
  });

  test("delete an item → no longer in list", async ({ page }) => {
    await openNewItemModal(page, "Login");

    await page.fill('input[placeholder="Name"]', "ToDelete");
    await page.fill('input[placeholder="Username or email"]', "user");
    await page.fill('input[type="password"]', "pw");
    await page.click('button[type="submit"]');
    await expect(page.locator("text=ToDelete")).toBeVisible({ timeout: 10_000 });

    await page.click('button:has-text("Delete")');

    const confirmBtn = page.locator('button:has-text("Confirm"), button:has-text("Yes")');
    if (await confirmBtn.isVisible({ timeout: 1_000 })) await confirmBtn.click();

    await expect(page.locator("text=ToDelete")).not.toBeVisible({ timeout: 10_000 });
  });

  test("search filters items by name", async ({ page }) => {
    for (const name of ["GitHub", "GitLab"]) {
      await openNewItemModal(page, "Login");
      await page.fill('input[placeholder="Name"]', name);
      await page.fill('input[placeholder="Username or email"]', "alice");
      await page.fill('input[type="password"]', "pw");
      await page.click('button[type="submit"]');
      await expect(page.locator(`text=${name}`)).toBeVisible({ timeout: 10_000 });
    }

    await page.fill('input[type="search"]', "GitHub");
    await expect(page.locator("text=GitHub")).toBeVisible();
    await expect(page.locator("text=GitLab")).not.toBeVisible();
  });

  test("lock button redirects to login", async ({ page }) => {
    await page.click('button:has-text("Lock")');
    await expect(page).toHaveURL(/\/login/);
  });

  test("new login item has a pre-generated password", async ({ page }) => {
    await openNewItemModal(page, "Login");
    // Password field should already have a value (pre-generated, hidden)
    const passwordField = page.locator('input[type="password"]');
    await expect(passwordField).not.toHaveValue("");
    // Strength bar should be visible (green)
    await expect(page.locator(".bg-green-500, .bg-blue-500")).toBeVisible({ timeout: 3_000 });
  });

  test("save shows toast notification", async ({ page }) => {
    await openNewItemModal(page, "Login");
    await page.fill('input[placeholder="Name"]', "ToastTest");
    await page.click('button[type="submit"]');
    await expect(page.locator("text=Item saved")).toBeVisible({ timeout: 10_000 });
  });

  test("quick-copy password button appears on list item hover", async ({ page }) => {
    await openNewItemModal(page, "Login");
    await page.fill('input[placeholder="Name"]', "HoverTest");
    await page.fill('input[placeholder="Username or email"]', "alice@example.com");
    await page.fill('input[type="password"]', "mysecret123");
    await page.click('button[type="submit"]');
    await expect(page.locator("text=HoverTest")).toBeVisible({ timeout: 10_000 });

    // Hover over the item row to reveal quick-copy buttons
    const itemRow = page.locator("text=HoverTest").first();
    await itemRow.hover();
    // Copy password button should become visible
    await expect(page.locator('button[title*="Copy password"]')).toBeVisible({ timeout: 3_000 });
  });

  test("keyboard shortcut C copies password of selected login item", async ({ page }) => {
    await openNewItemModal(page, "Login");
    await page.fill('input[placeholder="Name"]', "KeyTest");
    await page.fill('input[placeholder="Username or email"]', "keyuser");
    await page.fill('input[type="password"]', "keypw123");
    await page.click('button[type="submit"]');
    await expect(page.locator("text=KeyTest")).toBeVisible({ timeout: 10_000 });

    // Click item to select it (opens detail pane)
    await page.click("text=KeyTest");
    await expect(page.locator('aside:has-text("KeyTest")')).toBeVisible({ timeout: 5_000 });

    // Press C to copy password — toast should appear
    await page.keyboard.press("c");
    await expect(page.locator("text=Password copied")).toBeVisible({ timeout: 3_000 });
  });
});
