/**
 * E2E tests for vault CRUD operations.
 * Requires the web app + API to be running.
 */
import { test, expect, Page } from "@playwright/test";
import { itemRow, registerAccount } from "./helpers";

const PASSWORD = "vault test password e2e";

// Each test gets a unique email so re-registration doesn't conflict
function uniqueEmail() {
  return `e2e-vault-${Date.now()}-${Math.random().toString(36).slice(2, 7)}@playwright.test`;
}

async function registerAndLogin(page: Page, email: string) {
  await registerAccount(page, email, PASSWORD);
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

    await expect(itemRow(page, "GitHub")).toBeVisible({ timeout: 10_000 });
  });

  test("edit an existing item → updated name visible", async ({ page }) => {
    await openNewItemModal(page, "Login");

    await page.fill('input[placeholder="Name"]', "Twitter");
    await page.fill('input[placeholder="Username or email"]', "alice");
    await page.fill('input[type="password"]', "pass123");
    await page.click('button[type="submit"]');
    await expect(itemRow(page, "Twitter")).toBeVisible({ timeout: 10_000 });

    await page.click('button:has-text("Edit")');

    const nameField = page.locator('input[placeholder="Name"]');
    await nameField.fill("");
    await nameField.fill("X (Twitter)");
    await page.click('button[type="submit"]');

    await expect(itemRow(page, "X (Twitter)")).toBeVisible({ timeout: 10_000 });
    // Use exact match: "Twitter" must not appear as a standalone item name
    await expect(page.getByText("Twitter", { exact: true })).not.toBeVisible({ timeout: 5_000 });
  });

  test("delete an item → no longer in list", async ({ page }) => {
    await openNewItemModal(page, "Login");

    await page.fill('input[placeholder="Name"]', "ToDelete");
    await page.fill('input[placeholder="Username or email"]', "user");
    await page.fill('input[type="password"]', "pw");
    await page.click('button[type="submit"]');
    await expect(itemRow(page, "ToDelete")).toBeVisible({ timeout: 10_000 });

    await page.getByRole("complementary", { name: "Item details" }).getByRole("button", { name: "Delete", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Delete item" }).click();

    await expect(itemRow(page, "ToDelete")).not.toBeVisible({ timeout: 10_000 });
  });

  test("search filters items by name", async ({ page }) => {
    for (const name of ["GitHub", "GitLab"]) {
      await openNewItemModal(page, "Login");
      await page.fill('input[placeholder="Name"]', name);
      await page.fill('input[placeholder="Username or email"]', "alice");
      await page.fill('input[type="password"]', "pw");
      await page.click('button[type="submit"]');
      await expect(itemRow(page, name)).toBeVisible({ timeout: 10_000 });
    }

    await page.fill('input[type="search"]', "GitHub");
    await expect(itemRow(page, "GitHub")).toBeVisible();
    await expect(itemRow(page, "GitLab")).not.toBeVisible();
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
    // Strength meter should be visible
    await expect(page.getByText(/to guess/)).toBeVisible({ timeout: 3_000 });
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
    await expect(itemRow(page, "HoverTest")).toBeVisible({ timeout: 10_000 });

    // Hover over the item row to reveal quick-copy buttons
    await itemRow(page, "HoverTest").hover();
    // Copy password button should become visible
    await expect(itemRow(page, "HoverTest").getByRole("button", { name: "Copy password" })).toBeVisible({ timeout: 3_000 });
  });

  test("keyboard shortcut C copies password of selected login item", async ({ page, context }) => {
    // Headless Chromium blocks clipboard writes without an explicit grant; a real keypress counts as a user gesture.
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await openNewItemModal(page, "Login");
    await page.fill('input[placeholder="Name"]', "KeyTest");
    await page.fill('input[placeholder="Username or email"]', "keyuser");
    await page.fill('input[type="password"]', "keypw123");
    await page.click('button[type="submit"]');
    await expect(itemRow(page, "KeyTest")).toBeVisible({ timeout: 10_000 });

    // Click item to select it (opens detail pane)
    await itemRow(page, "KeyTest").click();
    await expect(page.locator('aside:has-text("KeyTest")')).toBeVisible({ timeout: 5_000 });

    // Press C to copy password — toast should appear
    await page.keyboard.press("c");
    await expect(page.locator("text=Password copied")).toBeVisible({ timeout: 3_000 });
  });
});
