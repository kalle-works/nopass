import { expect, type Page } from "@playwright/test";

/**
 * Creates an account through the register screen, including the recovery kit
 * step that every new account has to complete, and waits for the vault.
 */
export async function registerAccount(page: Page, email: string, password: string) {
  await page.goto("/register");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Master password", { exact: true }).fill(password);
  await page.getByLabel("Confirm master password").fill(password);
  await page.getByRole("button", { name: "Create vault" }).click();

  await expect(page.getByRole("heading", { name: "Save your recovery kit" })).toBeVisible({ timeout: 30_000 });
  const continueButton = page.getByRole("button", { name: "Continue to your vault" });
  await expect(continueButton).toBeDisabled();
  await page.getByLabel("I've saved my recovery kit").check();
  await continueButton.click();
  await expect(page).toHaveURL(/\/vault/, { timeout: 30_000 });
}

/** Signs in through the login screen. The button text changes while the keys are derived. */
export async function logIn(page: Page, email: string, password: string) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Master password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
}

/** The vault list row for an item. Item names also appear in the detail pane, so match the row itself. */
export function itemRow(page: Page, name: string) {
  return page.locator("[data-item-id]").filter({ hasText: name });
}

/**
 * Opens the import page through the sidebar. A full page load would drop the
 * in-memory keys and lock the vault, so navigation has to stay client-side.
 */
export async function openImportPage(page: Page) {
  await page.getByRole("navigation", { name: "Vault" }).getByRole("link", { name: "Import" }).click();
  await expect(page).toHaveURL(/\/vault\/import/, { timeout: 10_000 });
}
