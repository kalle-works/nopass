/**
 * E2E tests for 1Password .1pux import flow.
 * Requires the web app + API to be running.
 */
import { test, expect, Page } from "@playwright/test";
import { zipSync, strToU8 } from "fflate";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";

const PASSWORD = "import test password e2e";

function uniqueEmail() {
  return `e2e-import-${Date.now()}-${Math.random().toString(36).slice(2, 7)}@playwright.test`;
}

async function registerAndLogin(page: Page, email: string) {
  await page.goto("/register");
  await page.fill('input[type="email"]', email);
  await page.fill('input[type="password"]', PASSWORD);
  await page.click('button[type="submit"]');
  await expect(page).toHaveURL(/\/vault/, { timeout: 30_000 });
}

function makeOnePuxFile(items: object[]): string {
  const data = {
    accounts: [
      {
        attrs: { name: "Test", email: "test@example.com", masterKeyUuid: "abc", type: "P" },
        vaults: [
          {
            attrs: { name: "Personal", type: "P" },
            items,
          },
        ],
      },
    ],
  };
  const json = JSON.stringify(data);
  const zip = zipSync({ "export.data": strToU8(json) });
  const tmpFile = path.join(os.tmpdir(), `nopass-test-${Date.now()}.1pux`);
  fs.writeFileSync(tmpFile, Buffer.from(zip));
  return tmpFile;
}

test.describe("1Password import", () => {
  let email: string;

  test.beforeEach(async ({ page }) => {
    email = uniqueEmail();
    await registerAndLogin(page, email);
  });

  test("import button navigates to import page", async ({ page }) => {
    await page.click('button:has-text("Import")');
    await expect(page).toHaveURL(/\/vault\/import/, { timeout: 10_000 });
    await expect(page.getByText("Import from 1Password")).toBeVisible();
  });

  test("import page shows instructions", async ({ page }) => {
    await page.goto("/vault/import");
    await expect(page.getByText("File → Export → All Vaults")).toBeVisible();
    await expect(page.getByText(".1pux")).toBeVisible();
  });

  test("uploading a valid .1pux file shows preview with item counts", async ({ page }) => {
    const tmpFile = makeOnePuxFile([
      {
        uuid: "1",
        favIndex: 0,
        createdAt: 0,
        updatedAt: 0,
        trashed: "N",
        categoryUuid: "001",
        overview: { title: "My Bank", url: "https://bank.example.com" },
        details: {
          loginFields: [
            { value: "user@example.com", id: "username", name: "username", type: "T", designation: "username" },
            { value: "s3cr3t", id: "password", name: "password", type: "P", designation: "password" },
          ],
        },
      },
      {
        uuid: "2",
        favIndex: 0,
        createdAt: 0,
        updatedAt: 0,
        trashed: "N",
        categoryUuid: "003",
        overview: { title: "Wi-Fi Password" },
        details: { notesPlain: "SSID: HomeNet\nPassword: hunter2" },
      },
    ]);

    try {
      await page.goto("/vault/import");
      const fileInput = page.locator('input[type="file"]');
      await fileInput.setInputFiles(tmpFile);

      await expect(page.getByText("Ready to import")).toBeVisible({ timeout: 10_000 });
      await expect(page.getByText("2")).toBeVisible();
      await expect(page.getByText("Logins")).toBeVisible();
      await expect(page.getByText("Notes")).toBeVisible();
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });

  test("confirming import saves items to vault", async ({ page }) => {
    const tmpFile = makeOnePuxFile([
      {
        uuid: "imported-1",
        favIndex: 0,
        createdAt: 0,
        updatedAt: 0,
        trashed: "N",
        categoryUuid: "001",
        overview: { title: "Imported Login", url: "https://example.com" },
        details: {
          loginFields: [
            { value: "importeduser", id: "username", name: "username", type: "T", designation: "username" },
            { value: "importedpass", id: "password", name: "password", type: "P", designation: "password" },
          ],
        },
      },
    ]);

    try {
      await page.goto("/vault/import");
      const fileInput = page.locator('input[type="file"]');
      await fileInput.setInputFiles(tmpFile);

      await expect(page.getByText("Ready to import")).toBeVisible({ timeout: 10_000 });
      await page.click('button:has-text("Import 1 items")');

      await expect(page.getByText("Import complete")).toBeVisible({ timeout: 30_000 });
      await expect(page.getByText("1 items imported")).toBeVisible();

      await page.click('button:has-text("Go to vault")');
      await expect(page).toHaveURL(/\/vault/, { timeout: 10_000 });
      await expect(page.getByText("Imported Login")).toBeVisible({ timeout: 10_000 });
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });

  test("trashed items are skipped during import", async ({ page }) => {
    const tmpFile = makeOnePuxFile([
      {
        uuid: "active-1",
        favIndex: 0,
        createdAt: 0,
        updatedAt: 0,
        trashed: "N",
        categoryUuid: "001",
        overview: { title: "Active Item" },
        details: { loginFields: [] },
      },
      {
        uuid: "trashed-1",
        favIndex: 0,
        createdAt: 0,
        updatedAt: 0,
        trashed: "Y",
        categoryUuid: "001",
        overview: { title: "Deleted Item" },
        details: { loginFields: [] },
      },
    ]);

    try {
      await page.goto("/vault/import");
      const fileInput = page.locator('input[type="file"]');
      await fileInput.setInputFiles(tmpFile);

      await expect(page.getByText("Ready to import")).toBeVisible({ timeout: 10_000 });
      // Shows 1 item (trashed one skipped), with a "trashed items skipped" note
      await expect(page.getByText("1")).toBeVisible();
      await expect(page.getByText(/trashed.*skipped/i)).toBeVisible();
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });

  test("cancel returns to file selection", async ({ page }) => {
    const tmpFile = makeOnePuxFile([
      {
        uuid: "1",
        favIndex: 0,
        createdAt: 0,
        updatedAt: 0,
        trashed: "N",
        categoryUuid: "001",
        overview: { title: "Test" },
        details: { loginFields: [] },
      },
    ]);

    try {
      await page.goto("/vault/import");
      const fileInput = page.locator('input[type="file"]');
      await fileInput.setInputFiles(tmpFile);

      await expect(page.getByText("Ready to import")).toBeVisible({ timeout: 10_000 });
      await page.click('button:has-text("Cancel")');

      await expect(page.getByText("Drop your .1pux file here")).toBeVisible({ timeout: 5_000 });
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });
});
