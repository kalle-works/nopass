import { expect, test } from "@playwright/test";

test.describe("Share link", () => {
  test("opening a link does not consume a view until the recipient reveals it", async ({ page }) => {
    const viewRequests: string[] = [];
    page.on("request", (req) => {
      if (req.url().includes("/view")) viewRequests.push(req.url());
    });

    await page.goto("/s/00000000-0000-0000-0000-000000000000#k=irrelevant");
    await expect(page.getByRole("button", { name: "Reveal secret" })).toBeVisible();
    await page.waitForLoadState("networkidle");
    expect(viewRequests).toEqual([]);

    await page.getByRole("button", { name: "Reveal secret" }).click();
    await expect(page.getByRole("heading", { name: "This link doesn't work" })).toBeVisible();
  });
});
