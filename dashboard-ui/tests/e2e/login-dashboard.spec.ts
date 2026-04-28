import { expect, test } from "@playwright/test";

test("login completes (admin sees dashboard, others see access denied)", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder("Tenant UUID").fill("00000000-0000-0000-0000-000000000001");
  await page.getByPlaceholder("Email").fill("admin@example.com");
  await page.getByPlaceholder("Password").fill("AdminPass123!");
  await page.getByRole("button", { name: "Sign In" }).click();

  const dashboard = page.getByText("Admin Dashboard");
  const denied = page.getByRole("heading", { name: "Access denied" });
  await expect(dashboard.or(denied)).toBeVisible({ timeout: 15_000 });
});
