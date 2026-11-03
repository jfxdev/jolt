import { expect, test } from "@playwright/test";

test("public share labels are safe while navigation retains canonical paths", async ({ page }) => {
  const directory = "pastas\u202eocultas";
  const file = "relatório\u001b.txt";
  const paths: string[] = [];
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const json = (value: unknown) => route.fulfill({ contentType: "application/json", body: JSON.stringify(value) });
    if (url.pathname.endsWith("/auth/me")) return route.fulfill({ status: 401, body: "{}" });
    if (url.pathname === "/api/v1/public/shares/test") {
      return json({ share: { name: "compartilhado\u202e", kind: "directory", unlocked: true, allow_archive: true } });
    }
    if (url.pathname.endsWith("/list")) {
      const path = url.searchParams.get("path") || "";
      paths.push(path);
      return json({ items: path === "" ? [
        { name: directory, path: directory, type: "directory" },
        { name: file, path: file, type: "file" },
      ] : [] });
    }
    return json({ items: [] });
  });
  await page.goto("/s/test");
  await expect(page.getByText("compartilhado⟦U+202E⟧", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("relatório⟦U+001B⟧.txt")).toBeVisible();
  const download = page.getByRole("link", { name: "Baixar relatório⟦U+001B⟧.txt" });
  const href = await download.getAttribute("href");
  expect(new URL(href!, "http://localhost").searchParams.get("path")).toBe(file);
  await page.getByRole("button", { name: "pastas⟦U+202E⟧ocultas" }).click();
  await expect.poll(() => paths.at(-1)).toBe(directory);
  await expect(page.getByRole("button", { name: "pastas⟦U+202E⟧ocultas" })).toBeVisible();
});
