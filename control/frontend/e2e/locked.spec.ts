import { expect, test, type Page } from "@playwright/test";

const now = "2026-11-06T12:00:00Z";

// A node whose only mount is locked: it lists names, sizes and dates, and the
// node answers 403 mount_locked to anything that reads or writes content.
async function fixture(page: Page, locked = true) {
  const calls = { content: 0, listed: [] as string[] };
  await page.route("**/api/**", async (route) => {
    const request = route.request(),
      url = new URL(request.url()),
      path = url.pathname;
    const json = (data: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(data) });
    if (path.endsWith("/auth/me"))
      return json({ user: { user_id: "admin", username: "admin", role: "admin", enabled: true } });
    if (path.endsWith("/auth/permissions")) {
      const { paths } = request.postDataJSON();
      return json({ paths: Object.fromEntries(paths.map((value: string) => [value, ["list", "read", "create", "update", "delete", "execute", "sudo"]])) });
    }
    if (path.endsWith("/about")) return json({ version: "x", commit: "unknown", build_date: "unknown", features: {} });
    if (path === "/api/v1/control-tower/nodes")
      return json({ items: [{ node_id: "a", name: "Node A", endpoint: "http://a.invalid", state: "online", last_seen_at: now, configuration: { source: "yaml", apply_mode: "restart", mounts_mutable: false, grants_mutable: false } }] });
    if (path.endsWith("/jobs/summary")) return json({ counts: {}, observed_at: now });
    if (path.endsWith("/jobs/events")) return route.fulfill({ contentType: "text/event-stream", body: ": heartbeat\n\n" });
    if (path.endsWith("/jobs")) return json({ items: [] });
    if (path.endsWith("/mounts"))
      return json({ items: [{ mount_id: "media", name: "Arquivos", enabled: true, published: true, mode: "read_write", state: "available", readable: true, writable: true, ...(locked ? { locked: true } : {}) }] });
    if (path.endsWith("/files/content")) {
      calls.content++;
      return json({ error: { code: "mount_locked", message: "locked" } }, 403);
    }
    if (path.endsWith("/files")) {
      calls.listed.push(url.searchParams.get("path") ?? "");
      return json({
        items: [
          { name: "docs", path: "docs", type: "directory", size: 0, modified_at: now },
          { name: "nota.txt", path: "nota.txt", type: "file", size: 7, modified_at: now },
        ],
        has_more: false,
        next_after: "",
      });
    }
    if (path.endsWith("/config/effective")) return json({ transfer_max_source_paths: 1000 });
    return json({ items: [] });
  });
  return calls;
}

test("a locked mount still lists names and sizes, and says what it is", async ({ page }) => {
  await fixture(page);
  await page.goto("/nodes/a/mounts/media");
  await expect(page.getByRole("row", { name: "Ações para nota.txt" })).toContainText("7 B");
  await expect(page.getByRole("row", { name: "Ações para docs" })).toBeVisible();
  // Metadata views stay available.
  await expect(page.getByRole("button", { name: "Exibir uso de disco" })).toBeVisible();
});

test("a locked mount offers no way to read content or move files", async ({ page }) => {
  const calls = await fixture(page);
  await page.goto("/nodes/a/mounts/media");
  await expect(page.getByRole("row", { name: "Ações para nota.txt" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Enviar arquivos" })).toHaveCount(0);
  await expect(page.getByPlaceholder("Nova pasta")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Mais ações" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Lixeira" })).toHaveCount(0);
  await expect(page.getByRole("checkbox", { name: "Selecionar nota.txt" })).toBeDisabled();

  await page.getByRole("row", { name: "Ações para nota.txt" }).click({ button: "right" });
  await expect(page.getByRole("menuitem", { name: /Mount bloqueado/ })).toBeDisabled();
  for (const name of ["Baixar", "Ver", "Editar", "Criar link público…", "Copiar para…", "Mover para…", "Remover"]) {
    await expect(page.getByRole("menuitem", { name })).toHaveCount(0);
  }
  await page.keyboard.press("Escape");

  const row = page.getByRole("row", { name: "Ações para nota.txt" });
  await expect(row.getByRole("button", { name: "nota.txt" })).toBeDisabled();
  await row.dblclick();
  expect(calls.content).toBe(0);
});

test("a folder on a locked mount still opens, because browsing reads only metadata", async ({ page }) => {
  const calls = await fixture(page);
  await page.goto("/nodes/a/mounts/media");
  await page.getByRole("row", { name: "Ações para docs" }).click({ button: "right" });
  await expect(page.getByRole("menuitem", { name: "Abrir" })).toBeVisible();
  await page.getByRole("menuitem", { name: "Abrir" }).click();
  await expect.poll(() => calls.listed).toContain("docs");
});

test("a regular mount keeps every action", async ({ page }) => {
  await fixture(page, false);
  await page.goto("/nodes/a/mounts/media");
  await expect(page.getByRole("button", { name: "Enviar arquivos" })).toBeVisible();
  await page.getByRole("row", { name: "Ações para nota.txt" }).click({ button: "right" });
  for (const name of ["Baixar", "Remover"]) {
    await expect(page.getByRole("menuitem", { name })).toBeVisible();
  }
});

test("the mount card says the mount shows metadata only", async ({ page }) => {
  await fixture(page);
  await page.goto("/nodes/a");
  await expect(page.getByText("Somente metadados")).toBeVisible();
});
