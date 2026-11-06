import { expect, test, type Page } from "@playwright/test";

const now = "2026-11-06T12:00:00Z";

interface Options {
  trash?: boolean;
  restoreError?: { status: number; code: string };
}

async function fixture(page: Page, options: Options = {}) {
  const trash = options.trash ?? true;
  const calls = { restored: [] as string[], purged: [] as string[], deletes: 0 };
  let entries = [
    { trash_id: "tr_1_a", mount_id: "media", path: "docs/relatorio.txt", type: "file", size: 2048, state: "stored", deleted_at: now, expires_at: new Date(Date.now() + 30.5 * 86_400_000).toISOString() },
    { trash_id: "tr_2_b", mount_id: "media", path: "obras", type: "directory", state: "stored", deleted_at: now, expires_at: new Date(Date.now() + 5.5 * 3_600_000).toISOString() },
  ];
  await page.route("**/api/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
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
      return json({ items: [{ mount_id: "media", name: "Arquivos", enabled: true, published: true, mode: "read_write", state: "available", readable: true, writable: true, ...(trash ? { trash: { enabled: true, retention_days: 30 } } : {}) }] });
    if (path.endsWith("/restore")) {
      const id = path.split("/").slice(-2)[0];
      calls.restored.push(id);
      if (options.restoreError) return json({ error: { code: options.restoreError.code, message: "x" } }, options.restoreError.status);
      entries = entries.filter((entry) => entry.trash_id !== id);
      return json({ trash_id: id });
    }
    if (request.method() === "DELETE" && path.includes("/trash/")) {
      const id = path.split("/").slice(-1)[0];
      calls.purged.push(id);
      entries = entries.filter((entry) => entry.trash_id !== id);
      return json({ trash_id: id });
    }
    if (path.endsWith("/trash")) return json({ items: entries });
    if (request.method() === "DELETE" && path.endsWith("/files")) {
      calls.deletes++;
      return json({ job_id: "job_1", state: "queued" }, 202);
    }
    if (path.endsWith("/files"))
      return json({ items: [{ name: "nota.txt", path: "nota.txt", type: "file", size: 7, modified_at: now }], has_more: false, next_after: "" });
    if (path.endsWith("/config/effective")) return json({ transfer_max_source_paths: 1000 });
    return json({ items: [] });
  });
  return calls;
}

test("a mount with trash offers it and lists what was deleted, with where it was", async ({ page }) => {
  await fixture(page);
  await page.goto("/nodes/a/mounts/media");
  await page.getByRole("button", { name: "Lixeira" }).click();
  const dialog = page.getByRole("dialog", { name: "Lixeira" });
  await expect(dialog).toContainText("30 dias");
  const entries = dialog.getByTestId("trash-entry");
  await expect(entries).toHaveCount(2);
  await expect(entries.first()).toContainText("relatorio.txt");
  await expect(entries.first()).toContainText("Estava em /docs");
  await expect(entries.first()).toContainText("30 dias");
  await expect(entries.nth(1)).toContainText("pasta");
  await expect(entries.nth(1)).toContainText("5 h");
});

test("restoring puts the entry back and refreshes the list", async ({ page }) => {
  const calls = await fixture(page);
  await page.goto("/nodes/a/mounts/media");
  await page.getByRole("button", { name: "Lixeira" }).click();
  const dialog = page.getByRole("dialog", { name: "Lixeira" });
  await dialog.getByTestId("trash-entry").first().getByRole("button", { name: "Restaurar" }).click();
  await expect.poll(() => calls.restored).toEqual(["tr_1_a"]);
  await expect(dialog.getByTestId("trash-entry")).toHaveCount(1);
  await expect(page.getByText(/voltou para \/docs/)).toBeVisible();
});

test("a restore that cannot happen says why and keeps the entry", async ({ page }) => {
  const calls = await fixture(page, { restoreError: { status: 409, code: "conflict" } });
  await page.goto("/nodes/a/mounts/media");
  await page.getByRole("button", { name: "Lixeira" }).click();
  const dialog = page.getByRole("dialog", { name: "Lixeira" });
  await dialog.getByTestId("trash-entry").first().getByRole("button", { name: "Restaurar" }).click();
  await expect.poll(() => calls.restored.length).toBe(1);
  await expect(page.getByText(/Já existe algo com o nome original/)).toBeVisible();
  await expect(dialog.getByTestId("trash-entry")).toHaveCount(2);
});

test("purging asks first and removes only after the confirmation", async ({ page }) => {
  const calls = await fixture(page);
  await page.goto("/nodes/a/mounts/media");
  await page.getByRole("button", { name: "Lixeira" }).click();
  await page.getByRole("dialog", { name: "Lixeira" }).getByTestId("trash-entry").first().getByRole("button", { name: "Apagar de vez" }).click();
  const confirm = page.getByRole("alertdialog");
  await expect(confirm).toContainText("não há como recuperar");
  await confirm.getByRole("button", { name: "Cancelar" }).click();
  expect(calls.purged).toHaveLength(0);
  await page.getByRole("dialog", { name: "Lixeira" }).getByTestId("trash-entry").first().getByRole("button", { name: "Apagar de vez" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Apagar de vez" }).click();
  await expect.poll(() => calls.purged).toEqual(["tr_1_a"]);
});

test("deleting on a trash mount says it can be undone, and on a plain mount it says it cannot", async ({ page }) => {
  const calls = await fixture(page);
  await page.goto("/nodes/a/mounts/media");
  await page.getByRole("row", { name: "Ações para nota.txt" }).click({ button: "right" });
  await page.getByRole("menuitem", { name: "Remover" }).click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("Vai para a lixeira e pode ser restaurado por 30 dias");
  await dialog.getByRole("button", { name: "Remover" }).click();
  await expect.poll(() => calls.deletes).toBe(1);
  await expect(page.getByText("Item enviado para a lixeira.")).toBeVisible();
});

test("a mount without trash shows no button and warns the delete is final", async ({ page }) => {
  await fixture(page, { trash: false });
  await page.goto("/nodes/a/mounts/media");
  await expect(page.getByRole("button", { name: "Lixeira" })).toHaveCount(0);
  await page.getByRole("row", { name: "Ações para nota.txt" }).click({ button: "right" });
  await page.getByRole("menuitem", { name: "Remover" }).click();
  await expect(page.getByRole("alertdialog")).toContainText("não pode ser desfeita");
});
