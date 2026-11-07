import { expect, test, type Page } from "@playwright/test";

async function fixture(page: Page) {
  const state = { connected: false, created: [] as unknown[] };
  const now = "2026-11-05T12:00:00Z";
  const node = (id: string, name: string) => ({
    node_id: id,
    name,
    endpoint: `http://${id}.invalid`,
    state: "online",
    last_seen_at: now,
    configuration: { source: "yaml", apply_mode: "restart", mounts_mutable: false, grants_mutable: false },
  });
  await page.route("**/api/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    const json = (data: unknown) => route.fulfill({ contentType: "application/json", body: JSON.stringify(data) });
    if (path.endsWith("/auth/me"))
      return json({ user: { user_id: "operator", username: "operator", role: "operator", enabled: true } });
    if (path.endsWith("/auth/permissions")) {
      const { paths } = request.postDataJSON();
      return json({
        paths: Object.fromEntries(paths.map((value: string) => [value, ["list", "read", "create", "update", "delete", "execute", "sudo"]])),
      });
    }
    if (path === "/api/v1/control-tower/nodes")
      return json({ items: [node("2c6a824153853aba3e96cfd38a6b0000", "Green"), node("5bedcce4241fece38a589acdbc86fca7", "Blue")] });
    if (path.endsWith("/jobs/summary")) return json({ counts: {}, observed_at: now });
    if (path.endsWith("/jobs/events")) return route.fulfill({ contentType: "text/event-stream", body: ": heartbeat\n\n" });
    if (path.endsWith("/jobs")) return json({ items: [] });
    if (path.endsWith("/crypto/identity")) return json({ active: { fingerprint: `fp-${path.split("/")[4]}` } });
    if (request.method() === "POST" && path === "/api/v1/control-tower/connections") {
      state.created.push(request.postDataJSON());
      state.connected = true;
      return json({ status: "connected", auto_approved: true });
    }
    if (path.endsWith("/trust")) {
      const id = path.split("/")[4];
      const other = id.startsWith("2c6a") ? node("5bedcce4241fece38a589acdbc86fca7", "Blue") : node("2c6a824153853aba3e96cfd38a6b0000", "Green");
      const peers = state.connected
        ? [{ node_id: other.node_id, name: other.name, fingerprint: `fp-${other.node_id}`, state: "trusted", trust_status: "connected", grants: [] }]
        : [];
      return json({ peers, connections: [], requests: [], invites: [], can_list_grants: true });
    }
    if (path.endsWith("/crypto/mtls")) return json({ current: { not_after: "2099-01-01T00:00:00Z", state: "active" }, rollouts: {} });
    if (path.endsWith("/mounts"))
      return json({ items: [{ mount_id: "media", name: "Media", enabled: true, published: true, mode: "read_write", state: "available", readable: true, writable: true }] });
    if (path.endsWith("/files"))
      return json({ items: [{ name: "nota.txt", path: "nota.txt", type: "file", size: 7, modified_at: now }], has_more: false, next_after: "" });
    if (path.endsWith("/config/effective")) return json({ transfer_max_source_paths: 1000 });
    return json({ items: [] });
  });
  return state;
}

test("files view names the node in the header badge and tab title", async ({ page }) => {
  await fixture(page);
  await page.goto("/nodes/2c6a824153853aba3e96cfd38a6b0000/mounts/media");
  // The node, with its state dot, replaces the plain-text crumb in the header; Jolt is gone.
  const header = page.locator("header");
  await expect(header.getByTestId("node-badge")).toContainText("Green");
  await expect(header.getByRole("link", { name: "Green" })).toBeVisible();
  await expect(header).not.toContainText("Jolt");
  await expect(page.getByTestId("node-badge")).toHaveCount(1);
  await expect(page).toHaveTitle("Green / Media · Jolt");
});

test("deleting says which node and mount it will hit", async ({ page }) => {
  await fixture(page);
  await page.goto("/nodes/2c6a824153853aba3e96cfd38a6b0000/mounts/media");
  await page.getByRole("row", { name: "Ações para nota.txt" }).click({ button: "right" });
  await page.getByRole("menuitem", { name: "Remover" }).click();
  await expect(page.getByRole("alertdialog")).toContainText("Em Green / Media.");
});

test("connect dialog lists nodes by name and pairs mode with expiry", async ({ page }) => {
  await fixture(page);
  await page.goto("/relationships");
  await page.getByRole("button", { name: /Conectar/ }).first().click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Green", { exact: true }).first()).toBeVisible();
  await expect(dialog).not.toContainText("2c6a824153853aba3e96cfd38a6b0000");
  await expect(dialog).not.toContainText("5bedcce4241fece38a589acdbc86fca7");
  await expect(dialog.getByText("Dual channel", { exact: true })).toBeVisible();
  const mode = await dialog.getByText("Modo operacional").boundingBox();
  const expiry = await dialog.getByText("Expiração do convite").boundingBox();
  expect(Math.abs(mode!.y - expiry!.y)).toBeLessThan(4);
  expect(expiry!.x).toBeGreaterThan(mode!.x);
});

test("zip of the folder lives in the more-actions menu", async ({ page }) => {
  await fixture(page);
  await page.goto("/nodes/2c6a824153853aba3e96cfd38a6b0000/mounts/media");
  await expect(page.getByRole("button", { name: "Baixar pasta (.zip)" })).toHaveCount(0);
  await page.getByRole("button", { name: "Mais ações" }).click();
  await expect(page.getByRole("menuitem", { name: "Baixar pasta (.zip)" })).toBeVisible();
});

test("selection actions share the floating bar at the bottom of the page", async ({ page }) => {
  await fixture(page);
  await page.goto("/nodes/2c6a824153853aba3e96cfd38a6b0000/mounts/media");
  await expect(page.getByText("1 item selecionado")).toHaveCount(0);
  await page.getByRole("checkbox", { name: "Selecionar nota.txt" }).click();
  const bar = page.locator(".fixed", { hasText: "1 item selecionado" });
  await expect(bar.getByRole("button", { name: "Baixar .zip" })).toBeVisible();
  await expect(bar.getByRole("button", { name: "Copiar para…" })).toBeVisible();
  await expect(bar.getByRole("button", { name: "Mover para…" })).toBeVisible();
  const box = (await bar.boundingBox())!;
  const viewport = page.viewportSize()!;
  expect(box.y + box.height).toBeGreaterThan(viewport.height - 40);
  expect(Math.abs(box.x + box.width / 2 - viewport.width / 2)).toBeLessThan(4);
});

test("connect dialog stays on its step after the connection refreshes the page data", async ({ page }) => {
  const state = await fixture(page);
  await page.goto("/relationships");
  await page.getByRole("button", { name: /Conectar/ }).first().click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Finalidade").fill("Backup");
  await dialog.getByRole("button", { name: /Continuar/ }).click();
  await expect(dialog).toContainText("Passo 2 de 3");
  await dialog.getByLabel(/Digite a fingerprint/).fill("fp-2c6a824153853aba3e96cfd38a6b0000");
  await dialog.getByRole("button", { name: /Estabelecer conexão/ }).click();
  await expect.poll(() => state.created.length).toBe(1);
  // The refresh that follows marks the pair as connected; the dialog must not
  // fall back to an empty step 1.
  await expect(dialog).toContainText("Passo 3 de 3");
  await page.waitForTimeout(500);
  await expect(dialog).toContainText("Passo 3 de 3");
});
