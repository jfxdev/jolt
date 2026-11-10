import { expect, test, type Page } from "@playwright/test";

const now = "2026-11-05T12:00:00Z";

// Two receive grants on one destination mount: each root is its own destination.
async function fixture(page: Page) {
  const plans: any[] = [];
  const nodes = ["a", "b"].map((id) => ({
    node_id: id,
    name: `Node ${id.toUpperCase()}`,
    endpoint: `http://${id}.invalid`,
    state: "online",
    last_seen_at: now,
    configuration: { source: "yaml", apply_mode: "restart", mounts_mutable: false, grants_mutable: false },
  }));
  const root = (root_path: string) => ({
    mount_id: "media", name: "Media", root_path, conflict_policies: ["fail"], can_browse: true, available: true, state: "available",
  });
  await page.route("**/api/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    const json = (data: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(data) });
    if (path.endsWith("/auth/me"))
      return json({ user: { user_id: "operator", username: "operator", role: "operator", enabled: true } });
    if (path.endsWith("/auth/permissions")) {
      const { paths } = request.postDataJSON();
      return json({ paths: Object.fromEntries(paths.map((value: string) => [value, ["list", "read", "create", "update", "delete", "execute", "sudo"]])) });
    }
    if (path.endsWith("/about")) return json({ version: "x", commit: "unknown", build_date: "unknown", features: { typed_policies: false, approvals: true } });
    if (path === "/api/v1/control-tower/nodes") return json({ items: nodes });
    if (path.endsWith("/jobs/summary")) return json({ counts: {}, observed_at: now });
    if (path.endsWith("/jobs/events")) return route.fulfill({ contentType: "text/event-stream", body: ": heartbeat\n\n" });
    if (path.endsWith("/jobs")) return json({ items: [] });
    if (path.endsWith("/trust")) return json({ peers: [], connections: [], requests: [], invites: [] });
    if (path.endsWith("/mounts"))
      return json({ items: [{ mount_id: "media", name: "Media", enabled: true, published: true, mode: "read_write", state: "available", readable: true, writable: true }] });
    if (path.endsWith("/transfers/targets"))
      return json({
        max_source_paths: 1000,
        targets: [{ node_id: "b", name: "Node B", state: "online", available: true, mounts: [root("shows"), root("movies")] }],
      });
    if (path.endsWith("/transfers/plan")) {
      plans.push(request.postDataJSON());
      return json({ max_source_paths: 1000, plan: { files_total: 1, bytes_total: 7, copy_count: 1, conflict_count: 0 } });
    }
    if (path.endsWith("/files"))
      return json({ items: [{ name: "nota.txt", path: "nota.txt", type: "file", size: 7, modified_at: now }], has_more: false, next_after: "" });
    if (path.endsWith("/config/effective")) return json({ transfer_max_source_paths: 1000 });
    return json({ items: [] });
  });
  return plans;
}

test("every receive root of one destination mount can be chosen", async ({ page }) => {
  const plans = await fixture(page);
  await page.goto("/nodes/a/mounts/media");
  await page.getByRole("checkbox", { name: "Selecionar nota.txt", exact: true }).check();
  await page.getByRole("button", { name: "Copiar para…", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("Copiar para outro node");
  const destination = dialog.getByLabel("Pasta de destino");
  await expect(destination).toHaveValue("shows");

  await dialog.getByRole("combobox").filter({ hasText: "Media · /shows" }).click();
  await expect(page.getByRole("option", { name: /Media · \/shows/ })).toBeVisible();
  await page.getByRole("option", { name: /Media · \/movies/ }).click();
  await expect(dialog.getByRole("combobox").filter({ hasText: "Media · /movies" })).toBeVisible();
  await expect(destination).toHaveValue("movies");

  await destination.fill("movies/2026");
  await expect(dialog).not.toContainText("Informe uma pasta relativa");
  await dialog.getByRole("button", { name: "Gerar prévia" }).click();
  await expect.poll(() => plans.length).toBe(1);
  expect(plans[0]).toMatchObject({ destination: { mount_id: "media", path: "movies/2026" } });
});
