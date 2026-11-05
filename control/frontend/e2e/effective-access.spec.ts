import { expect, test, type Page } from "@playwright/test";

const now = "2026-11-05T12:00:00Z";
const cell = (outcome: string, allowed = outcome === "allowed", ids: string[] = []) => ({ allowed, denied: !allowed && outcome !== "denied", outcome, policy_ids: ids, typed: ids.length > 0 });

async function fixture(page: Page) {
  const asked: { path: string; body: unknown }[] = [];
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
    if (path.endsWith("/about")) return json({ version: "x", commit: "unknown", build_date: "unknown", features: { typed_policies: true } });
    if (path === "/api/v1/control-tower/nodes")
      return json({ items: [{ node_id: "a", name: "Node A", endpoint: "http://a.invalid", state: "online", last_seen_at: now, configuration: { source: "yaml", apply_mode: "restart", mounts_mutable: false, grants_mutable: false } }] });
    if (path.endsWith("/jobs/summary")) return json({ counts: {}, observed_at: now });
    if (path.endsWith("/jobs/events")) return route.fulfill({ contentType: "text/event-stream", body: ": heartbeat\n\n" });
    if (path.endsWith("/mounts"))
      return json({ items: [{ mount_id: "media", name: "Arquivos", enabled: true, published: true, mode: "read_write", state: "available", readable: true, writable: true }] });
    if (path.endsWith("/users"))
      return json({ items: [{ user_id: "op", username: "operadora", role: "operator", enabled: true }] });
    if (path.endsWith("/service-accounts")) return json({ items: [] });
    if (path.endsWith("/policies"))
      return json({ items: [{ policy_id: "typed", name: "sem-chaves", description: "", rules: [] }] });
    if (path.endsWith("/effective-access")) {
      asked.push({ path, body: request.postDataJSON() });
      const capabilities = Object.fromEntries(
        ["read", "list", "create", "update", "delete", "write", "execute", "sudo"].map((name) => [name, cell("denied")]),
      );
      return json({
        subject: { actor_type: "user", id: "op", name: "operadora", role: "operator", enabled: true },
        typed_policies: true,
        notes: ["Políticas por tipo estão desativadas neste Control Tower: exemplo de aviso."],
        results: [
          { path: "nodes/a/files/mounts/media", entry_type: "directory", capabilities: { ...capabilities, read: cell("allowed", true, ["typed"]) } },
          { path: "nodes/a/files/mounts/media/chave.pem", entry_type: "file", capabilities: { ...capabilities, read: cell("blocked", false, ["typed"]), list: cell("hidden", false, ["typed"]) } },
          { path: "nodes/b/files/mounts/media/x", entry_type: "file", reason: "node_not_in_group", capabilities },
        ],
      });
    }
    return json({ items: [] });
  });
  return asked;
}

test("the effective access tab asks for each path with its entry type and explains the answer", async ({ page }) => {
  const asked = await fixture(page);
  await page.goto("/access");
  await page.getByRole("tab", { name: "Acesso efetivo" }).click();
  await expect(page.getByLabel("Caminho 1")).toHaveValue("nodes/a/files/mounts/media");
  await page.getByLabel("Identidade").selectOption({ label: "operadora · usuário (operator)" });
  await page.getByRole("button", { name: "Adicionar caminho" }).click();
  await page.getByLabel("Caminho 2").fill("nodes/a/files/mounts/media/chave.pem");
  await page.getByLabel("Tipo da entrada 2").selectOption("file");
  await page.getByRole("button", { name: "Consultar" }).click();

  await expect.poll(() => asked.length).toBe(1);
  expect(asked[0].path).toContain("/subjects/user/op/effective-access");
  expect(asked[0].body).toEqual({
    checks: [
      { path: "nodes/a/files/mounts/media", entry_type: "directory" },
      { path: "nodes/a/files/mounts/media/chave.pem", entry_type: "file" },
    ],
  });

  const result = page.getByTestId("effective-result");
  await expect(result).toContainText("Acesso efetivo de operadora");
  await expect(result.getByRole("status")).toContainText("exemplo de aviso");
  const pem = result.getByRole("row", { name: /chave\.pem/ });
  await expect(pem.locator('[data-outcome="blocked"]')).toHaveCount(1);
  await expect(pem.locator('[data-outcome="hidden"]')).toHaveCount(1);
  // The policy is named, not shown as an id, and the cell says what happened.
  await expect(pem.locator('[data-outcome="blocked"]')).toHaveAttribute("title", /Bloqueado\..*403.*por tipo.*sem-chaves/);
  await expect(pem.locator('[data-outcome="blocked"]')).toContainText("Bloqueado");
  await expect(result.getByRole("row", { name: /media\s*pasta/ }).locator('[data-outcome="allowed"]')).toHaveCount(1);
  await expect(result).toContainText("não pertence a nenhum grupo de acesso");
});

test("the query needs an identity", async ({ page }) => {
  const asked = await fixture(page);
  await page.goto("/access");
  await page.getByRole("tab", { name: "Acesso efetivo" }).click();
  await expect(page.getByRole("button", { name: "Consultar" })).toBeDisabled();
  expect(asked).toHaveLength(0);
});
