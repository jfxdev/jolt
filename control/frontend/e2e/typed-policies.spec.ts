import { expect, test, type Page } from "@playwright/test";

const now = "2026-11-05T12:00:00Z";

async function fixture(page: Page, typedPolicies: boolean) {
  const saved: unknown[] = [];
  const policy = {
    policy_id: "policy-1",
    name: "segredos",
    description: "",
    rules: [
      {
        path: "nodes/a/files/mounts/media",
        capabilities: ["deny", "read"],
        file_types: { classes: ["secret"], extensions: ["pem"] },
        visibility: "visible",
      },
    ],
  };
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
    if (path.endsWith("/about"))
      return json({ version: "x", commit: "unknown", build_date: "unknown", features: { typed_policies: typedPolicies } });
    if (path === "/api/v1/control-tower/nodes")
      return json({ items: [{ node_id: "a", name: "Node A", endpoint: "http://a.invalid", state: "online", last_seen_at: now, configuration: { source: "yaml", apply_mode: "restart", mounts_mutable: false, grants_mutable: false } }] });
    if (path.endsWith("/jobs/summary")) return json({ counts: {}, observed_at: now });
    if (path.endsWith("/jobs/events")) return route.fulfill({ contentType: "text/event-stream", body: ": heartbeat\n\n" });
    if (path.endsWith("/mounts"))
      return json({ items: [{ mount_id: "media", name: "Arquivos", enabled: true, published: true, mode: "read_write", state: "available", readable: true, writable: true }] });
    if (path.endsWith("/policies/policy-1") && request.method() === "PATCH") {
      saved.push(request.postDataJSON());
      return json(policy);
    }
    if (path.endsWith("/policies")) return json({ items: [policy] });
    if (path.endsWith("/files"))
      return json({
        items: [
          { name: "notas.txt", path: "notas.txt", type: "file", size: 7, modified_at: now },
          { name: "chave.pem", path: "chave.pem", type: "file", size: 9, modified_at: now, blocked: true },
        ],
        has_more: false,
        next_after: "",
      });
    if (path.endsWith("/config/effective")) return json({ transfer_max_source_paths: 1000 });
    return json({ items: [] });
  });
  return saved;
}

test("editing a typed rule keeps its file types and saves them back", async ({ page }) => {
  const saved = await fixture(page, true);
  await page.goto("/access");
  await page.getByRole("button", { name: "Editar" }).click();
  const typed = page.getByTestId("typed-rule-0");
  await expect(typed.getByRole("button", { name: "Restringir por tipo de arquivo" })).toHaveAttribute("aria-pressed", "true");
  await expect(typed.getByLabel("Extensões")).toHaveValue("pem");
  await expect(typed.getByRole("checkbox", { name: /Segredo/ })).toBeChecked();
  await expect(page.getByTestId("typed-rule-summary-0")).toContainText("Nega ler o conteúdo de arquivos");
  await expect(page.getByTestId("typed-rule-summary-0")).toContainText("bloqueados");
  // A typed denial keeps the capability it takes away.
  await typed.getByLabel("Extensões").fill("pem, key, ");
  await page.getByRole("button", { name: "Salvar policy" }).click();
  await expect.poll(() => saved.length).toBe(1);
  expect(saved[0]).toMatchObject({
    rules: [
      {
        path: "nodes/a/files/mounts/media",
        capabilities: ["deny", "read"],
        file_types: { classes: ["secret"], extensions: ["pem", "key"] },
        visibility: "visible",
      },
    ],
  });
});

test("a typed rule without any type is refused before it is sent", async ({ page }) => {
  const saved = await fixture(page, true);
  await page.goto("/access");
  await page.getByRole("button", { name: "Editar" }).click();
  const typed = page.getByTestId("typed-rule-0");
  await typed.getByRole("checkbox", { name: /Segredo/ }).uncheck();
  await typed.getByLabel("Extensões").fill("");
  await expect(typed.getByRole("alert")).toContainText("ao menos uma");
  await page.getByRole("button", { name: "Salvar policy" }).click();
  expect(saved).toHaveLength(0);
});

test("typed controls are disabled when the Control Tower has typed policies off", async ({ page }) => {
  await fixture(page, false);
  await page.goto("/access");
  await page.getByRole("button", { name: "Nova policy" }).click();
  const typed = page.getByTestId("typed-rule-0");
  await expect(typed.getByRole("button", { name: "Restringir por tipo de arquivo" })).toBeDisabled();
  await expect(typed).toContainText("desativadas neste Control Tower");
});

test("a blocked entry shows a lock and cannot be opened", async ({ page }) => {
  await fixture(page, true);
  await page.goto("/nodes/a/mounts/media");
  const row = page.getByRole("row", { name: "Ações para chave.pem" });
  await expect(row).toHaveAttribute("data-blocked", "true");
  await expect(row).toContainText("Bloqueado pela política de acesso");
  await expect(row.getByRole("checkbox")).toBeDisabled();
  await expect(row.getByRole("button", { name: /chave\.pem/ })).toBeDisabled();
  await expect(page.getByRole("row", { name: "Ações para notas.txt" })).not.toHaveAttribute("data-blocked");
  await row.click({ button: "right" });
  await expect(page.getByRole("menuitem", { name: "Bloqueado pela política de acesso" })).toBeDisabled();
  await expect(page.getByRole("menuitem", { name: "Baixar" })).toHaveCount(0);
});
