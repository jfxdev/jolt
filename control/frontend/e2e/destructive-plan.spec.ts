import { expect, test, type Page } from "@playwright/test";

type Mode = "plan" | "unavailable" | "changed";

async function fixture(page: Page, mode: Mode) {
  const calls = { plans: [] as unknown[], confirms: [] as { path: string; key: string | null; body: unknown }[], direct: [] as string[] };
  const now = "2026-11-05T12:00:00Z";
  await page.route("**/api/**", async (route) => {
    const request = route.request(),
      url = new URL(request.url()),
      path = url.pathname;
    const json = (data: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(data) });
    if (path.endsWith("/auth/me"))
      return json({ user: { user_id: "operator", username: "operator", role: "operator", enabled: true } });
    if (path.endsWith("/auth/permissions")) {
      const { paths } = request.postDataJSON();
      return json({
        paths: Object.fromEntries(paths.map((value: string) => [value, ["list", "read", "create", "update", "delete", "execute"]])),
      });
    }
    if (path === "/api/v1/control-tower/nodes")
      return json({
        items: [{ node_id: "a", name: "Node A", endpoint: "http://a.invalid", state: "online", last_seen_at: now, configuration: { source: "yaml", apply_mode: "restart", mounts_mutable: false, grants_mutable: false } }],
      });
    if (path.endsWith("/jobs/summary")) return json({ counts: {}, observed_at: now });
    if (path.endsWith("/jobs/events")) return route.fulfill({ contentType: "text/event-stream", body: ": heartbeat\n\n" });
    if (path.endsWith("/jobs")) return json({ items: [] });
    if (path.endsWith("/trust")) return json({ peers: [], connections: [], requests: [], invites: [] });
    if (path.endsWith("/crypto/mtls")) return json({ current: { not_after: "2099-01-01T00:00:00Z", state: "active" }, rollouts: {} });
    if (path.endsWith("/mounts"))
      return json({ items: [{ mount_id: "media", name: "Arquivos", enabled: true, published: true, mode: "read_write", state: "available", readable: true, writable: true }] });
    if (path.endsWith("/files/destructive-plans")) {
      calls.plans.push(request.postDataJSON());
      if (mode === "unavailable") return json({ error: { code: "resource_not_found", message: "Recurso do node não permitido." } }, 404);
      return json({ plan_id: "plan_1", token: "one-use-token", expires_at: "2026-11-05T12:05:00Z", operation: "delete", mount_id: "media", source_path: "pasta", files: 2, directories: 3, bytes: 2048 }, 201);
    }
    if (path.endsWith("/destructive-plans/plan_1/confirm")) {
      calls.confirms.push({ path, key: request.headers()["idempotency-key"] ?? null, body: request.postDataJSON() });
      if (mode === "changed") return json({ error: { code: "tree_changed", message: "A pasta mudou depois do plano." } }, 409);
      return json({ job_id: "job_1", state: "waiting_validation" }, 202);
    }
    if (request.method() === "DELETE" && path.endsWith("/files")) {
      calls.direct.push(`${url.searchParams.get("path")}?recursive=${url.searchParams.get("recursive")}`);
      return json({ job_id: "job_2", state: "queued" }, 202);
    }
    if (path.endsWith("/files"))
      return json({
        items: [
          { name: "pasta", path: "pasta", type: "directory", size: 4096, modified_at: now },
          { name: "nota.txt", path: "nota.txt", type: "file", size: 7, modified_at: now },
        ],
        has_more: false,
        next_after: "",
      });
    if (path.endsWith("/config/effective")) return json({ transfer_max_source_paths: 1000 });
    return json({ items: [] });
  });
  return calls;
}

async function openRemove(page: Page, name: string) {
  await page.goto("/nodes/a/mounts/media");
  await page.getByRole("row", { name: `Ações para ${name}` }).click({ button: "right" });
  await page.getByRole("menuitem", { name: "Remover" }).click();
}

test("removing a folder shows what will be lost and confirms with the plan token", async ({ page }) => {
  const calls = await fixture(page, "plan");
  await openRemove(page, "pasta");
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("Remover a pasta “pasta”?");
  await expect(dialog).toContainText("2 arquivos em 3 pastas (2.0 KB)");
  await expect(dialog).toContainText("removidos permanentemente");
  // Planning alone changes nothing.
  expect(calls.confirms).toHaveLength(0);
  expect(calls.direct).toHaveLength(0);
  await dialog.getByRole("button", { name: "Remover pasta" }).click();
  await expect.poll(() => calls.confirms.length).toBe(1);
  expect(calls.plans).toEqual([{ operation: "delete", source_path: "pasta" }]);
  expect(calls.confirms[0].body).toEqual({ token: "one-use-token" });
  expect(calls.confirms[0].key).toMatch(/[0-9a-f-]{36}/);
  expect(calls.direct).toHaveLength(0);
});

test("cancelling the confirmation never sends the token", async ({ page }) => {
  const calls = await fixture(page, "plan");
  await openRemove(page, "pasta");
  await page.getByRole("alertdialog").getByRole("button", { name: "Cancelar" }).click();
  await expect(page.getByRole("alertdialog")).toBeHidden();
  expect(calls.plans).toHaveLength(1);
  expect(calls.confirms).toHaveLength(0);
});

test("a tree that changed after the plan reports the refusal", async ({ page }) => {
  const calls = await fixture(page, "changed");
  await openRemove(page, "pasta");
  await page.getByRole("alertdialog").getByRole("button", { name: "Remover pasta" }).click();
  await expect(page.getByText("A pasta mudou depois do plano.")).toBeVisible();
  expect(calls.confirms).toHaveLength(1);
});

test("without plans on the server the direct route and a plain confirmation apply", async ({ page }) => {
  const calls = await fixture(page, "unavailable");
  await openRemove(page, "pasta");
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("Remover “pasta”?");
  await dialog.getByRole("button", { name: "Remover" }).click();
  await expect.poll(() => calls.direct.length).toBe(1);
  expect(calls.direct[0]).toBe("pasta?recursive=true");
  expect(calls.confirms).toHaveLength(0);
});

test("files keep the direct route and never ask for a plan", async ({ page }) => {
  const calls = await fixture(page, "plan");
  await openRemove(page, "nota.txt");
  await page.getByRole("alertdialog").getByRole("button", { name: "Remover" }).click();
  await expect.poll(() => calls.direct.length).toBe(1);
  expect(calls.direct[0]).toBe("nota.txt?recursive=false");
  expect(calls.plans).toHaveLength(0);
});
