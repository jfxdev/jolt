import { expect, test, type Page } from "@playwright/test";

const now = "2026-11-05T12:00:00Z";
const soon = new Date(Date.now() + 4 * 60_000).toISOString();

interface Options {
  approvals?: boolean;
  deleteAnswer?: "pending" | "job";
  pending?: unknown[];
}

async function fixture(page: Page, options: Options = {}) {
  const approvals = options.approvals ?? true;
  const calls = { saved: [] as unknown[], approved: [] as { id: string; body: unknown }[], rejected: [] as { id: string; body: unknown }[], deletes: 0 };
  let pending = options.pending ?? [];
  const policy = {
    policy_id: "policy-1",
    name: "limpeza",
    description: "",
    rules: [{ path: "nodes/a/files/mounts/media", capabilities: ["read", "delete"], needs_approval: ["delete"] }],
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
    if (path.endsWith("/about")) return json({ version: "x", commit: "unknown", build_date: "unknown", features: { typed_policies: false, approvals } });
    if (path === "/api/v1/control-tower/nodes")
      return json({ items: [{ node_id: "a", name: "Node A", endpoint: "http://a.invalid", state: "online", last_seen_at: now, configuration: { source: "yaml", apply_mode: "restart", mounts_mutable: false, grants_mutable: false } }] });
    if (path.endsWith("/jobs/summary")) return json({ counts: {}, observed_at: now });
    if (path.endsWith("/jobs/events")) return route.fulfill({ contentType: "text/event-stream", body: ": heartbeat\n\n" });
    if (path.endsWith("/jobs")) return json({ items: [] });
    if (path.endsWith("/mounts"))
      return json({ items: [{ mount_id: "media", name: "Arquivos", enabled: true, published: true, mode: "read_write", state: "available", readable: true, writable: true }] });
    if (path.endsWith("/pending-operations")) return json({ items: pending });
    if (path.endsWith("/approve")) {
      const id = path.split("/").slice(-2)[0];
      calls.approved.push({ id, body: request.postDataJSON() });
      pending = [];
      return json({ pending_operation: { ...(options.pending?.[0] as object), state: "executed" }, result: { status: 200, body: { done: true } } });
    }
    if (path.endsWith("/reject")) {
      const id = path.split("/").slice(-2)[0];
      calls.rejected.push({ id, body: request.postDataJSON() });
      pending = [];
      return json({ pending_operation_id: id, state: "rejected" });
    }
    if (path.endsWith("/policies/policy-1") && request.method() === "PATCH") {
      calls.saved.push(request.postDataJSON());
      return json(policy);
    }
    if (path.endsWith("/policies")) return json({ items: [policy] });
    if (request.method() === "DELETE" && path.endsWith("/files")) {
      calls.deletes++;
      if (options.deleteAnswer === "pending")
        return json({ pending_operation_id: "pop_1", state: "pending_approval", expires_at: soon, operation: "delete" }, 202);
      return json({ job_id: "job_1", state: "queued" }, 202);
    }
    if (path.endsWith("/files"))
      return json({ items: [{ name: "nota.txt", path: "nota.txt", type: "file", size: 7, modified_at: now }], has_more: false, next_after: "" });
    if (path.endsWith("/config/effective")) return json({ transfer_max_source_paths: 1000 });
    return json({ items: [] });
  });
  return calls;
}

const operation = (extra: Record<string, unknown> = {}) => ({
  pending_operation_id: "pop_1",
  requester_type: "user",
  requester_id: "operator",
  requester_name: "operadora",
  method: "DELETE",
  node_id: "a",
  resource: "mounts/media/files",
  summary: { operation: "delete", mount_id: "media", paths: ["docs/relatorio.txt"] },
  requirements: [],
  state: "pending",
  created_at: now,
  expires_at: soon,
  ...extra,
});

test("a rule can ask for approval and keeps the mark when it is edited and saved", async ({ page }) => {
  const calls = await fixture(page);
  await page.goto("/access");
  await page.getByRole("button", { name: "Editar" }).click();
  const fields = page.getByTestId("approval-rule-0");
  await expect(fields.getByRole("checkbox", { name: "Exigir aprovação para apagar" })).toBeChecked();
  await expect(fields.getByRole("checkbox", { name: /Exigir aprovação para alterar/ })).toHaveCount(0);
  await expect(page.getByTestId("approval-summary-0")).toContainText("Exige a aprovação de uma pessoa para apagar.");
  await page.getByRole("button", { name: "Salvar policy" }).click();
  await expect.poll(() => calls.saved.length).toBe(1);
  expect(calls.saved[0]).toMatchObject({ rules: [{ path: "nodes/a/files/mounts/media", capabilities: ["read", "delete"], needs_approval: ["delete"] }] });
});

test("removing the capability drops its approval mark", async ({ page }) => {
  const calls = await fixture(page);
  await page.goto("/access");
  await page.getByRole("button", { name: "Editar" }).click();
  await page.getByRole("checkbox", { name: "delete" }).uncheck();
  await expect(page.getByTestId("approval-rule-0")).toHaveCount(0);
  await page.getByRole("button", { name: "Salvar policy" }).click();
  await expect.poll(() => calls.saved.length).toBe(1);
  expect(JSON.stringify(calls.saved[0])).not.toContain("needs_approval");
});

test("approval controls are disabled when the Control Tower has approvals off", async ({ page }) => {
  await fixture(page, { approvals: false });
  await page.goto("/access");
  await page.getByRole("button", { name: "Nova policy" }).click();
  await page.getByRole("checkbox", { name: "delete" }).check();
  const fields = page.getByTestId("approval-rule-0");
  await expect(fields.getByRole("checkbox", { name: "Exigir aprovação para apagar" })).toBeDisabled();
  await expect(fields).toContainText("desativadas neste Control Tower");
});

test("an approver sees what is asked, approves it and the request leaves the list", async ({ page }) => {
  const calls = await fixture(page, { pending: [operation()] });
  await page.goto("/access");
  await page.getByRole("tab", { name: "Aprovações" }).click();
  const item = page.getByTestId("pending-operation");
  await expect(item).toContainText("Apagar docs/relatorio.txt no mount media");
  await expect(item).toContainText("Pedido de operadora");
  await expect(item).toContainText(/Aguardando · [34] min/);
  await item.getByRole("button", { name: "Aprovar" }).click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("docs/relatorio.txt");
  await expect(dialog).toContainText("com as suas permissões");
  await expect(dialog).not.toContainText("seu próprio pedido");
  expect(calls.approved).toHaveLength(0);
  await dialog.getByRole("button", { name: "Aprovar e executar" }).click();
  await expect.poll(() => calls.approved.length).toBe(1);
  expect(calls.approved[0]).toEqual({ id: "pop_1", body: { acknowledge_self_approval: false } });
  await expect(page.getByTestId("approvals-empty")).toBeVisible();
});

test("approving your own request asks for an explicit acknowledgement", async ({ page }) => {
  const calls = await fixture(page, { pending: [operation({ requester_id: "admin", requester_name: "admin" })] });
  await page.goto("/access");
  await page.getByRole("tab", { name: "Aprovações" }).click();
  await expect(page.getByTestId("pending-operation")).toContainText("Pedido de admin (você)");
  await page.getByRole("button", { name: "Aprovar" }).click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("você está aprovando o seu próprio pedido");
  await dialog.getByRole("button", { name: "Aprovo o meu pedido" }).click();
  await expect.poll(() => calls.approved.length).toBe(1);
  expect(calls.approved[0].body).toEqual({ acknowledge_self_approval: true });
});

test("rejecting sends the note and cancelling the dialog sends nothing", async ({ page }) => {
  const calls = await fixture(page, { pending: [operation()] });
  await page.goto("/access");
  await page.getByRole("tab", { name: "Aprovações" }).click();
  await page.getByRole("button", { name: "Aprovar" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Cancelar" }).click();
  expect(calls.approved).toHaveLength(0);
  await page.getByRole("button", { name: "Rejeitar" }).click();
  await page.getByLabel("Motivo (opcional)").fill("não é para apagar");
  await page.getByRole("button", { name: "Rejeitar", exact: true }).last().click();
  await expect.poll(() => calls.rejected.length).toBe(1);
  expect(calls.rejected[0]).toEqual({ id: "pop_1", body: { note: "não é para apagar" } });
});

test("the approvals tab says so when the feature is off", async ({ page }) => {
  await fixture(page, { approvals: false });
  await page.goto("/access");
  await page.getByRole("tab", { name: "Aprovações" }).click();
  await expect(page.getByRole("status")).toContainText("não estão habilitadas");
});

test("deleting a file that needs approval tells the requester it is waiting", async ({ page }) => {
  const calls = await fixture(page, { deleteAnswer: "pending" });
  await page.goto("/nodes/a/mounts/media");
  await page.getByRole("row", { name: "Ações para nota.txt" }).click({ button: "right" });
  await page.getByRole("menuitem", { name: "Remover" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Remover" }).click();
  await expect.poll(() => calls.deletes).toBe(1);
  await expect(page.getByText(/Apagar aguardando aprovação de uma pessoa/)).toBeVisible();
  await expect(page.getByText("Item removido.")).toHaveCount(0);
  // The file is still there: nothing was removed.
  await expect(page.getByRole("row", { name: "Ações para nota.txt" })).toBeVisible();
});

test("a delete that does not need approval keeps saying it was removed", async ({ page }) => {
  const calls = await fixture(page, { deleteAnswer: "job" });
  await page.goto("/nodes/a/mounts/media");
  await page.getByRole("row", { name: "Ações para nota.txt" }).click({ button: "right" });
  await page.getByRole("menuitem", { name: "Remover" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Remover" }).click();
  await expect.poll(() => calls.deletes).toBe(1);
  await expect(page.getByText("Item removido.")).toBeVisible();
});
