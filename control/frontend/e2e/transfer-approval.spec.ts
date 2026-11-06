import { expect, test, type Page } from "@playwright/test";

const now = "2026-11-05T12:00:00Z";
const soon = new Date(Date.now() + 4 * 60_000).toISOString();

interface Options {
  createAnswer?: "pending" | "job";
}

async function fixture(page: Page, options: Options = {}) {
  const calls = { plans: 0, creates: [] as { body: any; key: string | undefined }[] };
  const nodes = ["a", "b"].map((id) => ({
    node_id: id,
    name: `Node ${id.toUpperCase()}`,
    endpoint: `http://${id}.invalid`,
    state: "online",
    last_seen_at: now,
    configuration: { source: "yaml", apply_mode: "restart", mounts_mutable: false, grants_mutable: false },
  }));
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
      return json({ items: [{ mount_id: "media", name: "Arquivos", enabled: true, published: true, mode: "read_write", state: "available", readable: true, writable: true }] });
    if (path.endsWith("/transfers/targets"))
      return json({
        max_source_paths: 1000,
        targets: [{
          node_id: "b", name: "Node B", state: "online", available: true,
          mounts: [{ mount_id: "media", name: "Arquivos", root_path: "dest", conflict_policies: ["fail"], can_browse: true, available: true, state: "available" }],
        }],
      });
    if (path.endsWith("/transfers/plan")) {
      calls.plans++;
      return json({
        max_source_paths: 1000,
        plan: { files_total: 12, bytes_total: 4096, copy_count: 12, conflict_count: 0, move_plan: { plan_id: "plan1", token: "token-1", expires_at: soon } },
      });
    }
    if (path.endsWith("/transfers") && request.method() === "POST") {
      calls.creates.push({ body: request.postDataJSON(), key: request.headers()["idempotency-key"] });
      if (options.createAnswer === "pending")
        return json({ pending_operation_id: "pop_7", state: "pending_approval", expires_at: soon, operation: "move", files: 12, bytes: 4096 }, 202);
      return json({ job_id: "job_9", type: "copy_remote", state: "queued" }, 202);
    }
    if (path.endsWith("/files"))
      return json({ items: [{ name: "obras", path: "obras", type: "directory", size: 4096, modified_at: now }, { name: "nota.txt", path: "nota.txt", type: "file", size: 7, modified_at: now }], has_more: false, next_after: "" });
    if (path.endsWith("/config/effective")) return json({ transfer_max_source_paths: 1000 });
    return json({ items: [] });
  });
  return calls;
}

async function openMoveDialog(page: Page) {
  await page.goto("/nodes/a/mounts/media");
  await page.getByRole("checkbox", { name: "Selecionar obras", exact: true }).check();
  await page.getByRole("button", { name: "Mover para…", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("Mover para outro node");
}

test("a transfer that needs approval tells the requester it is waiting and creates no job", async ({ page }) => {
  const calls = await fixture(page, { createAnswer: "pending" });
  await openMoveDialog(page);
  await page.getByRole("button", { name: "Gerar prévia" }).click();
  await expect(page.getByRole("dialog")).toContainText("Arquivos");
  await expect.poll(() => calls.plans).toBe(1);
  await page.getByRole("button", { name: "Confirmar transferência" }).click();
  await expect.poll(() => calls.creates.length).toBe(1);
  // The move was confirmed with the preview the requester saw, once.
  expect(calls.creates[0].body).toMatchObject({ operation: "move", move_plan: { plan_id: "plan1", token: "token-1" } });
  expect(calls.creates[0].key).toBeTruthy();
  await expect(page.getByText(/Mover 12 arquivos \(4\.0 KB\) aguardando aprovação de uma pessoa/)).toBeVisible();
  // The dialog closed and no job was announced.
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByText(/adicionada à fila/)).toHaveCount(0);
  await expect(page.getByText(/Job .* criado/)).toHaveCount(0);
});

test("a transfer that needs no approval still reports the job it created", async ({ page }) => {
  const calls = await fixture(page, { createAnswer: "job" });
  await openMoveDialog(page);
  await page.getByRole("button", { name: "Gerar prévia" }).click();
  await expect.poll(() => calls.plans).toBe(1);
  await page.getByRole("button", { name: "Confirmar transferência" }).click();
  await expect.poll(() => calls.creates.length).toBe(1);
  await expect(page.getByRole("dialog")).toContainText("Job job_9 criado");
});
