import { createHash } from "node:crypto";
import { test, expect, type Page, type Route } from "@playwright/test";

async function fixture(
  page: Page,
  options: {
    recover?: boolean;
    failCreate?: boolean;
    failTrust?: boolean;
  } = {},
) {
  const state = {
    offset: 3,
    completed: false,
    completeCalls: 0,
    createTargets: [] as string[],
    appendBodies: [] as string[],
    trustFails: !!options.failTrust,
  };
  const now = "2026-10-24T12:00:00Z";
  const nodes = ["a", "b"].map((id) => ({
    node_id: id,
    name: `Node ${id.toUpperCase()}`,
    endpoint: `http://${id}.invalid`,
    state: "online",
    last_seen_at: now,
    configuration: {
      source: "yaml",
      apply_mode: "restart",
      mounts_mutable: false,
      grants_mutable: false,
    },
  }));
  const session = () => ({
    upload_id: "pending",
    mount_id: "media",
    destination_path: "resume.txt",
    size: 7,
    offset: state.offset,
    overwrite: false,
    chunk_size: 8,
    state: state.completed ? "completed" : "open",
    created_at: now,
    updated_at: now,
    expires_at: "2099-01-01T00:00:00Z",
  });
  await page.route("**/api/**", async (route) => {
    const request = route.request(),
      url = new URL(request.url()),
      path = url.pathname;
    const json = (data: unknown, status = 200) =>
      route.fulfill({
        status,
        contentType: "application/json",
        body: JSON.stringify(data),
      });
    if (path.endsWith("/auth/me"))
      return json({
        user: {
          user_id: "operator",
          username: "operator",
          role: "operator",
          enabled: true,
        },
      });
    if (path.endsWith("/auth/permissions")) {
      const { paths } = request.postDataJSON();
      return json({
        paths: Object.fromEntries(
          paths.map((value: string) => [
            value,
            value === "nodes/b/jobs"
              ? []
              : [
                  "list",
                  "read",
                  "create",
                  "update",
                  "delete",
                  "execute",
                  "sudo",
                ],
          ]),
        ),
      });
    }
    if (path === "/api/v1/control-tower/nodes") return json({ items: nodes });
    if (path.endsWith("/jobs/summary"))
      return json({
        counts: { running: 4, queued: 7, waiting_validation: 2 },
        observed_at: now,
      });
    if (path.endsWith("/jobs/events"))
      return route.fulfill({
        contentType: "text/event-stream",
        body: ": heartbeat\n\n",
      });
    if (path.endsWith("/jobs")) return json({ items: [] });
    if (path.endsWith("/trust")) {
      if (state.trustFails)
        return json({ error: { message: "Falha de confiança simulada" } }, 503);
      return json({ peers: [], connections: [], requests: [], invites: [] });
    }
    if (path.endsWith("/crypto/mtls"))
      return json({
        current: { not_after: "2099-01-01T00:00:00Z", state: "active" },
        rollouts: {},
      });
    if (path.endsWith("/mounts"))
      return json({
        items: [
          {
            mount_id: "media",
            name: "Arquivos",
            enabled: true,
            published: true,
            mode: "read_write",
            state: "available",
            readable: true,
            writable: true,
          },
        ],
      });
    if (path.endsWith("/files/uploads")) {
      if (request.method() === "POST") {
        state.createTargets.push(path);
        if (options.failCreate)
          return json({ error: { message: "Falha de envio simulada" } }, 403);
        return json(session(), 201);
      }
      return json({
        sessions:
          options.recover && !state.completed && path.includes("/nodes/a/")
            ? [session()]
            : [],
      });
    }
    if (path.endsWith("/verification"))
      return json({
        offset: state.offset,
        next_after: 0,
        blocks: [
          {
            offset: 0,
            size: 3,
            sha256: createHash("sha256").update("pay").digest("hex"),
          },
        ],
      });
    if (path.endsWith("/complete")) {
      state.completed = true;
      state.completeCalls++;
      if (state.completeCalls === 1) return route.abort("connectionreset");
      return json(
        {
          upload_id: "pending",
          destination_path: "resume.txt",
          size: 7,
          checksum: createHash("sha256").update("payload").digest("hex"),
        },
        201,
      );
    }
    if (path.includes("/files/uploads/")) {
      if (request.method() === "PATCH") {
        state.appendBodies.push(request.postData() || "");
        state.offset = 7;
      }
      if (request.method() === "DELETE") return route.fulfill({ status: 204 });
      return json(session());
    }
    if (path.endsWith("/files")) {
      const after = Number(url.searchParams.get("after") || 0),
        limit = 200,
        total = 1005;
      const items = Array.from(
        { length: Math.min(limit, total - after) },
        (_, offset) => ({
          name: `file-${String(after + offset).padStart(4, "0")}.txt`,
          path: `file-${String(after + offset).padStart(4, "0")}.txt`,
          type: "file",
          size: 7,
          modified_at: now,
        }),
      );
      return json({
        items,
        has_more: after + limit < total,
        next_after: after + limit < total ? String(after + limit) : "",
      });
    }
    if (path.endsWith("/config/effective"))
      return json({ transfer_max_source_paths: 1000 });
    return json({ items: [] });
  });
  return state;
}

async function navigate(page: Page, path: string) {
  await page.evaluate((path) => {
    history.pushState({}, "", path);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, path);
}

test("network shows real activity and clearly marks restricted totals", async ({
  page,
}) => {
  await fixture(page);
  await page.goto("/");
  await expect(
    page.getByText("4 em execução · 7 na fila · 2 aguardando"),
  ).toBeVisible();
  await expect(page.getByText("Restrito por permissão")).toBeVisible();
  await expect(page.getByText(/Visão parcial:/)).toBeVisible();
  await expect(page.getByText(/Válido até/).first()).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: test.info().outputPath("network.png"),
    fullPage: true,
  });
});

test("large directory pages preserve selection and another section can fail independently", async ({
  page,
}) => {
  const state = await fixture(page, { failTrust: true });
  await page.goto("/nodes/a/mounts/media");
  await expect(
    page.getByRole("button", { name: "file-0000.txt", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("Confiança: Não foi possível atualizar esta seção."),
  ).toBeVisible();
  await page
    .getByRole("checkbox", { name: "Selecionar file-0000.txt", exact: true })
    .check();
  for (let i = 0; i < 5; i++)
    await page
      .getByRole("button", { name: "Carregar mais", exact: true })
      .click();
  await expect(
    page.getByRole("button", { name: "file-1004.txt", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("checkbox", {
      name: "Selecionar file-0000.txt",
      exact: true,
    }),
  ).toBeChecked();
  await expect(
    page.getByRole("button", { name: "Carregar mais", exact: true }),
  ).toHaveCount(0);
  expect(await page.getByRole("row").count()).toBe(1006);
  state.trustFails = false;
  await page
    .getByRole("button", { name: "Tentar novamente", exact: true })
    .click();
  await expect(
    page.getByText("Confiança: Não foi possível atualizar esta seção."),
  ).toHaveCount(0);
});

test("reload restores pending upload and rejects an equal-size different prefix", async ({
  page,
}) => {
  const state = await fixture(page, { recover: true });
  await page.goto("/nodes/a/mounts/media");
  await page.reload();
  const input = page.getByLabel("Selecionar arquivo para retomar resume.txt", {
    exact: true,
  });
  await expect(input).toBeAttached();
  await input.setInputFiles({
    name: "resume.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("badload"),
  });
  await expect(page.getByText(/conteúdo do arquivo é diferente/)).toBeVisible();
  expect(state.appendBodies).toEqual([]);
  await input.setInputFiles({
    name: "resume.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("payload"),
  });
  await expect(page.getByText("Concluído", { exact: true })).toBeVisible();
  expect(state.appendBodies).toEqual(["load"]);
  expect(state.completeCalls).toBe(2);
});

test("retry after navigating to another node keeps its original destination", async ({
  page,
}) => {
  const state = await fixture(page, { failCreate: true });
  await page.goto("/nodes/a/mounts/media");
  await expect(
    page.getByRole("button", { name: "file-0000.txt", exact: true }),
  ).toBeVisible();
  await page
    .locator('input[type="file"][multiple]')
    .setInputFiles({
      name: "retry.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("synthetic"),
    });
  await expect(
    page.getByRole("button", { name: "Tentar de novo", exact: true }),
  ).toBeVisible();
  await navigate(page, "/nodes/b/mounts/media");
  await expect(page).toHaveURL(/nodes\/b\/mounts\/media/);
  await page
    .getByRole("button", { name: "Tentar de novo", exact: true })
    .click();
  await expect.poll(() => state.createTargets.length).toBe(2);
  expect(state.createTargets.every((path) => path.includes("/nodes/a/"))).toBe(
    true,
  );
});

test("destination pagination recovers after failure and a trailing-slash edit", async ({ page }) => {
  await fixture(page);
  await page.route("**/api/v1/nodes/a/transfers/targets", route => route.fulfill({
    json: { max_source_paths: 1000, targets: [{
      node_id: "b", name: "Node B", state: "online", available: true,
      mounts: [{ mount_id: "media", name: "Arquivos", root_path: "dest", conflict_policies: ["fail"], can_browse: true, available: true, state: "available" }],
    }] },
  }));
  let attempts = 0;
  let pending: Route | undefined;
  const directory = (name: string) => ({ name, path: `dest/${name}`, type: "directory", size: 0 });
  await page.route(/\/api\/v1\/nodes\/b\/mounts\/media\/files(?:\?|$)/, route => {
    if (!new URL(route.request().url()).searchParams.get("after")) {
      return route.fulfill({ json: { items: [directory("first")], next_after: "more" } });
    }
    if (++attempts === 1) return route.fulfill({ status: 503, json: { error: { message: "Falha simulada" } } });
    pending = route;
  });
  await page.goto("/nodes/a/mounts/media");
  await page.getByRole("checkbox", { name: "Selecionar file-0000.txt", exact: true }).check();
  await page.getByRole("button", { name: "Copiar para…", exact: true }).click();
  const more = page.getByRole("button", { name: "Carregar mais subpastas", exact: true });
  await expect(page.getByRole("button", { name: "first", exact: true })).toBeVisible();
  await more.click();
  await expect(page.getByText("Não foi possível carregar mais subpastas.", { exact: true })).toBeVisible();
  await more.click();
  await expect.poll(() => !!pending).toBe(true);
  await page.getByRole("textbox", { name: "Pasta de destino", exact: true }).fill("dest/");
  await pending!.fulfill({ json: { items: [directory("second")], next_after: "last" } });
  await expect(page.getByRole("button", { name: "second", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "first", exact: true })).toBeVisible();
  await expect(more).toBeEnabled();
  await expect(page.getByText("Não foi possível carregar mais subpastas.", { exact: true })).toHaveCount(0);
});

test("older section retries cannot clear the latest failure", async ({ page }) => {
  await fixture(page, { failTrust: true });
  await page.goto("/nodes/a/mounts/media");
  const error = page.getByText("Confiança: Não foi possível atualizar esta seção.");
  await expect(error).toBeVisible();
  let pending: Route | undefined;
  let calls = 0;
  await page.route("**/api/v1/control-tower/nodes/a/trust", route => {
    if (++calls === 1) { pending = route; return; }
    return route.fulfill({ status: 503, json: { error: { message: "Falha mais recente" } } });
  });
  const retry = page.getByRole("button", { name: "Tentar novamente", exact: true });
  await retry.click();
  await expect.poll(() => !!pending).toBe(true);
  await retry.click();
  await expect(page.getByText("Falha mais recente", { exact: true })).toBeVisible();
  await pending!.fulfill({ json: { peers: [], connections: [], requests: [], invites: [] } });
  // The response has been delivered; let React commit any queued state writes.
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  await expect(error).toBeVisible();
});

for (const [scenario, title] of [
  ["newer data", "initial load cannot overwrite newer refresh data"],
  ["newer error", "initial load cannot clear a newer refresh error"],
  ["older error", "initial load error cannot replace a successful refresh"],
] as const) {
  test(title, async ({ page }) => {
    await fixture(page, { failTrust: true });
    let initial: Route | undefined;
    let calls = 0;
    const job = (id: string) => ({
      job_id: id, type: "copy_local", state: "completed", destination_path: `${id}.txt`,
      created_at: "2026-10-24T12:00:00Z", bytes_completed: 7, bytes_total: 7,
    });
    await page.route("**/api/v1/nodes/a/jobs", route => {
      if (++calls === 1) { initial = route; return; }
      return scenario === "newer error"
        ? route.fulfill({ status: 503, json: { error: { message: "Falha da atualização" } } })
        : route.fulfill({ json: { items: [job("fresh")] } });
    });
    // Reuse the mounted provider so the delayed request belongs to the active
    // node load, rather than StrictMode's discarded first mount.
    await page.goto("/nodes/b?tab=jobs");
    await expect(page.getByText("Confiança: Não foi possível atualizar esta seção.", { exact: true })).toBeVisible();
    await navigate(page, "/nodes/a?tab=jobs");
    await expect.poll(() => !!initial).toBe(true);
    await page.getByRole("button", { name: "Atualizar", exact: true }).click();
    const error = page.getByText("Jobs: Não foi possível atualizar esta seção.", { exact: true });
    if (scenario === "newer error") await expect(error).toBeVisible();
    else await expect(page.getByText("fresh.txt", { exact: true })).toBeVisible();

    const streaming = page.waitForRequest(request => new URL(request.url()).pathname === "/api/v1/nodes/a/jobs/events");
    await initial!.fulfill(scenario === "older error"
      ? { status: 503, json: { error: { message: "Falha inicial antiga" } } }
      : { json: { items: [job("stale")] } });
    await streaming;
    if (scenario === "newer error") await expect(error).toBeVisible();
    else {
      await expect(page.getByText("fresh.txt", { exact: true })).toBeVisible();
      await expect(error).toHaveCount(0);
    }
    await expect(page.getByText("stale.txt", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Confiança: Não foi possível atualizar esta seção.", { exact: true })).toBeVisible();
  });
}

for (const operation of ["add", "remove"] as const) {
  test(`successful node ${operation} survives an inventory refresh failure`, async ({ page }, testInfo) => {
    await fixture(page);
    await page.goto("/nodes/a");
    await expect(page.getByRole("heading", { name: "Node A", exact: true })).toBeVisible();
    let mutated = false;
    let refreshFailures = 0;
    const inventoryError = "Falha ao atualizar nodes";
    await page.route("**/api/v1/control-tower/nodes", route => {
      if (route.request().method() === "POST") {
        mutated = true;
        return route.fulfill({ status: 201, json: { node_id: "c" } });
      }
      if (refreshFailures++) return route.fallback();
      return route.fulfill({ status: 503, json: { error: { message: inventoryError } } });
    });
    if (operation === "add") {
      if (testInfo.project.name === "mobile") await page.getByRole("button", { name: "Toggle Sidebar" }).click();
      await page.getByRole("button", { name: "Adicionar node", exact: true }).click();
      await page.getByRole("textbox", { name: "Nome amigável", exact: true }).fill("Node C");
      await page.getByLabel("Token operacional", { exact: true }).fill("synthetic-token");
      await page.getByRole("button", { name: "Validar e conectar", exact: true }).click();
      await expect(page.getByText("Node conectado com sucesso.", { exact: true })).toBeVisible();
    } else {
      await page.route("**/api/v1/control-tower/nodes/a", route => {
        mutated = true;
        return route.fulfill({ status: 204 });
      });
      await page.getByRole("button", { name: "Remover node", exact: true }).click();
      await page.getByRole("textbox", { name: "Digite Node A para confirmar", exact: true }).fill("Node A");
      await page.getByRole("button", { name: "Remover da Control Tower", exact: true }).click();
      await expect(page.getByText("Node removido da Control Tower. O node e seus dados não foram alterados.", { exact: true })).toBeVisible();
    }
    expect(mutated).toBe(true);
    await expect(page.getByText(inventoryError, { exact: true })).toHaveCount(1);
  });
}
