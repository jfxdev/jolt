import { createHash } from "node:crypto";
import { test, expect, type Page } from "@playwright/test";

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
