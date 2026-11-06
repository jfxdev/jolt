import { expect, test, type Page } from "@playwright/test";

const day = 24 * 60 * 60 * 1000;
const iso = (offsetDays: number) => new Date(Date.now() + offsetDays * day).toISOString();
const FINGERPRINT = "27:40:89:D7:C6:AA:57:45:23:6E:21:A3:95:58:5B:2D:E0:0B:18:4A:BD:80:26:D6:02:00:31:98:90:AE:D5:B7";
const NEXT = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";

interface State {
  phase: "none" | "prepared" | "promoted";
  nodes: Record<string, unknown>[];
  revocations: Record<string, unknown>[];
  /** Makes the first promotion answer that a node has not confirmed the bundle. */
  nodesBehind: boolean;
  posts: { path: string; body: unknown }[];
}

const node = (extra: Record<string, unknown> = {}) => ({
  node_id: "n1",
  name: "alpha",
  bundle_version: 4,
  bundle_behind: 0,
  cert_serial: "aa01",
  cert_not_after: iso(60),
  auth_mode: "certificate",
  ...extra,
});

async function fixture(page: Page, initial: Partial<State> = {}) {
  const state: State = { phase: "none", nodes: [node()], revocations: [], nodesBehind: false, posts: [], ...initial };
  await page.route("**/api/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    const json = (data: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(data) });
    if (path.endsWith("/auth/me")) return json({ user: { user_id: "admin", username: "admin", role: "admin", enabled: true } });
    if (path.endsWith("/auth/permissions")) {
      const { paths } = request.postDataJSON();
      return json({ paths: Object.fromEntries(paths.map((value: string) => [value, ["list", "read", "create", "update", "delete", "execute", "sudo"]])) });
    }
    if (path.endsWith("/about")) return json({ version: "x", commit: "unknown", build_date: "unknown", features: { typed_policies: false, approvals: false, managed_tls: true } });
    if (path.endsWith("/crypto/ca")) {
      return json({
        mode: "managed",
        root_fingerprint: FINGERPRINT.replace(/:/g, "").toLowerCase(),
        root_fingerprint_display: FINGERPRINT,
        bundle_version: 5,
        items: [],
        rotation: { phase: state.phase, ...(state.phase === "prepared" ? { next_root_fingerprint: "ab" } : {}) },
        ...(state.phase === "prepared" ? { next_root_fingerprint_display: NEXT } : {}),
        nodes: state.nodes,
      });
    }
    if (path.endsWith("/crypto/authorization-keys")) return json({ signing_key_id: "k", keys: [], node_yaml: "authorization_public_keys:\n" });
    if (path.endsWith("/crypto/revocations") && request.method() === "GET") return json({ items: state.revocations });
    if (request.method() === "POST" && path.includes("/crypto/")) {
      const body = request.postDataJSON?.() ?? null;
      state.posts.push({ path: path.replace("/api/v1/control-tower/crypto/", ""), body });
      if (path.endsWith("/crypto/revocations")) {
        state.revocations = [{ serial: "aa01", subject: "node n1", reason: body.reason, revoked_at: iso(0), not_after: iso(60) }];
        return json({ serial: "aa01", bundle_version: 6 });
      }
      if (path.endsWith("/root/rotate")) {
        state.phase = "prepared";
        return json({ rotation: { phase: "prepared" }, bundle_version: 6 }, 202);
      }
      if (path.endsWith("/root/promote")) {
        if (state.nodesBehind && !body.force) {
          return json({ error: { code: "nodes_behind", message: "Estes nodes ainda não confirmaram o pacote com a raiz nova: beta." } }, 409);
        }
        state.phase = "promoted";
        return json({ rotation: { phase: "promoted" }, bundle_version: 7 });
      }
      return json({ bundle_version: 8 });
    }
    return json({ items: [] });
  });
  return state;
}

async function open(page: Page) {
  await page.goto("/access");
  await page.getByRole("tab", { name: "Certificados" }).click();
}

test("each enrolled node shows how it authenticates and what is wrong with it", async ({ page }) => {
  await fixture(page, {
    nodes: [
      node(),
      node({ node_id: "n2", name: "beta", auth_mode: "token", bundle_behind: 2 }),
      node({ node_id: "n3", name: "gamma", auth_mode: "token", last_error: "send the trust bundle: node unavailable" }),
    ],
  });
  await open(page);
  const rows = page.getByTestId("managed-node");
  await expect(rows).toHaveCount(3);
  await expect(rows.nth(0)).toContainText("Certificado");
  await expect(rows.nth(0).locator("[data-tone]")).toHaveAttribute("data-tone", "ok");
  await expect(rows.nth(1)).toContainText("Token compartilhado");
  await expect(rows.nth(1)).toContainText("Pacote atrasado em 2 versões");
  await expect(rows.nth(2).locator("[data-tone]")).toHaveAttribute("data-tone", "critical");
  await expect(page.getByTestId("nodes-on-token")).toContainText("2 nodes ainda aceitam o token compartilhado");
  await expect(page.getByTestId("nodes-on-token")).toContainText("managed-only");
});

test("no hint about the token appears once every node uses the certificate", async ({ page }) => {
  await fixture(page);
  await open(page);
  await expect(page.getByTestId("managed-node")).toHaveCount(1);
  await expect(page.getByTestId("nodes-on-token")).toHaveCount(0);
});

test("revoking a node asks why, sends the node and lists it as revoked", async ({ page }) => {
  const state = await fixture(page);
  await open(page);
  await page.getByTestId("managed-node").getByRole("button", { name: "Revogar certificado" }).click();
  await expect(page.getByText("precisa ser enrolado de novo")).toBeVisible();
  await page.getByLabel("Motivo (opcional)").fill("disco roubado");
  await page.getByRole("button", { name: "Revogar", exact: true }).last().click();
  await expect(page.getByText("Certificado revogado.")).toBeVisible();
  expect(state.posts).toEqual([{ path: "revocations", body: { node_id: "n1", reason: "disco roubado" } }]);
  await expect(page.getByTestId("revocation")).toContainText("node n1");
  await expect(page.getByTestId("revocation")).toContainText("disco roubado");
});

test("cancelling the revocation sends nothing", async ({ page }) => {
  const state = await fixture(page);
  await open(page);
  await page.getByTestId("managed-node").getByRole("button", { name: "Revogar certificado" }).click();
  await page.getByRole("button", { name: "Cancelar" }).click();
  expect(state.posts).toEqual([]);
  await expect(page.getByTestId("revocation")).toHaveCount(0);
});

test("a root rotation is begun, shows the next fingerprint, and is promoted", async ({ page }) => {
  const state = await fixture(page);
  await open(page);
  await expect(page.getByRole("button", { name: "Promover a raiz nova" })).toHaveCount(0);
  await page.getByRole("button", { name: "Começar a troca da raiz" }).click();
  await page.getByRole("button", { name: "Começar a troca", exact: true }).click();
  await expect(page.getByTestId("root-rotation")).toContainText("Raiz nova publicada");
  await expect(page.getByTestId("next-root-fingerprint")).toContainText(NEXT);
  await expect(page.getByRole("button", { name: "Começar a troca da raiz" })).toHaveCount(0);
  await page.getByRole("button", { name: "Promover a raiz nova" }).click();
  await expect(page.getByText("Raiz nova em uso.")).toBeVisible();
  await expect(page.getByTestId("root-rotation")).toContainText("A raiz antiga sai do pacote sozinha");
  expect(state.posts.map((post) => post.path)).toEqual(["ca/root/rotate", "ca/root/promote"]);
  expect(state.posts[1].body).toEqual({ force: false });
});

test("promoting with a node behind explains it and only forces after a second confirmation", async ({ page }) => {
  const state = await fixture(page, { phase: "prepared", nodesBehind: true });
  await open(page);
  await page.getByRole("button", { name: "Promover a raiz nova" }).click();
  await expect(page.getByText("Estes nodes ainda não confirmaram o pacote com a raiz nova: beta.")).toBeVisible();
  await page.getByRole("button", { name: "Cancelar" }).click();
  expect(state.posts.map((post) => post.body)).toEqual([{ force: false }]);
  await expect(page.getByTestId("root-rotation")).toContainText("Raiz nova publicada");

  await page.getByRole("button", { name: "Promover a raiz nova" }).click();
  await page.getByRole("button", { name: "Promover mesmo assim" }).click();
  await expect(page.getByTestId("root-rotation")).toContainText("Raiz nova em uso");
  expect(state.posts.map((post) => post.body)).toEqual([{ force: false }, { force: false }, { force: true }]);
});

test("rotating the intermediate asks first, and revoking says what it costs", async ({ page }) => {
  const state = await fixture(page);
  await open(page);
  await page.getByRole("button", { name: "Girar a intermediária" }).click();
  await expect(page.getByText("nada precisa ser reemitido")).toBeVisible();
  await page.getByRole("button", { name: "Girar", exact: true }).click();
  await expect(page.getByText("Intermediária nova em uso.")).toBeVisible();

  await page.getByRole("button", { name: "Girar e revogar (chave vazada)" }).click();
  await expect(page.getByText("sai do pacote na hora")).toBeVisible();
  await page.getByRole("button", { name: "Girar e revogar", exact: true }).click();
  await expect(page.getByText("Intermediária nova em uso.").last()).toBeVisible();
  expect(state.posts.map((post) => (post.body as { revoke_previous: boolean }).revoke_previous)).toEqual([false, true]);
});

test("declining the intermediate rotation changes nothing", async ({ page }) => {
  const state = await fixture(page);
  await open(page);
  await page.getByRole("button", { name: "Girar e revogar (chave vazada)" }).click();
  await page.getByRole("button", { name: "Cancelar" }).click();
  expect(state.posts).toEqual([]);
});

test("without any node the panel says so and the page does not scroll sideways", async ({ page }) => {
  await fixture(page, { nodes: [] });
  await open(page);
  await expect(page.getByText("Nenhum node usa a autoridade ainda.")).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});
