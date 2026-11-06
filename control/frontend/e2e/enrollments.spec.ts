import { expect, test, type Page } from "@playwright/test";

const minute = 60 * 1000;
const iso = (offsetMinutes: number) => new Date(Date.now() + offsetMinutes * minute).toISOString();
const FINGERPRINT = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12";
const TOKEN = "jolt-join:v1:" + "s".repeat(43) + ":" + "0a".repeat(32) + ":https://control.lan:8090";

interface Options {
  canEnroll?: boolean;
}

async function fixture(page: Page, options: Options = {}) {
  const canEnroll = options.canEnroll ?? true;
  const calls = { created: [] as unknown[], approved: [] as string[], rejected: [] as { id: string; body: unknown }[], revoked: [] as string[] };
  let tokens: Record<string, unknown>[] = [
    { token_id: "jt_used", node_name: "antigo", approval: "auto", created_by: "admin", created_at: iso(-600), expires_at: iso(-585), used_at: iso(-598), enrollment_id: "enr_old" },
    { token_id: "jt_open", node_name: "aguardando", approval: "manual", created_by: "admin", created_at: iso(-2), expires_at: iso(13) },
  ];
  let pending: Record<string, unknown>[] = [
    { enrollment_id: "enr_1", token_id: "jt_x", state: "pending", node_name: "beta", node_id: "node-beta", node_fingerprint: FINGERPRINT, api_endpoint: "https://beta.lan:8080", remote_addr: "10.0.0.7", created_at: iso(-1), expires_at: iso(14) },
  ];
  await page.route("**/api/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    const json = (data: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(data) });
    if (path.endsWith("/auth/me")) return json({ user: { user_id: "admin", username: "admin", role: "admin", enabled: true } });
    if (path.endsWith("/auth/permissions")) {
      const { paths } = request.postDataJSON();
      return json({ paths: Object.fromEntries(paths.map((value: string) => [value, value === "control-tower/enrollments" && !canEnroll ? [] : ["list", "read", "create", "update", "delete", "execute", "sudo"]])) });
    }
    if (path.endsWith("/about")) return json({ version: "x", commit: "unknown", build_date: "unknown", features: { typed_policies: false, approvals: false, managed_tls: true } });
    if (path.endsWith("/crypto/ca"))
      return json({ mode: "managed", root_fingerprint: "ab".repeat(32), root_fingerprint_display: "AB:AB", bundle_version: 1, items: [] });
    if (path.endsWith("/crypto/authorization-keys")) return json({ signing_key_id: "k", keys: [], node_yaml: "authorization_public_keys:\n" });
    if (path.endsWith("/enrollments/tokens") && request.method() === "POST") {
      const body = request.postDataJSON();
      calls.created.push(body);
      tokens = [{ token_id: "jt_new", node_name: body.node_name, approval: body.approval, created_by: "admin", created_at: iso(0), expires_at: iso(body.valid_minutes) }, ...tokens];
      return json({ token_id: "jt_new", token: TOKEN, node_name: body.node_name, approval: body.approval, expires_at: iso(body.valid_minutes), control_url: "https://control.lan:8090" }, 201);
    }
    if (path.endsWith("/enrollments/tokens")) return json({ items: tokens });
    if (path.includes("/enrollments/tokens/") && request.method() === "DELETE") {
      const id = path.split("/").pop()!;
      calls.revoked.push(id);
      tokens = tokens.filter((token) => token.token_id !== id);
      return route.fulfill({ status: 204 });
    }
    if (path.endsWith("/approve")) {
      const id = path.split("/").slice(-2)[0];
      calls.approved.push(id);
      pending = [];
      return json({ enrollment_id: id, state: "issued" });
    }
    if (path.endsWith("/reject")) {
      const id = path.split("/").slice(-2)[0];
      calls.rejected.push({ id, body: request.postDataJSON() });
      pending = [];
      return json({ enrollment_id: id, state: "rejected" });
    }
    if (path.endsWith("/enrollments")) return json({ items: new URL(request.url()).searchParams.get("state") === "pending" ? pending : pending });
    if (path.endsWith("/policies") || path.endsWith("/shares")) return json({ items: [] });
    return json({ items: [] });
  });
  return calls;
}

async function open(page: Page) {
  await page.goto("/access");
  await page.getByRole("tab", { name: "Certificados" }).click();
  await expect(page.getByTestId("enrollments")).toBeVisible();
}

test("a token is made once, shown once, and then only its status remains", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const calls = await fixture(page);
  await open(page);
  await page.getByLabel("Nome do node").fill("nas-sala");
  await page.getByLabel("Aprovação").selectOption("manual");
  await page.getByLabel("Validade (min)").fill("30");
  await page.getByRole("button", { name: "Criar token" }).click();
  await expect.poll(() => calls.created.length).toBe(1);
  expect(calls.created[0]).toEqual({ node_name: "nas-sala", approval: "manual", valid_minutes: 30 });
  const shown = page.getByTestId("created-token");
  await expect(shown).toContainText("nas-sala");
  await expect(page.getByTestId("token-value")).toContainText("JOLT_JOIN_TOKEN=" + TOKEN);
  await expect(shown).toContainText("tls_mode: managed");
  await shown.getByRole("button", { name: "Copiar token" }).click();
  await expect(page.getByText("Token copiado.")).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("JOLT_JOIN_TOKEN=" + TOKEN);
  await shown.getByRole("button", { name: "Já copiei" }).click();
  await expect(page.getByTestId("created-token")).toHaveCount(0);
  // The list shows the token as a status, never as a secret.
  await expect(page.getByTestId("join-token").first()).toContainText("nas-sala");
  await expect(page.getByTestId("join-token").first()).toContainText("Aguardando o node");
  await expect(page.locator("body")).not.toContainText("s".repeat(43));
});

test("the name is required before a token can be made", async ({ page }) => {
  const calls = await fixture(page);
  await open(page);
  await expect(page.getByRole("button", { name: "Criar token" })).toBeDisabled();
  await page.getByLabel("Nome do node").fill("   ");
  await expect(page.getByRole("button", { name: "Criar token" })).toBeDisabled();
  expect(calls.created).toHaveLength(0);
});

test("a pending node shows its fingerprint and is approved only after the person confirms", async ({ page }) => {
  const calls = await fixture(page);
  await open(page);
  const item = page.getByTestId("pending-enrollment");
  await expect(item).toContainText("beta");
  await expect(item).toContainText("https://beta.lan:8080");
  await expect(page.getByTestId("enrollment-fingerprint")).toHaveText("AB:12:CD:34:EF:56:AB:12:CD:34:EF:56:AB:12:CD:34:EF:56:AB:12:CD:34:EF:56:AB:12:CD:34:EF:56:AB:12");
  await item.getByRole("button", { name: "Aprovar" }).click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("AB:12:CD:34");
  await expect(dialog).toContainText("log de inicialização");
  expect(calls.approved).toHaveLength(0);
  await dialog.getByRole("button", { name: "Cancelar" }).click();
  expect(calls.approved).toHaveLength(0);
  await item.getByRole("button", { name: "Aprovar" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "O fingerprint confere, aprovar" }).click();
  await expect.poll(() => calls.approved).toEqual(["enr_1"]);
  await expect(page.getByTestId("no-pending-enrollments")).toBeVisible();
});

test("rejecting sends the reason", async ({ page }) => {
  const calls = await fixture(page);
  await open(page);
  await page.getByTestId("pending-enrollment").getByRole("button", { name: "Rejeitar" }).click();
  await page.getByLabel("Motivo (opcional)").fill("host desconhecido");
  await page.getByRole("button", { name: "Rejeitar", exact: true }).last().click();
  await expect.poll(() => calls.rejected.length).toBe(1);
  expect(calls.rejected[0]).toEqual({ id: "enr_1", body: { note: "host desconhecido" } });
});

test("a token that was not used can be taken back and a spent one cannot", async ({ page }) => {
  const calls = await fixture(page);
  await open(page);
  const spent = page.getByTestId("join-token").filter({ hasText: "antigo" });
  await expect(spent).toContainText("Usado");
  await expect(spent.getByRole("button", { name: "Revogar" })).toHaveCount(0);
  const open_ = page.getByTestId("join-token").filter({ hasText: "aguardando" });
  await expect(open_).toContainText("Aguardando o node");
  await open_.getByRole("button", { name: "Revogar" }).click();
  await expect.poll(() => calls.revoked).toEqual(["jt_open"]);
  await expect(page.getByTestId("join-token").filter({ hasText: "aguardando" })).toHaveCount(0);
});

test("without sudo on enrollments the certificates stay visible and the enrollment section does not", async ({ page }) => {
  await fixture(page, { canEnroll: false });
  await page.goto("/access");
  await page.getByRole("tab", { name: "Certificados" }).click();
  await expect(page.getByTestId("root-fingerprint")).toBeVisible();
  await expect(page.getByTestId("enrollments")).toHaveCount(0);
});
