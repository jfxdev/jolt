import { expect, test, type Page } from "@playwright/test";

const day = 24 * 60 * 60 * 1000;
const iso = (offsetDays: number) => new Date(Date.now() + offsetDays * day).toISOString();

interface Options {
  managed?: boolean;
  canSee?: boolean;
  httpsEndsInDays?: number;
}

const FINGERPRINT = "27:40:89:D7:C6:AA:57:45:23:6E:21:A3:95:58:5B:2D:E0:0B:18:4A:BD:80:26:D6:02:00:31:98:90:AE:D5:B7";
const YAML = 'authorization_public_keys:\n  - id: ct-20261106-ea41\n    key: "zGGgO2Grljd0b+20hW01G87P+Cf+POjLUFn+rnZXO9o="\n';

async function fixture(page: Page, options: Options = {}) {
  const managed = options.managed ?? true;
  const canSee = options.canSee ?? true;
  const calls = { inventory: 0, keys: 0 };
  const item = (kind: string, subject: string, state: string, ends: number, seed: string) => ({
    kind,
    subject,
    state,
    fingerprint: seed.repeat(32).slice(0, 64),
    not_before: iso(ends - 90),
    not_after: iso(ends),
  });
  await page.route("**/api/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    const json = (data: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(data) });
    if (path.endsWith("/auth/me")) return json({ user: { user_id: "admin", username: "admin", role: "admin", enabled: true } });
    if (path.endsWith("/auth/permissions")) {
      const { paths } = request.postDataJSON();
      return json({
        paths: Object.fromEntries(
          paths.map((value: string) => [
            value,
            value === "control-tower/crypto" && !canSee ? [] : ["list", "read", "create", "update", "delete", "execute", "sudo"],
          ]),
        ),
      });
    }
    if (path.endsWith("/about")) return json({ version: "x", commit: "unknown", build_date: "unknown", features: { typed_policies: false, approvals: false, managed_tls: managed } });
    if (path.endsWith("/crypto/ca")) {
      calls.inventory++;
      return json({
        mode: "managed",
        root_fingerprint: FINGERPRINT.replace(/:/g, "").toLowerCase(),
        root_fingerprint_display: FINGERPRINT,
        bundle_version: 3,
        items: [
          item("signing_key", "ct-old", "retired", 6, "c"),
          item("https", "Control Tower", "active", options.httpsEndsInDays ?? 60, "b"),
          item("signing_key", "ct-20261106-ea41", "active", 80, "d"),
          item("root", "Jolt Root CA 1bc2f5c8", "active", 3650, "a"),
          item("intermediate", "Jolt Issuing CA 2026-11-06", "active", 700, "e"),
          item("signing_key", "ct-next", "pending", 150, "f"),
        ],
      });
    }
    if (path.endsWith("/crypto/authorization-keys")) {
      calls.keys++;
      return json({ signing_key_id: "ct-20261106-ea41", keys: [{ id: "ct-20261106-ea41", key: "zGGg", not_after: iso(80) }], node_yaml: YAML });
    }
    if (path.endsWith("/policies")) return json({ items: [] });
    if (path.endsWith("/shares")) return json({ items: [] });
    if (path === "/api/v1/control-tower/nodes") return json({ items: [] });
    return json({ items: [] });
  });
  return calls;
}

test("the inventory shows the root fingerprint and every certificate in a sensible order", async ({ page }) => {
  const calls = await fixture(page);
  await page.goto("/access");
  await page.getByRole("tab", { name: "Certificados" }).click();
  await expect(page.getByTestId("root-fingerprint")).toContainText(FINGERPRINT);
  const subjects = page.getByTestId("certificate").locator("p.break-all").first();
  await expect(subjects).toContainText("Jolt Root CA");
  await expect(page.getByTestId("certificate")).toHaveCount(6);
  const order = await page.getByTestId("certificate").evaluateAll((nodes) => nodes.map((node) => node.querySelector("strong")?.textContent));
  expect(order).toEqual(["Raiz", "Intermediária", "Certificado HTTPS", "Chave de assinatura", "Chave de assinatura", "Chave de assinatura"]);
  await expect(page.getByTestId("certificate").nth(4)).toContainText("Publicada, ainda não assina");
  await expect(page.getByTestId("certificate").nth(5)).toContainText("Em despedida");
  expect(calls.inventory).toBe(1);
  expect(calls.keys).toBe(1);
});

test("nothing is flagged while everything in use has time left", async ({ page }) => {
  await fixture(page);
  await page.goto("/access");
  await page.getByRole("tab", { name: "Certificados" }).click();
  await expect(page.getByTestId("certificate")).toHaveCount(6);
  await expect(page.getByTestId("certificate-attention")).toHaveCount(0);
  // The retired key ends in six days, as planned: it must not look like trouble.
  await expect(page.getByTestId("certificate").nth(5).locator("[data-tone]")).toHaveAttribute("data-tone", "neutral");
});

test("a certificate in use that is near its end is flagged", async ({ page }) => {
  await fixture(page, { httpsEndsInDays: 5.5 });
  await page.goto("/access");
  await page.getByRole("tab", { name: "Certificados" }).click();
  await expect(page.getByTestId("certificate-attention")).toBeVisible();
  await expect(page.getByTestId("certificate").nth(2).locator("[data-tone]")).toHaveAttribute("data-tone", "warning");
  await expect(page.getByTestId("certificate").nth(2)).toContainText("5 dias");
});

test("the root can be downloaded from the Control Tower itself", async ({ page }) => {
  await fixture(page);
  await page.goto("/access");
  await page.getByRole("tab", { name: "Certificados" }).click();
  const link = page.getByRole("link", { name: "Baixar a raiz" });
  await expect(link).toHaveAttribute("href", "/.well-known/jolt/ca.pem");
  await expect(link).toHaveAttribute("download", "jolt-root-ca.pem");
});

test("the YAML block for a node can be copied", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await fixture(page);
  await page.goto("/access");
  await page.getByRole("tab", { name: "Certificados" }).click();
  await expect(page.getByTestId("node-yaml")).toContainText("authorization_public_keys:");
  await expect(page.getByTestId("node-yaml")).toContainText("Versão do pacote de confiança: 3");
  await page.getByRole("button", { name: "Copiar bloco" }).click();
  await expect(page.getByText("Bloco copiado.")).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(YAML);
});

test("the tab says so when the Control Tower does not run its own authority", async ({ page }) => {
  const calls = await fixture(page, { managed: false });
  await page.goto("/access");
  await page.getByRole("tab", { name: "Certificados" }).click();
  await expect(page.getByRole("status")).toContainText("não estão habilitados");
  expect(calls.inventory).toBe(0);
});

test("a person without sudo on the Control Tower does not see the tab", async ({ page }) => {
  await fixture(page, { canSee: false });
  await page.goto("/access");
  await expect(page.getByRole("tab", { name: "Policies" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Certificados" })).toHaveCount(0);
});
