import { expect, test } from "@playwright/test";

test("create an agent with explicit limits and stop all agents", async ({ page }) => {
  let created: Record<string, unknown> | undefined;
  let updated: Record<string, unknown> | undefined;
  let disableCalls = 0;
  let temporaryGrant: Record<string, unknown> | undefined;
  let temporaryRevokes = 0;
  let workload: Record<string, unknown> | undefined;
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const json = (value: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(value) });
    if (path.endsWith("/auth/me")) return json({ user: { user_id: "admin", username: "admin", role: "admin", enabled: true } });
    if (path.endsWith("/auth/permissions")) {
      const { paths } = request.postDataJSON();
      return json({ paths: Object.fromEntries(paths.map((value: string) => [value, ["sudo", "list", "read", "create", "update", "delete"]])) });
    }
    if (path.endsWith("/service-accounts/disable")) { disableCalls++; return json({ disabled: 1 }); }
    if (path.endsWith("/workload-identities/wid-1") && request.method() === "PATCH") { workload = { ...workload, ...request.postDataJSON() }; return route.fulfill({ status: 204 }); }
    if (path.endsWith("/workload-identities") && request.method() === "POST") { workload = { ...request.postDataJSON(), credential_id: "wid-1", service_account_id: "agent-1", enabled: true, revoked: false, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" }; return json(workload, 201); }
    if (path.endsWith("/workload-identities")) return json({ items: workload ? [workload] : [] });
    if (path.endsWith("/policies/temporary/policy-1") && request.method() === "DELETE") { temporaryRevokes++; return route.fulfill({ status: 204 }); }
    if (path.endsWith("/policies/temporary") && request.method() === "POST") { temporaryGrant = request.postDataJSON(); return json({ policy_id: "policy-1", created_by: "admin", created_at: "2026-01-01T00:00:00Z", expires_at: "2099-01-01T00:15:00Z" }, 201); }
    if (path.endsWith("/policies/temporary")) return json({ items: [] });
    if (path.endsWith("/service-accounts/agent-1/tokens/key-1") && request.method() === "PATCH") { updated = request.postDataJSON(); return route.fulfill({ status: 204 }); }
    if (path.endsWith("/service-accounts/agent-1/tokens")) return json({ items: [] });
    if (path.endsWith("/service-accounts") && request.method() === "POST") {
      created = request.postDataJSON();
      return json({ service_account: { service_account_id: "agent-1", name: "reader", description: "", kind: "agent", enabled: true }, credential: { token_id: "key-1", name: "initial", token: "synthetic-token", expires_at: "2099-01-01T00:00:00Z", created_at: "2026-01-01T00:00:00Z" } }, 201);
    }
    if (path.endsWith("/access-groups")) return json({ items: [{ group_id: "group-1", name: "Leitura", enabled: true, node_ids: [], policy_ids: [] }] });
    if (path.endsWith("/policies")) return json({ items: [{ policy_id: "policy-1", name: "Temporária", description: "", rules: [] }] });
    if (path.endsWith("/users") || path.endsWith("/service-accounts") || path.endsWith("/nodes")) return json({ items: [] });
    return json({ items: [] });
  });
  await page.goto("/identity");
  await page.getByRole("tab", { name: "API Keys" }).click();
  await page.getByRole("button", { name: "Nova API key" }).click();
  await page.getByLabel("Tipo de conta").click();
  await page.getByRole("option", { name: "Agente de IA" }).click();
  await page.getByLabel("Nome", { exact: true }).fill("reader");
  await page.getByText("Leitura", { exact: true }).click();
  await expect(page.getByLabel("Bytes por resposta")).toHaveValue("16777216");
  await page.getByLabel("Redes permitidas (CIDR, opcional)").fill("10.2.0.0/16");
  await page.getByLabel("Formatos de leitura (opcional)").fill("text/plain, application/pdf");
  await page.getByRole("checkbox", { name: "Ler", exact: true }).uncheck();
  await page.getByRole("button", { name: "Criar e emitir API key" }).click();
  await expect(page.getByText("synthetic-token")).toBeVisible();
  expect(created).toMatchObject({ name: "reader", kind: "agent", group_ids: ["group-1"], agent_limits: { requests_per_minute: 60, max_concurrent: 2, allowed_cidrs: ["10.2.0.0/16"], read_media_types: ["text/plain", "application/pdf"], capabilities: ["list"] } });
  await page.getByLabel("Requisições por minuto").fill("120");
  await page.getByRole("button", { name: "Aplicar limites" }).click();
  await expect.poll(() => updated).toMatchObject({ agent_limits: { requests_per_minute: 120, allowed_cidrs: ["10.2.0.0/16"], read_media_types: ["text/plain", "application/pdf"] } });
  await page.getByLabel("Provedor", { exact: true }).fill("issuer-local");
  await page.getByLabel("Emissor", { exact: true }).fill("https://issuer.example");
  await page.getByLabel("Sujeito", { exact: true }).fill("workload-reader");
  await page.getByLabel("Audiência", { exact: true }).fill("jolt");
  await page.getByRole("button", { name: "Adicionar identidade" }).click();
  await expect.poll(() => workload).toMatchObject({ provider_id: "issuer-local", issuer: "https://issuer.example", subject: "workload-reader", audience: "jolt", agent_limits: { requests_per_minute: 120 } });
  await page.getByRole("button", { name: "Desativar identidade workload-reader" }).click();
  await expect.poll(() => workload?.enabled).toBe(false);
  await page.getByRole("button", { name: "Ativar identidade workload-reader" }).click();
  await expect.poll(() => workload?.enabled).toBe(true);
  await page.getByLabel("Policy", { exact: true }).selectOption("policy-1");
  await page.getByRole("button", { name: "Conceder", exact: true }).click();
  await expect.poll(() => temporaryGrant).toMatchObject({ policy_id: "policy-1", duration_seconds: 900 });
  await page.getByRole("button", { name: "Remover", exact: true }).click();
  await expect.poll(() => temporaryRevokes).toBe(1);
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Desativar agentes", exact: true }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Desativar agentes" }).click();
  await expect.poll(() => disableCalls).toBe(1);
});
