import { test, expect, type Page } from "@playwright/test";

const required = (name: string) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
};

const adminPassword = required("JOLT_INTEGRATION_ADMIN_PASSWORD");
const nodeA = required("JOLT_INTEGRATION_NODE_A_ID");
const nodeB = required("JOLT_INTEGRATION_NODE_B_ID");
const tokens = {
  "Node A": required("JOLT_INTEGRATION_NODE_A_TOKEN"),
  "Node B": required("JOLT_INTEGRATION_NODE_B_TOKEN"),
};

async function login(page: Page, username = "admin", password = adminPassword) {
  await page.goto("/login");
  await page.getByRole("textbox", { name: "Usuário", exact: true }).fill(username);
  await page.getByLabel("Senha", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Entrar na torre", exact: true }).click();
  await expect(page).toHaveURL(/\/$/);
}

async function addNode(page: Page, name: "Node A" | "Node B") {
  const inventory = await page.request.get("/api/v1/control-tower/nodes");
  expect(inventory.ok()).toBe(true);
  const nodes = (await inventory.json()).items || [];
  if (nodes.some((node: { name: string }) => node.name === name)) return;
  if (test.info().project.name === "mobile") {
    await page.getByRole("button", { name: "Toggle Sidebar", exact: true }).click();
  }
  await page.getByRole("button", { name: "Adicionar node", exact: true }).click();
  await page.getByRole("textbox", { name: "Nome amigável", exact: true }).fill(name);
  await page.getByRole("textbox", { name: "Endpoint", exact: true }).fill(`http://node-${name.endsWith("A") ? "a" : "b"}:8080`);
  await page.getByLabel("Token operacional", { exact: true }).fill(tokens[name]);
  await page.getByRole("button", { name: "Validar e conectar", exact: true }).click();
  await expect(page.getByText("Node conectado com sucesso.", { exact: true })).toBeVisible();
}

async function waitJob(page: Page, nodeId: string, jobId: string) {
  await expect.poll(async () => {
    const response = await page.request.get(`/api/v1/nodes/${nodeId}/jobs/${jobId}`);
    if (!response.ok()) return "request_failed";
    const job = await response.json();
    if (["failed", "cancelled", "completed_with_warnings"].includes(job.state)) {
      throw new Error(`Job ${jobId} failed: ${JSON.stringify(job.error || job)}`);
    }
    return job.state;
  }, { timeout: 60_000 }).toBe("completed");
}

async function expectContent(page: Page, nodeId: string, path: string, content: string) {
  await expect.poll(async () => {
    const response = await page.request.get(`/api/v1/nodes/${nodeId}/mounts/files/files/content?path=${encodeURIComponent(path)}`);
    return response.ok() ? (await response.body()).toString() : `HTTP ${response.status()}`;
  }, { timeout: 60_000 }).toBe(content);
}

test("real HTTPS browser journey with two nodes", async ({ page, browser }) => {
  test.setTimeout(180_000);
  const project = test.info().project.name;
  const suffix = `${project}-${Date.now()}`;
  const smallName = `small-${suffix}.txt`;
  const emptyName = `empty-${suffix}.txt`;
  const multiName = `multi-${suffix}.bin`;
  const folderName = `folder-${suffix}`;
  const sourcePath = `/api/v1/nodes/${nodeA}/mounts/files/files`;

  await login(page);
  await addNode(page, "Node A");
  await addNode(page, "Node B");
  await page.goto(`/nodes/${nodeA}/mounts/files`);
  const uploadInput = page.locator('input[type="file"][multiple]');
  await expect(uploadInput).toBeAttached();
  const multiPayload = Buffer.alloc(8 * 1024 * 1024 + 127);
  for (let index = 0; index < multiPayload.length; index += 4096) multiPayload[index] = index % 251;
  await uploadInput.setInputFiles([
    { name: emptyName, mimeType: "application/octet-stream", buffer: Buffer.alloc(0) },
    { name: smallName, mimeType: "text/plain", buffer: Buffer.from(`payload-${suffix}`) },
    { name: multiName, mimeType: "application/octet-stream", buffer: multiPayload },
  ]);
  await expect(page.getByText("Concluído", { exact: true })).toHaveCount(3, { timeout: 90_000 });
  await expect(page.getByRole("button", { name: smallName, exact: true })).toBeVisible();
  await expectContent(page, nodeA, smallName, `payload-${suffix}`);
  await expectContent(page, nodeA, emptyName, "");

  const resumeName = `resume-${suffix}.txt`;
  const resumePayload = `resumable-${suffix}`;
  const created = await page.request.post(`${sourcePath}/uploads`, {
    data: { path: resumeName, size: Buffer.byteLength(resumePayload), overwrite: false },
  });
  expect(created.status()).toBe(201);
  const uploadId = (await created.json()).upload_id;
  const partial = await page.request.patch(`${sourcePath}/uploads/${uploadId}`, {
    data: resumePayload.slice(0, 4),
    headers: { "Content-Type": "application/octet-stream", "Content-Range": `bytes 0-3/${Buffer.byteLength(resumePayload)}` },
  });
  expect(partial.ok()).toBe(true);
  await page.reload();
  const reselect = page.getByLabel(`Selecionar arquivo para retomar ${resumeName}`, { exact: true });
  await expect(reselect).toBeAttached();
  await reselect.setInputFiles({ name: resumeName, mimeType: "text/plain", buffer: Buffer.from(resumePayload) });
  await expect(reselect).toHaveCount(0, { timeout: 60_000 });
  await expectContent(page, nodeA, resumeName, resumePayload);

  const cancelled = await page.request.post(`${sourcePath}/uploads`, {
    data: { path: `cancel-${suffix}.txt`, size: 1024, overwrite: false },
  });
  expect(cancelled.status()).toBe(201);
  expect((await page.request.delete(`${sourcePath}/uploads/${(await cancelled.json()).upload_id}`)).status()).toBe(204);

  expect((await page.request.post(`${sourcePath}/directories`, { data: { path: folderName } })).status()).toBe(202);
  expect((await page.request.put(`${sourcePath}/content?path=${encodeURIComponent(`${folderName}/nested.txt`)}`, {
    data: `nested-${suffix}`, headers: { "Content-Type": "application/octet-stream" },
  })).status()).toBe(201);
  const localCopy = await page.request.post(`${sourcePath}/copy`, {
    data: { source_path: smallName, destination_path: `local-copy-${suffix}.txt` },
  });
  expect(localCopy.status()).toBe(202);
  await waitJob(page, nodeA, (await localCopy.json()).job_id);
  const localMove = await page.request.post(`${sourcePath}/move`, {
    data: { source_path: `local-copy-${suffix}.txt`, destination_path: `local-moved-${suffix}.txt` },
  });
  expect(localMove.status()).toBe(202);
  await waitJob(page, nodeA, (await localMove.json()).job_id);
  await expectContent(page, nodeA, `local-moved-${suffix}.txt`, `payload-${suffix}`);

  await page.reload();
  await page.getByRole("checkbox", { name: `Selecionar ${smallName}`, exact: true }).check();
  await page.getByRole("checkbox", { name: `Selecionar ${folderName}`, exact: true }).check();
  await page.getByRole("button", { name: "Copiar para…", exact: true }).click();
  const transfer = page.getByRole("dialog");
  await transfer.getByRole("combobox").first().click();
  await page.getByRole("option", { name: /Node B/ }).click();
  await transfer.getByRole("button", { name: "Gerar prévia", exact: true }).click();
  await transfer.getByRole("button", { name: "Confirmar transferência", exact: true }).click();
  await expect(transfer.getByText(/Job .* criado no node de destino/)).toBeVisible();
  await expectContent(page, nodeB, smallName, `payload-${suffix}`);
  await expectContent(page, nodeB, `${folderName}/nested.txt`, `nested-${suffix}`);
  await transfer.getByRole("button", { name: "Fechar", exact: true }).click();

  await page.reload();
  await page.getByRole("row").filter({ hasText: smallName }).click({ button: "right" });
  await page.getByRole("menuitem", { name: "Criar link público…", exact: true }).click();
  const share = page.getByRole("dialog");
  await share.getByRole("button", { name: "Gerar link", exact: true }).click();
  const shareURL = await share.getByLabel("Link gerado", { exact: true }).inputValue();
  const publicPage = await browser.newPage({ baseURL: process.env.JOLT_INTEGRATION_BASE_URL, ignoreHTTPSErrors: true });
  await publicPage.goto(shareURL);
  await expect(publicPage.getByText(smallName, { exact: true })).toBeVisible();
  const shareToken = new URL(shareURL).pathname.split("/").pop();
  const sharedContent = await publicPage.request.get(`/api/v1/public/shares/${shareToken}/content`);
  expect(sharedContent.ok()).toBe(true);
  expect((await sharedContent.body()).toString()).toBe(`payload-${suffix}`);
  await publicPage.close();

  const privateName = `private-${suffix}.txt`;
  expect((await page.request.put(`${sourcePath}/content?path=${privateName}`, {
    data: "restricted-secret", headers: { "Content-Type": "application/octet-stream" },
  })).status()).toBe(201);
  const operatorPassword = `operator-${suffix}-password`;
  const operatorName = `operator-${suffix}`;
  const user = await page.request.post("/api/v1/control-tower/users", {
    data: { username: operatorName, password: operatorPassword, role: "operator" },
  });
  expect(user.status()).toBe(201);
  const userId = (await user.json()).user_id;
  const scope = `nodes/${nodeA}/files/mounts/files`;
  const policy = await page.request.post("/api/v1/control-tower/policies", {
    data: { name: `policy-${suffix}`, rules: [
      { path: `${scope}/**`, capabilities: ["read", "list"] },
      { path: `${scope}/${privateName}`, capabilities: ["deny"] },
    ] },
  });
  expect(policy.status()).toBe(201);
  expect((await page.request.put(`/api/v1/control-tower/users/${userId}/policies`, {
    data: { policy_ids: [(await policy.json()).policy_id] },
  })).ok()).toBe(true);

  const operatorContext = await browser.newContext({ baseURL: process.env.JOLT_INTEGRATION_BASE_URL, ignoreHTTPSErrors: true });
  const operatorPage = await operatorContext.newPage();
  await login(operatorPage, operatorName, operatorPassword);
  await operatorPage.goto(`/nodes/${nodeA}/mounts/files`);
  await expect(operatorPage.getByRole("button", { name: smallName, exact: true })).toBeVisible();
  expect((await operatorPage.request.get(`${sourcePath}/content?path=${privateName}`)).status()).toBe(403);
  expect((await page.request.put(`/api/v1/control-tower/users/${userId}/policies`, { data: { policy_ids: [] } })).ok()).toBe(true);
  await expect.poll(async () => (await operatorPage.request.get(`${sourcePath}/content?path=${smallName}`)).status()).toBe(403);
  await operatorContext.close();

  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
