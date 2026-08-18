import type {
  ApiError,
  AccessGroup,
  AuditEvent,
  AuditResponse,
  AuthUser,
  Grant,
  IdentityState,
  Job,
  JobItem,
  ListResponse,
  MTLSState,
  Mount,
  NodeInfo,
  PairingInvite,
  PairingRequest,
  Peer,
  PermissionsResponse,
  Policy,
  Role,
  ServiceAccount,
  ServiceAccountToken,
  ServiceCredential,
  TransferPlan,
  User,
} from "./types";

interface RequestOptions extends RequestInit {}

async function request<T = unknown>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      ...(options.body instanceof Blob
        ? {}
        : options.body
          ? { "Content-Type": "application/json" }
          : {}),
      ...options.headers,
    },
  });
  if (response.status === 204) return null as T;
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json")
    ? await response.json()
    : await response.blob();
  if (!response.ok) {
    const error = new Error(
      payload?.error?.message || "Não foi possível concluir a operação.",
    ) as ApiError;
    error.code = payload?.error?.code;
    error.status = response.status;
    throw error;
  }
  return payload as T;
}

async function requestText(path: string): Promise<string> {
  const response = await fetch(path, { credentials: "same-origin" });
  if (response.ok) return response.text();
  const payload = await response.json().catch(() => null);
  const error = new Error(
    payload?.error?.message || "Não foi possível concluir a operação.",
  ) as ApiError;
  error.code = payload?.error?.code;
  error.status = response.status;
  throw error;
}

export const api = {
  me: () =>
    request<{ user: AuthUser }>("/api/v1/control-tower/auth/me"),
  permissions: (paths: string[]) =>
    request<PermissionsResponse>("/api/v1/control-tower/auth/permissions", {
      method: "POST",
      body: JSON.stringify({ paths }),
    }),
  login: (username: string, password: string) =>
    request<{ user: AuthUser }>("/api/v1/control-tower/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: () =>
    request<null>("/api/v1/control-tower/auth/logout", { method: "POST" }),
  users: () => request<ListResponse<User>>("/api/v1/control-tower/users"),
  createUser: (user: Partial<User> & { password?: string }) =>
    request<User>("/api/v1/control-tower/users", {
      method: "POST",
      body: JSON.stringify(user),
    }),
  updateUser: (
    userId: string,
    user: Partial<User> & { password?: string },
  ) =>
    request<User>(
      `/api/v1/control-tower/users/${encodeURIComponent(userId)}`,
      {
        method: "PATCH",
        body: JSON.stringify(user),
      },
    ),
  deleteUser: (userId: string) =>
    request<null>(
      `/api/v1/control-tower/users/${encodeURIComponent(userId)}`,
      { method: "DELETE" },
    ),
  serviceAccounts: () =>
    request<ListResponse<ServiceAccount>>(
      "/api/v1/control-tower/service-accounts",
    ),
  createServiceAccount: (account: object) =>
    request<{
      service_account: ServiceAccount;
      credential: ServiceCredential;
    }>("/api/v1/control-tower/service-accounts", {
      method: "POST",
      body: JSON.stringify(account),
    }),
  updateServiceAccount: (
    accountId: string,
    account: object,
  ) =>
    request<ServiceAccount>(
      `/api/v1/control-tower/service-accounts/${encodeURIComponent(accountId)}`,
      {
        method: "PATCH",
        body: JSON.stringify(account),
      },
    ),
  deleteServiceAccount: (accountId: string) =>
    request<null>(
      `/api/v1/control-tower/service-accounts/${encodeURIComponent(accountId)}`,
      { method: "DELETE" },
    ),
  serviceAccountTokens: (accountId: string) =>
    request<ListResponse<ServiceAccountToken>>(
      `/api/v1/control-tower/service-accounts/${encodeURIComponent(accountId)}/tokens`,
    ),
  rotateServiceAccountToken: (
    accountId: string,
    credential: object,
  ) =>
    request<ServiceCredential>(
      `/api/v1/control-tower/service-accounts/${encodeURIComponent(accountId)}/tokens`,
      {
        method: "POST",
        body: JSON.stringify(credential),
      },
    ),
  revokeServiceAccountToken: (accountId: string, tokenId: string) =>
    request<null>(
      `/api/v1/control-tower/service-accounts/${encodeURIComponent(accountId)}/tokens/${encodeURIComponent(tokenId)}`,
      { method: "DELETE" },
    ),
  accessGroups: () =>
    request<ListResponse<AccessGroup>>("/api/v1/control-tower/access-groups"),
  createAccessGroup: (group: object) =>
    request<AccessGroup>("/api/v1/control-tower/access-groups", {
      method: "POST",
      body: JSON.stringify(group),
    }),
  updateAccessGroup: (groupId: string, group: object) =>
    request<AccessGroup>(
      `/api/v1/control-tower/access-groups/${encodeURIComponent(groupId)}`,
      { method: "PATCH", body: JSON.stringify(group) },
    ),
  deleteAccessGroup: (groupId: string) =>
    request<null>(
      `/api/v1/control-tower/access-groups/${encodeURIComponent(groupId)}`,
      { method: "DELETE" },
    ),
  accessGroupNodes: (groupId: string) =>
    request<{ node_ids: string[] }>(
      `/api/v1/control-tower/access-groups/${encodeURIComponent(groupId)}/nodes`,
    ),
  setAccessGroupNodes: (groupId: string, ids: string[]) =>
    request<{ node_ids: string[] }>(
      `/api/v1/control-tower/access-groups/${encodeURIComponent(groupId)}/nodes`,
      { method: "PUT", body: JSON.stringify({ ids }) },
    ),
  accessGroupPolicies: (groupId: string) =>
    request<{ policy_ids: string[] }>(
      `/api/v1/control-tower/access-groups/${encodeURIComponent(groupId)}/policies`,
    ),
  setAccessGroupPolicies: (groupId: string, ids: string[]) =>
    request<{ policy_ids: string[] }>(
      `/api/v1/control-tower/access-groups/${encodeURIComponent(groupId)}/policies`,
      { method: "PUT", body: JSON.stringify({ ids }) },
    ),
  policies: () =>
    request<ListResponse<Policy>>("/api/v1/control-tower/policies"),
  createPolicy: (policy: object) =>
    request<Policy>("/api/v1/control-tower/policies", {
      method: "POST",
      body: JSON.stringify(policy),
    }),
  updatePolicy: (policyId: string, policy: object) =>
    request<Policy>(
      `/api/v1/control-tower/policies/${encodeURIComponent(policyId)}`,
      {
        method: "PATCH",
        body: JSON.stringify(policy),
      },
    ),
  deletePolicy: (policyId: string) =>
    request<null>(
      `/api/v1/control-tower/policies/${encodeURIComponent(policyId)}`,
      { method: "DELETE" },
    ),
  roles: () => request<ListResponse<Role>>("/api/v1/control-tower/roles"),
  createRole: (role: object) =>
    request<Role>("/api/v1/control-tower/roles", {
      method: "POST",
      body: JSON.stringify(role),
    }),
  updateRole: (roleId: string, role: object) =>
    request<Role>(
      `/api/v1/control-tower/roles/${encodeURIComponent(roleId)}`,
      {
        method: "PATCH",
        body: JSON.stringify(role),
      },
    ),
  deleteRole: (roleId: string) =>
    request<null>(
      `/api/v1/control-tower/roles/${encodeURIComponent(roleId)}`,
      { method: "DELETE" },
    ),
  userRoles: (userId: string) =>
    request<{ role_ids: string[] }>(
      `/api/v1/control-tower/users/${encodeURIComponent(userId)}/roles`,
    ),
  setUserRoles: (userId: string, roleIds: string[]) =>
    request<null>(
      `/api/v1/control-tower/users/${encodeURIComponent(userId)}/roles`,
      {
        method: "PUT",
        body: JSON.stringify({ role_ids: roleIds }),
      },
    ),
  userPolicies: (userId: string) =>
    request<{ policy_ids: string[] }>(
      `/api/v1/control-tower/users/${encodeURIComponent(userId)}/policies`,
    ),
  setUserPolicies: (userId: string, policyIds: string[]) =>
    request<null>(
      `/api/v1/control-tower/users/${encodeURIComponent(userId)}/policies`,
      {
        method: "PUT",
        body: JSON.stringify({ policy_ids: policyIds }),
      },
    ),
  serviceAccountPolicies: (accountId: string) =>
    request<{ policy_ids: string[] }>(
      `/api/v1/control-tower/service-accounts/${encodeURIComponent(accountId)}/policies`,
    ),
  setServiceAccountPolicies: (accountId: string, policyIds: string[]) =>
    request<null>(
      `/api/v1/control-tower/service-accounts/${encodeURIComponent(accountId)}/policies`,
      {
        method: "PUT",
        body: JSON.stringify({ policy_ids: policyIds }),
      },
    ),
  serviceAccountGroups: (accountId: string) =>
    request<{ group_ids: string[] }>(
      `/api/v1/control-tower/service-accounts/${encodeURIComponent(accountId)}/groups`,
    ),
  setServiceAccountGroups: (accountId: string, groupIds: string[]) =>
    request<{ group_ids: string[] }>(
      `/api/v1/control-tower/service-accounts/${encodeURIComponent(accountId)}/groups`,
      { method: "PUT", body: JSON.stringify({ ids: groupIds }) },
    ),
  auditEvents: (filters: object = {}) => {
    const query = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== "" && value != null) query.set(key, String(value));
    });
    return request<AuditResponse>(
      `/api/v1/control-tower/audit?${query}`,
    );
  },
  nodes: () => request<ListResponse<NodeInfo>>("/api/v1/control-tower/nodes"),
  addNode: (node: object) =>
    request<NodeInfo>("/api/v1/control-tower/nodes", {
      method: "POST",
      body: JSON.stringify(node),
    }),
  removeNode: (id: string) =>
    request<null>(
      `/api/v1/control-tower/nodes/${encodeURIComponent(id)}`,
      { method: "DELETE" },
    ),
  rotateNodeToken: (id: string) =>
    request<unknown>(
      `/api/v1/control-tower/nodes/${encodeURIComponent(id)}/rotate-token`,
      {
        method: "POST",
        body: JSON.stringify({}),
      },
    ),
  mounts: (nodeId: string) =>
    request<ListResponse<Mount>>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/mounts`,
    ),
  createMount: (nodeId: string, mount: object) =>
    request<Mount>(`/api/v1/nodes/${encodeURIComponent(nodeId)}/mounts`, {
      method: "POST",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify(mount),
    }),
  browseFilesystem: (nodeId: string, path: string) =>
    request<import("./types").BrowseResult>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/fs/browse?path=${encodeURIComponent(path)}`,
    ),
  files: (nodeId: string, mountId: string, path: string) =>
    request<ListResponse<import("./types").FileEntry>>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/mounts/${encodeURIComponent(mountId)}/files?path=${encodeURIComponent(path)}`,
    ),
  jobs: (nodeId: string) =>
    request<ListResponse<Job>>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/jobs`,
    ),
  jobItems: (nodeId: string, jobId: string, after = 0) =>
    request<ListResponse<JobItem>>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/jobs/${encodeURIComponent(jobId)}/items?after=${after}`,
    ),
  overrideJobItem: (
    nodeId: string,
    jobId: string,
    ordinal: number,
    decision: object,
  ) =>
    request<Job>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/jobs/${encodeURIComponent(jobId)}/items/${ordinal}/override`,
      {
        method: "POST",
        body: JSON.stringify(decision),
      },
    ),
  jobEventsURL: (nodeId: string) =>
    `/api/v1/nodes/${encodeURIComponent(nodeId)}/jobs/events`,
  controlJob: (nodeId: string, jobId: string, action: string) =>
    request<unknown>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/jobs/${encodeURIComponent(jobId)}/${action}`,
      { method: "POST" },
    ),
  planCopy: (nodeId: string, mountId: string, copy: object) =>
    request<TransferPlan>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/mounts/${encodeURIComponent(mountId)}/files/copy/plan`,
      {
        method: "POST",
        body: JSON.stringify(copy),
      },
    ),
  copy: (nodeId: string, mountId: string, copy: object) =>
    request<unknown>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/mounts/${encodeURIComponent(mountId)}/files/copy`,
      {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify(copy),
      },
    ),
  move: (nodeId: string, mountId: string, move: object) =>
    request<unknown>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/mounts/${encodeURIComponent(mountId)}/files/move`,
      {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify(move),
      },
    ),
  mkdir: (nodeId: string, mountId: string, path: string) =>
    request<unknown>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/mounts/${encodeURIComponent(mountId)}/files/directories`,
      {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({ path }),
      },
    ),
  upload: (nodeId: string, mountId: string, path: string, file: Blob) =>
    request<unknown>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/mounts/${encodeURIComponent(mountId)}/files/content?path=${encodeURIComponent(path)}`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/octet-stream",
          "Idempotency-Key": crypto.randomUUID(),
        },
        body: file,
      },
    ),
  removeFile: (
    nodeId: string,
    mountId: string,
    path: string,
    recursive: boolean,
  ) =>
    request<unknown>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/mounts/${encodeURIComponent(mountId)}/files?path=${encodeURIComponent(path)}&recursive=${recursive}`,
      {
        method: "DELETE",
        headers: { "Idempotency-Key": crypto.randomUUID() },
      },
    ),
  pairingInvites: (nodeId: string) =>
    request<ListResponse<PairingInvite>>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/pairing/invites`,
    ),
  pairingRequests: (nodeId: string) =>
    request<ListResponse<PairingRequest>>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/pairing/requests`,
    ),
  peers: (nodeId: string) =>
    request<ListResponse<Peer>>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/peers`,
    ),
  updatePeerEndpoints: (
    nodeId: string,
    peerNodeId: string,
    endpoints: object,
  ) =>
    request<unknown>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/peers/${encodeURIComponent(peerNodeId)}`,
      {
        method: "PATCH",
        body: JSON.stringify(endpoints),
      },
    ),
  revokePeer: (nodeId: string, peerNodeId: string) =>
    request<{ canceled_jobs?: number }>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/peers/${encodeURIComponent(peerNodeId)}`,
      { method: "DELETE" },
    ),
  recoverPeerIdentity: (
    nodeId: string,
    peerNodeId: string,
    confirmedFingerprint: string,
  ) =>
    request<unknown>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/peers/${encodeURIComponent(peerNodeId)}/identity`,
      {
        method: "PATCH",
        body: JSON.stringify({ confirmed_fingerprint: confirmedFingerprint }),
      },
    ),
  identityState: (nodeId: string) =>
    request<IdentityState>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/crypto/identity`,
    ),
  rotateIdentity: (nodeId: string, confirmedFingerprint: string) =>
    request<IdentityState>(
      `/api/v1/control-tower/nodes/${encodeURIComponent(nodeId)}/rotate-identity`,
      {
        method: "POST",
        body: JSON.stringify({ confirmed_fingerprint: confirmedFingerprint }),
      },
    ),
  distributeIdentityHandovers: (nodeId: string) =>
    request<IdentityState>(
      `/api/v1/control-tower/nodes/${encodeURIComponent(nodeId)}/distribute-identity-handovers`,
      {
        method: "POST",
        body: JSON.stringify({}),
      },
    ),
  mtlsState: (nodeId: string) =>
    request<MTLSState>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/crypto/mtls`,
    ),
  prepareMTLSRotation: (nodeId: string, validityDays: number) =>
    request<unknown>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/crypto/mtls/rotate`,
      {
        method: "POST",
        body: JSON.stringify({ validity_days: validityDays }),
      },
    ),
  distributeMTLSRotation: (nodeId: string) =>
    request<{
      acknowledged_peer_node_ids?: string[];
      pending_peer_node_ids?: string[];
    }>(
      `/api/v1/control-tower/nodes/${encodeURIComponent(nodeId)}/distribute-mtls-rotation`,
      {
        method: "POST",
        body: JSON.stringify({}),
      },
    ),
  promoteMTLSRotation: (nodeId: string, graceHours: number) =>
    request<unknown>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/crypto/mtls/promote`,
      {
        method: "POST",
        body: JSON.stringify({ grace_hours: graceHours }),
      },
    ),
  grants: (nodeId: string) =>
    request<ListResponse<Grant>>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/grants`,
    ),
  createGrant: (nodeId: string, grant: object) =>
    request<Grant>(`/api/v1/nodes/${encodeURIComponent(nodeId)}/grants`, {
      method: "POST",
      body: JSON.stringify(grant),
    }),
  updateGrant: (
    nodeId: string,
    grantId: string,
    grant: object,
  ) =>
    request<Grant>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/grants/${encodeURIComponent(grantId)}`,
      {
        method: "PATCH",
        body: JSON.stringify(grant),
      },
    ),
  deleteGrant: (nodeId: string, grantId: string) =>
    request<null>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/grants/${encodeURIComponent(grantId)}`,
      { method: "DELETE" },
    ),
  pullTransfer: (nodeId: string, transfer: object) =>
    request<unknown>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/transfers/pull`,
      {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify(transfer),
      },
    ),
  planDirectoryPull: (nodeId: string, transfer: object) =>
    request<TransferPlan>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/transfers/pull/directory/plan`,
      {
        method: "POST",
        body: JSON.stringify(transfer),
      },
    ),
  pullDirectory: (nodeId: string, transfer: object) =>
    request<unknown>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/transfers/pull/directory`,
      {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify(transfer),
      },
    ),
  createConnection: (connection: object) =>
    request<unknown>("/api/v1/control-tower/connections", {
      method: "POST",
      body: JSON.stringify(connection),
    }),
  revokeInvite: (nodeId: string, inviteId: string) =>
    request<null>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/pairing/invites/${encodeURIComponent(inviteId)}`,
      { method: "DELETE" },
    ),
  approveConnection: (requestId: string, confirmedFingerprint: string) =>
    request<unknown>(
      `/api/v1/control-tower/connections/${encodeURIComponent(requestId)}/approve`,
      {
        method: "POST",
        body: JSON.stringify({ confirmed_fingerprint: confirmedFingerprint }),
      },
    ),
  rejectConnection: (requestId: string) =>
    request<unknown>(
      `/api/v1/control-tower/connections/${encodeURIComponent(requestId)}/reject`,
      {
        method: "POST",
        body: JSON.stringify({}),
      },
    ),
  downloadUrl: (nodeId: string, mountId: string, path: string) =>
    `/api/v1/nodes/${encodeURIComponent(nodeId)}/mounts/${encodeURIComponent(mountId)}/files/content?path=${encodeURIComponent(path)}`,
  previewUrl: (nodeId: string, mountId: string, path: string) =>
    `/api/v1/nodes/${encodeURIComponent(nodeId)}/mounts/${encodeURIComponent(mountId)}/files/content?path=${encodeURIComponent(path)}&disposition=inline`,
  editorContent: (nodeId: string, mountId: string, path: string) =>
    requestText(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/mounts/${encodeURIComponent(mountId)}/files/content?path=${encodeURIComponent(path)}&editor=true`,
    ),
  saveEditorContent: (nodeId: string, mountId: string, path: string, content: string) =>
    request<unknown>(
      `/api/v1/nodes/${encodeURIComponent(nodeId)}/mounts/${encodeURIComponent(mountId)}/files/content?path=${encodeURIComponent(path)}&editor=true&overwrite=true`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Idempotency-Key": crypto.randomUUID(),
        },
        body: new Blob([content], { type: "text/plain;charset=utf-8" }),
      },
    ),
};

export type { AuditEvent };
