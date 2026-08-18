// Domain types for the Control Tower API. Fields mirror the JSON returned by
// the Go backend; many are optional because the UI reads them defensively.

export type Capability =
  | "read"
  | "list"
  | "create"
  | "update"
  | "delete"
  | "write"
  | "execute"
  | "sudo"
  | "deny";

export interface AuthUser {
  user_id: string;
  username: string;
  role: string;
  enabled: boolean;
}

export interface User extends AuthUser {}

export interface ServiceAccount {
  service_account_id: string;
  name: string;
  description: string;
  enabled: boolean;
}

export interface AccessGroup {
  group_id: string;
  name: string;
  description: string;
  enabled: boolean;
  node_ids: string[];
  policy_ids: string[];
  created_at?: string;
  updated_at?: string;
}

export interface ServiceAccountToken {
  token_id: string;
  name: string;
  expires_at: string | null;
  created_at: string;
  revoked_at?: string | null;
}

export interface ServiceCredential extends ServiceAccountToken {
  token: string;
}

export interface PolicyRule {
  path: string;
  capabilities: Capability[];
}

export interface Policy {
  policy_id: string;
  name: string;
  description: string;
  rules: PolicyRule[];
}

export interface Role {
  role_id: string;
  name: string;
  description: string;
  policy_ids: string[];
}

export interface AuditEvent {
  event_id?: string;
  actor_type?: string;
  actor_id?: string;
  action?: string;
  result?: string;
  capability?: string;
  correlation_id?: string;
  resource?: string;
  evaluated_path?: string;
  policy_ids?: string[];
  created_at?: string;
  [key: string]: unknown;
}

export type NodeState = "online" | "offline" | "degraded" | "untrusted" | string;

export interface NodeInfo {
  node_id: string;
  name: string;
  endpoint: string;
  state: NodeState;
  last_seen_at?: string | null;
}

export type MountMode = "read_write" | "read_only";

export interface Mount {
  mount_id: string;
  name: string;
  local_path?: string;
  mode: MountMode;
  published?: boolean;
  enabled?: boolean;
}

export type FileEntryType = "directory" | "file" | "symlink";

export interface FileEntry {
  name: string;
  path: string;
  type: FileEntryType;
  size?: number;
  modified_at?: string;
}

export interface BrowseResult {
  home: string;
  path: string;
  parent: string;
  items: FileEntry[];
}

export interface Job {
  job_id: string;
  type: string;
  state: string;
  source_path?: string;
  destination_path?: string;
  mount_id?: string;
  bytes_completed?: number;
  bytes_total?: number;
  bytes_per_second?: number;
  eta_seconds?: number | null;
  eta_confidence?: string;
  files_total?: number;
  files_completed?: number;
  files_failed?: number;
  error?: string;
  created_at?: string;
}

export interface JobItem {
  ordinal: number;
  action: string;
  source_path?: string;
  destination_path?: string;
  [key: string]: unknown;
}

export type PeerState =
  | "trusted"
  | "unknown"
  | "online"
  | "offline"
  | "degraded"
  | "identity_changed"
  | "revoked"
  | string;

export interface Peer {
  node_id: string;
  name: string;
  fingerprint: string;
  state: PeerState;
  local_role?: string;
  remote_role?: string;
  cluster_id?: string;
  transfer_mode?: string;
  endpoint?: string;
  mtls_endpoint?: string;
}

export interface GrantPermissions {
  read: boolean;
  write: boolean;
  delete: boolean;
  rename: boolean;
}

export type GrantDirection = "send" | "receive" | "send_receive";

export interface Grant {
  grant_id: string;
  peer_node_id: string;
  mount_id: string;
  path: string;
  direction: GrantDirection;
  permissions: GrantPermissions;
  conflict_policies: string[];
  visible_to_peer: boolean;
  enabled: boolean;
}

export interface PairingInvite {
  invite_id: string;
  target_node_id: string;
  purpose?: string;
  issuer_role: string;
  invitee_role: string;
  expires_at?: string;
  status: string;
}

export interface PairingRequest {
  request_id: string;
  issuer_name: string;
  issuer_fingerprint: string;
  purpose?: string;
  transfer_mode: string;
  status: string;
}

export interface MTLSRolloutPeer {
  node_id: string;
  status: string;
}

export interface MTLSRollout {
  peers?: Record<string, MTLSRolloutPeer>;
}

export interface MTLSState {
  next?: { serial: string; key_id: string } | null;
  rollouts?: Record<string, MTLSRollout>;
  [key: string]: unknown;
}

export interface IdentityState {
  active?: { fingerprint: string } | null;
  next_active?: { fingerprint: string } | null;
  restart_required?: boolean;
  acknowledged_peer_node_ids?: string[];
  pending_peer_node_ids?: string[];
  delivery_complete?: boolean;
}

export interface TransferPlan {
  files_total: number;
  bytes_total: number;
  copy_count: number;
  conflict_count: number;
  remote_file?: boolean;
}

export interface ListResponse<T> {
  items: T[];
}

export interface AuditResponse {
  events: AuditEvent[];
  has_more?: boolean;
  next_before_id?: string | null;
}

export interface PermissionsResponse {
  paths: Record<string, Capability[]>;
}

export interface ApiError extends Error {
  code?: string;
  status?: number;
}
