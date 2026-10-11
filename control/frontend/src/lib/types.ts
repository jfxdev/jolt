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
  /** The peer's listener refused our certificate: it dropped us. */
  | "revoked_by_peer"
  | "untrusted"
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

export type PairingInviteStatus =
  | "pending"
  | "consumed"
  | "revoked"
  | "expired"
  | string;

export interface PairingInvite {
  invite_id: string;
  target_node_id: string;
  purpose?: string;
  issuer_role: string;
  invitee_role: string;
  expires_at?: string;
  status: PairingInviteStatus;
}

export type PairingRequestStatus =
  | "pending_review"
  | "accepted"
  | "rejected"
  | "expired"
  | string;

export interface PairingRequest {
  request_id: string;
  issuer_name: string;
  issuer_fingerprint: string;
  purpose?: string;
  transfer_mode: string;
  status: PairingRequestStatus;
}

export type ConnectionStatus =
  | "pending_review"
  | "connected"
  /** One node trusts the other but the handshake never finished. */
  | "partially_connected"
  | "rejected"
  | "revoked"
  | string;

export interface Connection {
  request_id: string;
  invite_id: string;
  issuer_node_id: string;
  target_node_id: string;
  issuer_fingerprint: string;
  status: ConnectionStatus;
  expires_at: string;
  created_at: string;
  updated_at: string;
}

/**
 * Why the two sides of a pairing disagree, as resolved by the Control Tower.
 * The browser cannot tell these apart from two peer listings, which is why the
 * server classifies them.
 */
export type TrustStatus =
  | "connected"
  | "revoked_by_peer"
  | "missing_on_peer"
  | "identity_changed"
  | "unreachable"
  | "revoked"
  | "not_registered"
  | "remote_unreadable"
  | string;

export interface TrustPeer extends Peer {
  previous_fingerprint?: string;
  identity_epoch?: number;
  last_seen_at?: string;
  consecutive_failures?: number;
  trusted_at?: string;
  remote_state?: PeerState;
  reciprocal: boolean;
  trust_status: TrustStatus;
  asymmetry_reason?: string;
  registered: boolean;
	registered_node_id?: string;
  grants: Grant[];
}

export interface TrustView {
  node_id: string;
  peers: TrustPeer[];
  invites: PairingInvite[];
  requests: PairingRequest[];
  connections: Connection[];
  can_read_pairing: boolean;
  can_list_grants: boolean;
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
	skip_count?: number;
	rename_count?: number;
	conflict_count: number;
	truncated?: boolean;
	items?: JobItem[];
	remote_file?: boolean;
}

export interface LogicalTransferRequest {
	operation: "copy" | "move";
	source: { node_id: string; mount_id: string; paths: string[] };
	destination: { mount_id: string; path: string };
	conflict_policy?: string;
	verify_checksum?: boolean;
	bandwidth_limit_bytes_per_second?: number;
	max_parallel_files?: number;
	max_parallel_chunks?: number;
}

export interface TransferTargetMount {
	mount_id: string;
	name: string;
	root_path: string;
	conflict_policies: string[];
	can_browse: boolean;
	available: boolean;
	state: string;
}

export interface TransferTargetNode {
	node_id: string;
	name: string;
	state: NodeState;
	available: boolean;
	mounts: TransferTargetMount[];
}

export interface TransferTargetsResponse {
	max_source_paths: number;
	targets: TransferTargetNode[];
	blocked_targets?: {
		node_id: string;
		name: string;
		reasons: ("source_grant_missing" | "destination_grant_missing")[];
	}[];
}

export interface LogicalTransferPlanResponse {
	max_source_paths: number;
	plan: TransferPlan;
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
