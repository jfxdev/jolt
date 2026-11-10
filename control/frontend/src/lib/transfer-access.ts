import type { Grant, GrantDirection, TransferTargetMount, TransferTargetNode, TransferTargetsResponse, TrustPeer } from "./types";

export type TransferDestination = TransferTargetNode & {
  reasons?: NonNullable<TransferTargetsResponse["blocked_targets"]>[number]["reasons"];
};

// Blocked nodes are still destinations the user can choose and configure.
export function transferDestinations(response: TransferTargetsResponse): TransferDestination[] {
  const ready = (response.targets || []).map((target) => ({ ...target, mounts: uniqueTransferTargetMounts(target.mounts || []) }));
  return [
    ...ready,
    ...(response.blocked_targets || [])
      .filter((blocked) => !ready.some((target) => target.node_id === blocked.node_id))
      .map((blocked) => ({ ...blocked, state: "online" as const, available: false, mounts: [] })),
  ];
}

// One destination entry per receive grant: a mount can appear once per grant
// root, so the selection is keyed by mount and root, never by mount alone.
export function transferTargetMountKey(mount: Pick<TransferTargetMount, "mount_id" | "root_path">): string {
  return `${mount.mount_id}\u0000${mount.root_path}`;
}

export function transferTargetMountLabel(mount: Pick<TransferTargetMount, "name" | "root_path">): string {
  return mount.root_path ? `${mount.name} · /${mount.root_path}` : mount.name;
}

// Grants sharing a mount and root become one entry; the server still picks the
// grant that accepts the chosen conflict policy.
function uniqueTransferTargetMounts(mounts: TransferTargetMount[]): TransferTargetMount[] {
  const byKey = new Map<string, TransferTargetMount>();
  for (const mount of mounts) {
    const key = transferTargetMountKey(mount);
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...mount, conflict_policies: [...mount.conflict_policies] });
      continue;
    }
    existing.conflict_policies = [...new Set([...existing.conflict_policies, ...mount.conflict_policies])];
    existing.can_browse ||= mount.can_browse;
  }
  return [...byKey.values()];
}

export function transferSourceFolder(paths: string[]): string {
  const folders = paths.map((path) => path.replaceAll("\\", "/").split("/").slice(0, -1));
  const common = folders[0] || [];
  let length = 0;
  while (length < common.length && folders.every((folder) => folder[length] === common[length])) length++;
  return common.slice(0, length).join("/");
}

export function transferPeer(peers: TrustPeer[], registeredNodeId: string): TrustPeer | undefined {
  return peers.find((peer) => (peer.registered_node_id || peer.node_id) === registeredNodeId);
}

export function matchingTransferGrant(grants: Grant[], peerNodeId: string, mountId: string, path: string, direction: GrantDirection): Grant | undefined {
  const normalize = (value: string) => value.replaceAll("\\", "/").replace(/^\/+|\/+$/g, "").replace(/^\.$/, "");
  return grants.find((grant) => grant.peer_node_id === peerNodeId && grant.mount_id === mountId && normalize(grant.path) === normalize(path) && (grant.direction === direction || grant.direction === "send_receive"));
}

export interface TransferSourceAccess {
  status: "ready" | "missing" | "removal_missing";
  grant?: Grant;
}

// A display hint only: transfer discovery and execution remain server-authorized.
export function transferSourceAccess(grants: Grant[], peerNodeId: string, mountId: string, paths: string[], operation: "copy" | "move"): TransferSourceAccess {
  const selected = paths.map(normalizeAccessPath);
  if (!selected.length || selected.some((path) => !path)) return { status: "missing" };
  const readable = grants.filter((grant) => {
    if (!grant.enabled || grant.peer_node_id !== peerNodeId || grant.mount_id !== mountId || !grant.permissions.read ||
      (grant.direction !== "send" && grant.direction !== "send_receive")) return false;
    const root = normalizeAccessPath(grant.path);
    return root !== null && selected.every((path) => !root || path === root || path!.startsWith(`${root}/`));
  });
  const allowed = readable.find((grant) => operation === "copy" || grant.permissions.delete);
  if (allowed) return { status: "ready", grant: allowed };
  if (readable.length) return { status: "removal_missing", grant: readable[0] };
  return { status: "missing" };
}

function normalizeAccessPath(value: string): string | null {
  const path = value.trim().replaceAll("\\", "/");
  if (path.startsWith("/")) return null;
  const parts: string[] = [];
  for (const part of path.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") {
      if (!parts.length) return null;
      parts.pop();
    } else parts.push(part);
  }
  return parts.join("/");
}

export function transferGrantAuthorization(peerNodeId: string, mountId: string, path: string, direction: "send" | "receive", operation: "copy" | "move", policy: string, existing?: Grant): Omit<Grant, "grant_id"> {
  return {
    peer_node_id: peerNodeId,
    mount_id: mountId,
    path: path.trim(),
    direction: existing?.direction || direction,
    permissions: {
      read: direction === "send" || existing?.permissions.read || false,
      write: direction === "receive" || existing?.permissions.write || false,
      rename: existing?.permissions.rename || false,
      delete: (direction === "send" && operation === "move") || existing?.permissions.delete || false,
    },
    conflict_policies: direction === "receive"
      ? [...new Set([...(existing?.conflict_policies || []), policy])]
      : existing?.conflict_policies || [],
    visible_to_peer: existing?.visible_to_peer || false,
    enabled: true,
  };
}
