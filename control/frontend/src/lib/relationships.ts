import type { NodeInfo, TrustPeer } from "./types";
import { trustPresentation } from "./trust.ts";

export interface RelationshipInventory {
  node: NodeInfo;
  peers: TrustPeer[];
  canListGrants: boolean;
}

export interface TrustLink {
  key: string;
  source: NodeInfo;
  target: NodeInfo | undefined;
  peer: TrustPeer;
}

export function relationshipKey(sourceId: string, targetId: string): string {
  return [sourceId, targetId].sort().join(":");
}

export function relationshipHref(sourceId: string, targetId: string): string {
  return `/relationships?${new URLSearchParams({ source: sourceId, target: targetId })}`;
}

export function relationshipLinks(inventory: RelationshipInventory[], nodes: NodeInfo[]): TrustLink[] {
  const byPair = new Map<string, TrustLink>();
  for (const entry of inventory) {
    for (const peer of entry.peers) {
      const targetId = peer.registered_node_id || peer.node_id;
      const key = relationshipKey(entry.node.node_id, targetId);
      const previous = byPair.get(key);
      if (!previous || (!trustPresentation(previous.peer.trust_status).healthy && trustPresentation(peer.trust_status).healthy)) {
        byPair.set(key, { key, source: entry.node, target: nodes.find((node) => node.node_id === targetId), peer });
      }
    }
  }
  return [...byPair.values()];
}

export function relationshipAccessSummary(entry: RelationshipInventory | undefined, targetId: string): string {
  if (!entry?.canListGrants) return "Permissões indisponíveis";
  const peer = entry.peers.find((candidate) => (candidate.registered_node_id || candidate.node_id) === targetId);
  const grants = (peer?.grants || []).filter((grant) => grant.enabled);
  const send = grants.filter((grant) => grant.permissions.read && (grant.direction === "send" || grant.direction === "send_receive")).length;
  const receive = grants.filter((grant) => grant.permissions.write && (grant.direction === "receive" || grant.direction === "send_receive")).length;
  if (!send && !receive) return "Sem acesso a arquivos";
  return `Envio: ${send} · Recebimento: ${receive}`;
}
