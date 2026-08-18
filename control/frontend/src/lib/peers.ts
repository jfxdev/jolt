import type { NodeInfo, Peer } from "./types";

const ACTIVE_PEER_STATES = [
  "trusted",
  "unknown",
  "online",
  "offline",
  "degraded",
];

/** Peers that count as reachable/trusted for grant and transfer flows. */
export function activePeers(peers: Peer[]): Peer[] {
  return peers.filter((peer) => ACTIVE_PEER_STATES.includes(peer.state));
}

export function nodeName(nodes: NodeInfo[], id: string): string {
  return nodes.find((node) => node.node_id === id)?.name || id.slice(0, 12);
}

/** Other nodes that are trusted peers of the selected node (transfer sources). */
export function remoteSourceNodes(
  nodes: NodeInfo[],
  peers: Peer[],
  selectedNodeId: string,
): NodeInfo[] {
  const trustedIds = new Set(activePeers(peers).map((peer) => peer.node_id));
  return nodes.filter(
    (node) => node.node_id !== selectedNodeId && trustedIds.has(node.node_id),
  );
}
