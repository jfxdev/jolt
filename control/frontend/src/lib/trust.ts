import type { Connection, TrustPeer, TrustStatus } from "./types";

/** The single action that resolves a given trust status. */
export type TrustAction =
  | "none"
  | "reconcile"
  | "recreate"
  | "confirm-identity"
  | "revoke-both"
  | "register-node"
  | "wait";

export interface TrustPresentation {
  label: string;
  /** One sentence naming what actually happened, not a generic warning. */
  explanation: string;
  variant: "success" | "secondary" | "destructive" | "outline" | "warning";
  action: TrustAction;
  actionLabel?: string;
  healthy: boolean;
}

const presentations: Record<string, TrustPresentation> = {
  connected: {
    label: "conectada",
    explanation: "Os dois nodes confiam um no outro com a identidade atual.",
    variant: "success",
    action: "none",
    healthy: true,
  },
  revoked_by_peer: {
    label: "revogada pelo outro node",
    explanation:
      "O outro node removeu esta conexão. Ele recusa o nosso certificado no handshake, " +
      "então nenhuma transferência funciona — mesmo que este lado ainda pareça confiável.",
    variant: "destructive",
    action: "recreate",
    actionLabel: "Recriar conexão",
    healthy: false,
  },
  missing_on_peer: {
    label: "não confirmada pelo outro node",
    explanation:
      "Este node confia no peer, mas o peer não tem registro desta conexão. " +
      "O handshake não terminou.",
    variant: "destructive",
    action: "reconcile",
    actionLabel: "Reconciliar",
    healthy: false,
  },
  identity_changed: {
    label: "identidade alterada",
    explanation:
      "A fingerprint do peer mudou sem handover assinado. Confirme a nova identidade " +
      "manualmente antes de voltar a confiar.",
    variant: "destructive",
    action: "confirm-identity",
    actionLabel: "Confirmar identidade",
    healthy: false,
  },
  unreachable: {
    label: "inalcançável",
    explanation:
      "Os dois lados confiam um no outro, mas o peer não responde ao heartbeat. " +
      "É problema de rede ou de endpoint, não de confiança.",
    variant: "warning",
    action: "none",
    healthy: false,
  },
  revoked: {
    label: "revogada aqui",
    explanation:
      "Este node revogou a confiança. Os grants do peer estão desabilitados.",
    variant: "outline",
    action: "revoke-both",
    actionLabel: "Remover nos dois nodes",
    healthy: false,
  },
  not_registered: {
    label: "peer fora da Control Tower",
    explanation:
      "O peer confia neste node, mas não está cadastrado aqui, então o outro lado " +
      "não pode ser verificado.",
    variant: "secondary",
    action: "register-node",
    actionLabel: "Cadastrar node",
    healthy: false,
  },
  remote_unreadable: {
    label: "outro lado ilegível",
    explanation:
      "Não foi possível ler os peers do outro node, então a reciprocidade não pode " +
      "ser confirmada.",
    variant: "secondary",
    action: "wait",
    healthy: false,
  },
};

const fallback: TrustPresentation = {
  label: "estado desconhecido",
  explanation: "A Control Tower não reconheceu este estado de confiança.",
  variant: "secondary",
  action: "wait",
  healthy: false,
};

export function trustPresentation(status: TrustStatus): TrustPresentation {
  return presentations[status] || fallback;
}

export function isHealthyTrust(peer: TrustPeer): boolean {
  return trustPresentation(peer.trust_status).healthy;
}

/** Peers whose relationship needs an operator decision. */
export function peersNeedingAttention(peers: TrustPeer[]): TrustPeer[] {
  return peers.filter((peer) => !isHealthyTrust(peer));
}

/**
 * The connection row that still governs a peer relationship, used to drive
 * reconcile and bilateral revoke. Terminal rows are ignored because they can no
 * longer be driven.
 */
export function connectionForPeer(
  connections: Connection[],
  nodeId: string,
  peerNodeId: string,
): Connection | null {
  const pair = [nodeId, peerNodeId];
  const candidates = connections.filter(
    (connection) =>
      pair.includes(connection.issuer_node_id) &&
      pair.includes(connection.target_node_id) &&
      connection.status !== "rejected",
  );
  if (!candidates.length) return null;
  return candidates.reduce((newest, current) =>
    current.created_at > newest.created_at ? current : newest,
  );
}

export function shortFingerprint(fingerprint: string): string {
  if (fingerprint.length <= 24) return fingerprint;
  return `${fingerprint.slice(0, 11)}…${fingerprint.slice(-11)}`;
}
