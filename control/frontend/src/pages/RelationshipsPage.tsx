import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { Link2, Plus, RefreshCw, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { nodeName } from "@/lib/peers";
import type { NodeInfo, PairingInvite, PairingRequest, Peer } from "@/lib/types";
import { useConfirm } from "@/context/ConfirmProvider";
import { useNodes } from "@/context/NodesContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useApiError } from "@/hooks/useApiError";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { RequestConnectionDialog } from "@/components/workspace/RequestConnectionDialog";
import { ReviewRequestDialog } from "@/components/workspace/ReviewRequestDialog";

interface NodeConnections {
  node: NodeInfo;
  peers: Peer[];
  invites: PairingInvite[];
  requests: PairingRequest[];
}

interface ConnectedLink {
  key: string;
  source: NodeInfo;
  target: NodeInfo | undefined;
  peer: Peer;
  reciprocal?: Peer;
}

interface IncomingRequest {
  node: NodeInfo;
  request: PairingRequest;
}

interface OutgoingInvite {
  node: NodeInfo;
  invite: PairingInvite;
}

export default function RelationshipsPage() {
  const { nodes } = useNodes();
  const { hasPermission, hasPermissionNow, loadPermissions } = usePermissions();
  const handleError = useApiError();
  const confirm = useConfirm();
  const [inventory, setInventory] = useState<NodeConnections[]>([]);
  const [loading, setLoading] = useState(true);
  const [connectOpen, setConnectOpen] = useState(false);
  const [review, setReview] = useState<PairingRequest | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const paths = nodes.flatMap((node) => [
        `nodes/${node.node_id}/peers`,
        `nodes/${node.node_id}/admin/pairing`,
      ]);
      await loadPermissions(paths);

      const details = await Promise.all(
        nodes.map(async (node): Promise<NodeConnections> => {
          const peerPath = `nodes/${node.node_id}/peers`;
          const pairingPath = `nodes/${node.node_id}/admin/pairing`;
          const [peerResult, inviteResult, requestResult] = await Promise.all([
            hasPermissionNow(peerPath, "list")
              ? api.peers(node.node_id)
              : Promise.resolve({ items: [] as Peer[] }),
            hasPermissionNow(pairingPath, "sudo")
              ? api.pairingInvites(node.node_id)
              : Promise.resolve({ items: [] as PairingInvite[] }),
            hasPermissionNow(pairingPath, "sudo")
              ? api.pairingRequests(node.node_id)
              : Promise.resolve({ items: [] as PairingRequest[] }),
          ]);
          return {
            node,
            peers: peerResult.items || [],
            invites: inviteResult.items || [],
            requests: requestResult.items || [],
          };
        }),
      );
      setInventory(details);
    } catch (error) {
      handleError(error);
    } finally {
      setLoading(false);
    }
  }, [nodes, loadPermissions, hasPermissionNow, handleError]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const connected = useMemo(() => {
    const links = new Map<string, ConnectedLink>();
    for (const entry of inventory) {
      for (const peer of entry.peers) {
        if (peer.state === "revoked") continue;
        const key = [entry.node.node_id, peer.node_id].sort().join(":");
        const previous = links.get(key);
        if (previous) {
          previous.reciprocal = peer;
        } else {
          links.set(key, {
            key,
            source: entry.node,
            target: nodes.find((node) => node.node_id === peer.node_id),
            peer,
          });
        }
      }
    }
    return [...links.values()];
  }, [inventory, nodes]);

  const incoming = useMemo<IncomingRequest[]>(
    () =>
      inventory.flatMap(({ node, requests }) =>
        requests.map((request) => ({ node, request })),
      ),
    [inventory],
  );
  const outgoing = useMemo<OutgoingInvite[]>(
    () =>
      inventory.flatMap(({ node, invites }) =>
        invites.map((invite) => ({ node, invite })),
      ),
    [inventory],
  );
  const connectedNodeIdsByIssuer = useMemo(() => {
    const byNode: Record<string, string[]> = {};
    for (const link of connected) {
      if (!link.target) continue;
      byNode[link.source.node_id] = [
        ...(byNode[link.source.node_id] || []),
        link.target.node_id,
      ];
      byNode[link.target.node_id] = [
        ...(byNode[link.target.node_id] || []),
        link.source.node_id,
      ];
    }
    return byNode;
  }, [connected]);

  async function revokeLink(link: ConnectedLink) {
    const sides = [
      { node: link.source, peer: link.peer },
      ...(link.reciprocal && link.target
        ? [{ node: link.target, peer: link.reciprocal }]
        : []),
    ].filter(({ node }) =>
      hasPermission(`nodes/${node.node_id}/peers`, "delete"),
    );
    if (!sides.length) return;
    if (
      !(await confirm({
        title: `Revogar a confiança entre “${link.source.name}” e “${link.target?.name || link.peer.name}”?`,
        description:
          "Os grants serão desabilitados e as transferências relacionadas serão canceladas.",
        confirmText: "Revogar",
        destructive: true,
      }))
    )
      return;
    try {
      await Promise.all(
        sides.map(({ node, peer }) => api.revokePeer(node.node_id, peer.node_id)),
      );
      await refresh();
      toast.success("Confiança revogada nos nodes disponíveis.");
    } catch (error) {
      handleError(error);
    }
  }

  async function revokeInvite(item: OutgoingInvite) {
    if (
      !(await confirm({
        title: "Revogar este pedido de conexão?",
        confirmText: "Revogar",
        destructive: true,
      }))
    )
      return;
    try {
      await api.revokeInvite(item.node.node_id, item.invite.invite_id);
      await refresh();
      toast.success("Pedido revogado.");
    } catch (error) {
      handleError(error);
    }
  }

  const canConnect = hasPermission("control-tower/connections", "create");

  return (
    <div className="grid gap-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Rede de confiança
          </p>
          <h1 className="text-3xl font-semibold tracking-tight">Connections</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            Gerencie todos os vínculos de confiança entre nodes em um só lugar.
            Conexões não compartilham mounts nem concedem acesso por si só.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => void refresh()}>
            <RefreshCw /> Atualizar
          </Button>
          {canConnect && (
            <Button size="sm" disabled={nodes.length < 2} onClick={() => setConnectOpen(true)}>
              <Plus /> Connect
            </Button>
          )}
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <Metric label="Nodes conectados" value={connected.length} icon={<Link2 />} />
        <Metric label="Aprovação pendente" value={incoming.filter(({ request }) => request.status === "pending_review").length} icon={<ShieldCheck />} />
        <Metric label="Possibilidades" value={Math.max((nodes.length * (nodes.length - 1)) / 2 - connected.length, 0)} icon={<Plus />} />
      </div>

      <section className="grid gap-4">
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Conectados</p>
          <h2 className="text-lg font-semibold">Nodes com confiança estabelecida</h2>
        </div>
        {loading ? (
          <p className="text-sm text-muted-foreground">Carregando conexões…</p>
        ) : connected.length ? (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {connected.map((link) => {
              const peerState = link.reciprocal?.state || link.peer.state;
              const canRevoke = [link.source, link.target].some(
                (node) => node && hasPermission(`nodes/${node.node_id}/peers`, "delete"),
              );
              return (
                <Card key={link.key} className="grid gap-3 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <strong>{link.source.name}</strong>
                      <p className="text-sm text-muted-foreground">↔ {link.target?.name || link.peer.name}</p>
                    </div>
                    <Badge variant={peerState === "identity_changed" ? "destructive" : "secondary"}>
                      {peerState === "identity_changed" ? "identidade alterada" : "confiável"}
                    </Badge>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {link.peer.local_role || "peer"} ↔ {link.peer.remote_role || "peer"}
                    {link.peer.cluster_id ? ` · ${link.peer.cluster_id}` : ""}
                  </p>
                  <code className="truncate text-xs text-muted-foreground">{link.peer.fingerprint}</code>
                  {canRevoke && (
                    <Button variant="destructive" size="sm" className="justify-self-start" onClick={() => void revokeLink(link)}>
                      Revogar confiança
                    </Button>
                  )}
                </Card>
              );
            })}
          </div>
        ) : (
          <Card className="grid gap-3 p-6 text-sm text-muted-foreground">
            Nenhum node conectado ainda.
            {canConnect && <Button size="sm" className="w-fit" disabled={nodes.length < 2} onClick={() => setConnectOpen(true)}>Ver possibilidades de conexão</Button>}
          </Card>
        )}
      </section>

      {(incoming.length > 0 || outgoing.length > 0) && (
        <section className="grid gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Pendentes</p>
            <h2 className="text-lg font-semibold">Pedidos de conexão</h2>
          </div>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {incoming.map((item) => (
              <Card key={`request-${item.request.request_id}`} className="grid gap-2 p-4">
                <span className="font-mono text-xs uppercase text-muted-foreground">Recebido por {item.node.name}</span>
                <strong>{item.request.issuer_name}</strong>
                <p className="text-sm text-muted-foreground">{item.request.purpose || "Sem finalidade informada"}</p>
                <div className="flex items-center justify-between gap-2">
                  <Badge variant="secondary">{item.request.status}</Badge>
                  {item.request.status === "pending_review" && hasPermission("control-tower/connections", "execute") && (
                    <Button size="sm" onClick={() => setReview(item.request)}>Revisar</Button>
                  )}
                </div>
              </Card>
            ))}
            {outgoing.map((item) => (
              <Card key={`invite-${item.invite.invite_id}`} className="grid gap-2 p-4">
                <span className="font-mono text-xs uppercase text-muted-foreground">Enviado por {item.node.name}</span>
                <strong>{nodeName(nodes, item.invite.target_node_id)}</strong>
                <p className="text-sm text-muted-foreground">{item.invite.purpose || "Pedido de conexão"}</p>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs text-muted-foreground">Expira {formatDate(item.invite.expires_at)}</span>
                  {item.invite.status === "pending" && hasPermission(`nodes/${item.node.node_id}/admin/pairing`, "sudo") && (
                    <Button variant="outline" size="sm" onClick={() => void revokeInvite(item)}>Revogar</Button>
                  )}
                </div>
              </Card>
            ))}
          </div>
        </section>
      )}

      <RequestConnectionDialog
        open={connectOpen}
        onOpenChange={setConnectOpen}
        connectedNodeIdsByIssuer={connectedNodeIdsByIssuer}
        onConnectionCreated={refresh}
      />
      <ReviewRequestDialog request={review} onClose={() => setReview(null)} onComplete={refresh} />
    </div>
  );
}

function Metric({ label, value, icon }: { label: string; value: number; icon: ReactNode }) {
  return (
    <Card className="flex items-center justify-between gap-3 p-5">
      <div className="grid gap-1">
        <span className="text-sm text-muted-foreground">{label}</span>
        <strong className="text-2xl font-semibold">{value}</strong>
      </div>
      <span className="text-muted-foreground">{icon}</span>
    </Card>
  );
}
