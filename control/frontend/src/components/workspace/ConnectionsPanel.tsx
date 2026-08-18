import { useState } from "react";
import { api } from "@/lib/api";
import type { Grant, PairingRequest, Peer } from "@/lib/types";
import { useWorkspace } from "@/context/WorkspaceContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useNodes } from "@/context/NodesContext";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm, usePrompt } from "@/context/ConfirmProvider";
import { activePeers, nodeName } from "@/lib/peers";
import { formatDate } from "@/lib/format";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { CreateGrantDialog } from "@/components/workspace/CreateGrantDialog";
import { ReviewRequestDialog } from "@/components/workspace/ReviewRequestDialog";

export function ConnectionsPanel() {
  const {
    nodeId,
    mounts,
    peers,
    grants,
    pairingInvites,
    pairingRequests,
    nodePath,
    refreshPairing,
  } = useWorkspace();
  const { hasPermission } = usePermissions();
  const { nodes } = useNodes();
  const handleError = useApiError();
  const confirm = useConfirm();
  const prompt = usePrompt();
  const [grantOpen, setGrantOpen] = useState(false);
  const [review, setReview] = useState<PairingRequest | null>(null);

  const trusted = activePeers(peers);

  async function revokePeer(peer: Peer) {
    if (
      !(await confirm({
        title: `Revogar o peer “${peer.name}”?`,
        description:
          "Seus grants serão desabilitados e as transferências relacionadas serão canceladas.",
        confirmText: "Revogar",
        destructive: true,
      }))
    )
      return;
    try {
      const result = await api.revokePeer(nodeId, peer.node_id);
      await refreshPairing();
      toast.success(
        `Peer revogado. ${result.canceled_jobs || 0} job(s) cancelado(s).`,
      );
    } catch (error) {
      handleError(error);
    }
  }

  async function updatePeerEndpoints(peer: Peer) {
    if (peer.state === "revoked") return;
    const endpoint = await prompt({
      title: "Endpoint HTTP de controle do peer",
      defaultValue: peer.endpoint,
    });
    if (endpoint === null) return;
    const mtlsEndpoint = await prompt({
      title: "Endpoint HTTPS mTLS do peer",
      defaultValue: peer.mtls_endpoint,
    });
    if (mtlsEndpoint === null) return;
    try {
      await api.updatePeerEndpoints(nodeId, peer.node_id, {
        endpoint,
        mtls_endpoint: mtlsEndpoint,
      });
      await refreshPairing();
      toast.success(
        "Endpoints atualizados. O peer será revalidado por heartbeat autenticado.",
      );
    } catch (error) {
      handleError(error);
    }
  }

  async function recoverPeerIdentity(peer: Peer) {
    if (peer.state !== "identity_changed") return;
    const fingerprint = await prompt({
      title: `Revalidar identidade de “${peer.name}”`,
      description:
        "Confirme a NOVA fingerprint do peer. Compare-a por um canal confiável antes de continuar.",
      label: "Fingerprint",
    });
    if (!fingerprint) return;
    if (
      !(await confirm({
        title: `Confiar novamente em “${peer.name}”?`,
        description: `Usando a fingerprint ${fingerprint}.`,
        confirmText: "Confiar",
      }))
    )
      return;
    try {
      await api.recoverPeerIdentity(nodeId, peer.node_id, fingerprint.trim());
      await refreshPairing();
      toast.success(
        "Nova identidade registrada. O peer será validado por mTLS antes de voltar a ficar online.",
      );
    } catch (error) {
      handleError(error);
    }
  }

  async function removeGrant(grant: Grant) {
    if (
      !(await confirm({
        title: `Revogar grant para ${grant.path === "." ? "todo o mount" : grant.path}?`,
        confirmText: "Revogar",
        destructive: true,
      }))
    )
      return;
    try {
      await api.deleteGrant(nodeId, grant.grant_id);
      await refreshPairing();
      toast.success("Grant revogado.");
    } catch (error) {
      handleError(error);
    }
  }

  async function revokeInvite(inviteId: string) {
    if (
      !(await confirm({
        title: "Revogar este pedido de conexão?",
        confirmText: "Revogar",
        destructive: true,
      }))
    )
      return;
    try {
      await api.revokeInvite(nodeId, inviteId);
      await refreshPairing();
      toast.success("Pedido revogado.");
    } catch (error) {
      handleError(error);
    }
  }

  const empty =
    !pairingInvites.length &&
    !pairingRequests.length &&
    !peers.length &&
    !grants.length;

  return (
    <section className="grid gap-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Confiança
          </p>
          <h2 className="text-lg font-semibold">Conexões e grants</h2>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" onClick={() => refreshPairing()}>
            Atualizar
          </Button>
          {trusted.length > 0 &&
            mounts.length > 0 &&
            hasPermission(nodePath("grants"), "create") && (
              <Button size="sm" onClick={() => setGrantOpen(true)}>
                Novo grant
              </Button>
            )}
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {peers.map((peer) => (
          <Card key={peer.node_id} className="grid gap-2 p-4">
            <span className="font-mono text-xs uppercase text-muted-foreground">
              {peer.state === "revoked" ? "Peer revogado" : "Peer confiável"}
            </span>
            <strong>{peer.name}</strong>
            <code className="truncate text-xs text-muted-foreground">
              {peer.fingerprint}
            </code>
            <p className="text-sm text-muted-foreground">
              {peer.local_role} ↔ {peer.remote_role}
            </p>
            <div className="flex flex-wrap items-center gap-1">
              <span className="mr-auto text-xs text-muted-foreground">
                {peer.cluster_id || peer.transfer_mode}
              </span>
              {peer.state === "identity_changed" &&
                hasPermission(nodePath("peers"), "update") && (
                  <Button
                    size="sm"
                    onClick={() => recoverPeerIdentity(peer)}
                  >
                    Revalidar identidade
                  </Button>
                )}
              {peer.state !== "revoked" &&
                hasPermission(nodePath("peers"), "update") && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => updatePeerEndpoints(peer)}
                  >
                    Endpoints
                  </Button>
                )}
              {peer.state !== "revoked" &&
              hasPermission(nodePath("peers"), "delete") ? (
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => revokePeer(peer)}
                >
                  Revogar
                </Button>
              ) : peer.state === "revoked" ? (
                <Badge variant="secondary">{peer.state}</Badge>
              ) : null}
            </div>
          </Card>
        ))}

        {grants.map((grant) => (
          <Card key={grant.grant_id} className="grid gap-2 p-4">
            <span className="font-mono text-xs uppercase text-muted-foreground">
              Transfer Path Grant
            </span>
            <strong>
              {mounts.find((m) => m.mount_id === grant.mount_id)?.name ||
                grant.mount_id}{" "}
              / {grant.path === "." ? "raiz" : grant.path}
            </strong>
            <p className="text-sm text-muted-foreground">
              {grant.direction} ·{" "}
              {grant.conflict_policies.join(", ") ||
                "sem política de conflito local"}
            </p>
            <div className="flex items-center gap-2">
              <span className="mr-auto text-xs text-muted-foreground">
                {peers.find((p) => p.node_id === grant.peer_node_id)?.name ||
                  grant.peer_node_id}
              </span>
              {hasPermission(nodePath("grants"), "delete") && (
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => removeGrant(grant)}
                >
                  Revogar
                </Button>
              )}
            </div>
          </Card>
        ))}

        {pairingRequests.map((request) => (
          <Card key={request.request_id} className="grid gap-2 p-4">
            <span className="font-mono text-xs uppercase text-muted-foreground">
              Recebido
            </span>
            <strong>{request.issuer_name}</strong>
            <code className="truncate text-xs text-muted-foreground">
              {request.issuer_fingerprint}
            </code>
            <p className="text-sm text-muted-foreground">
              {request.purpose || "Sem finalidade informada"}
            </p>
            <div className="flex items-center gap-2">
              <span className="mr-auto text-xs text-muted-foreground">
                {request.transfer_mode}
              </span>
              {request.status === "pending_review" &&
              hasPermission(nodePath("admin/pairing"), "sudo") ? (
                <Button size="sm" onClick={() => setReview(request)}>
                  Revisar
                </Button>
              ) : (
                <Badge variant="secondary">{request.status}</Badge>
              )}
            </div>
          </Card>
        ))}

        {pairingInvites.map((invite) => (
          <Card key={invite.invite_id} className="grid gap-2 p-4">
            <span className="font-mono text-xs uppercase text-muted-foreground">
              Enviado para {nodeName(nodes, invite.target_node_id)}
            </span>
            <strong>{invite.purpose || "Pedido de conexão"}</strong>
            <p className="text-sm text-muted-foreground">
              {invite.issuer_role} → {invite.invitee_role}
            </p>
            <div className="flex items-center gap-2">
              <span className="mr-auto text-xs text-muted-foreground">
                Expira {formatDate(invite.expires_at)}
              </span>
              {invite.status === "pending" &&
              hasPermission(nodePath("admin/pairing"), "sudo") ? (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => revokeInvite(invite.invite_id)}
                >
                  Revogar
                </Button>
              ) : (
                <Badge variant="secondary">{invite.status}</Badge>
              )}
            </div>
          </Card>
        ))}

        {empty && (
          <p className="py-6 text-sm text-muted-foreground">
            Nenhum pedido, peer ou grant neste node.
          </p>
        )}
      </div>

      <p className="text-xs text-muted-foreground">
        Pedidos pendentes não concedem acesso. Mounts e grants continuam
        separados e precisam de autorização explícita.
      </p>

      <CreateGrantDialog open={grantOpen} onOpenChange={setGrantOpen} />
      <ReviewRequestDialog request={review} onClose={() => setReview(null)} />
    </section>
  );
}
