import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { relationshipHref } from "@/lib/relationships";
import {
  ChevronDown,
  ChevronRight,
  Clock3,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type {
  PairingRequest,
  TrustPeer,
} from "@/lib/types";
import { useWorkspace } from "@/context/WorkspaceContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useNodes } from "@/context/NodesContext";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm } from "@/context/ConfirmProvider";
import { formatDate } from "@/lib/format";
import { nodeName } from "@/lib/peers";
import {
  connectionForPeer,
  peersNeedingAttention,
  shortFingerprint,
  trustPresentation,
  type TrustAction,
} from "@/lib/trust";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ReviewRequestDialog } from "@/components/workspace/ReviewRequestDialog";
import { GrantPermissionBadges, TransferDirectionBadge } from "@/components/transfers/TransferAccess";

export function TrustPanel() {
  const {
    nodeId,
    trust,
    trustPeers,
    connections,
    pairingInvites,
    pairingRequests,
    nodePath,
    refreshTrust,
  } = useWorkspace();
  const { hasPermission, loadPermissions } = usePermissions();
  const { nodes } = useNodes();
  const handleError = useApiError();
  const confirm = useConfirm();
  const navigate = useNavigate();
  const [review, setReview] = useState<PairingRequest | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const pendingRequests = useMemo(
    () =>
      pairingRequests.filter((request) => request.status === "pending_review"),
    [pairingRequests],
  );
  const outgoingInvites = useMemo(
    () => pairingInvites.filter((invite) => invite.status === "pending"),
    [pairingInvites],
  );
  const attention = useMemo(
    () => peersNeedingAttention(trustPeers),
    [trustPeers],
  );
  const connectionPaths = useMemo(() => {
    const requestIDs = new Set(pendingRequests.map((r) => r.request_id));
    for (const connection of connections) requestIDs.add(connection.request_id);
    return [...requestIDs].map((id) => `control-tower/connections/${id}`);
  }, [connections, pendingRequests]);

  useEffect(() => {
    if (!connectionPaths.length) return;
    void loadPermissions(connectionPaths);
  }, [connectionPaths, loadPermissions]);

  function canDriveConnection(requestID: string) {
    return (
      hasPermission("control-tower/connections", "sudo") &&
      hasPermission(`control-tower/connections/${requestID}`, "sudo")
    );
  }

  function canReview(request: PairingRequest) {
    return (
      hasPermission(nodePath("admin/pairing"), "sudo") &&
      canDriveConnection(request.request_id)
    );
  }

  async function run(key: string, action: () => Promise<void>) {
    setBusy(key);
    try {
      await action();
      await refreshTrust();
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(null);
    }
  }

  async function reconcile(peer: TrustPeer) {
    const connection = connectionForPeer(connections, nodeId, peer.node_id);
    if (!connection) {
      toast.error(
        "Não há pedido de conexão registrado para reconciliar. Crie uma nova conexão.",
      );
      return;
    }
    await run(`reconcile-${peer.node_id}`, async () => {
      const result = await api.reconcileConnection(connection.request_id);
      toast.success(
        result.status === "connected"
          ? "Conexão reconciliada nos dois nodes."
          : `Reconciliação terminou em ${result.status}.`,
      );
    });
  }

  async function revokeBoth(peer: TrustPeer) {
    const connection = connectionForPeer(connections, nodeId, peer.node_id);
    if (!connection) {
      toast.error(
        "Sem pedido de conexão registrado: remova a confiança em cada node pelo menu do peer.",
      );
      return;
    }
    if (
      !(await confirm({
        title: `Remover a confiança entre este node e “${peer.name}” nos dois lados?`,
        description:
          "Os grants do peer serão desabilitados e as transferências em andamento canceladas nos dois nodes.",
        confirmText: "Remover nos dois nodes",
        destructive: true,
      }))
    )
      return;
    await run(`revoke-${peer.node_id}`, async () => {
      await api.revokeConnection(connection.request_id);
      toast.success("Confiança removida nos dois nodes.");
    });
  }

  async function recreate(peer: TrustPeer) {
    if (
      !(await confirm({
        title: `Recriar a conexão com “${peer.name}”?`,
        description:
          "O convite original já foi consumido, então a confiança é removida nos dois nodes " +
          "e um novo pedido precisa ser enviado em seguida.",
        confirmText: "Remover e recomeçar",
        destructive: true,
      }))
    )
      return;
    const connection = connectionForPeer(connections, nodeId, peer.node_id);
    await run(`recreate-${peer.node_id}`, async () => {
      if (connection) {
        await api.revokeConnection(connection.request_id);
      } else {
        await api.revokePeer(nodeId, peer.node_id);
      }
      toast.success(
        "Confiança removida. Use Conectar para enviar um novo pedido.",
      );
    });
  }

  async function confirmIdentity(peer: TrustPeer) {
    const fingerprint = peer.remote_state ? peer.fingerprint : "";
    toast.info(
      `Confirme a fingerprint atual de ${peer.name} diretamente no node antes de restaurar a confiança.` +
        (fingerprint ? ` Fingerprint registrada: ${fingerprint}` : ""),
    );
  }

  async function revokeLocally(peer: TrustPeer) {
    if (
      !(await confirm({
        title: `Remover a conexão só deste node com “${peer.name}”?`,
        description:
          "O outro node continuará achando que confia neste. Prefira remover nos dois lados.",
        confirmText: "Remover só aqui",
        destructive: true,
      }))
    )
      return;
    await run(`revoke-local-${peer.node_id}`, async () => {
      const result = await api.revokePeer(nodeId, peer.node_id);
      toast.success(
        `Conexão removida deste node. ${result.canceled_jobs || 0} transferência(s) cancelada(s).`,
      );
    });
  }

  function actionButton(peer: TrustPeer, action: TrustAction, label?: string) {
    const connection = connectionForPeer(connections, nodeId, peer.node_id);
    const needsConnection = action === "reconcile" || action === "revoke-both";
    if (needsConnection && (!connection || !canDriveConnection(connection.request_id))) {
      return null;
    }
    const handlers: Partial<Record<TrustAction, () => Promise<void>>> = {
      reconcile: () => reconcile(peer),
      "revoke-both": () => revokeBoth(peer),
      recreate: () => recreate(peer),
      "confirm-identity": () => confirmIdentity(peer),
    };
    const handler = handlers[action];
    if (!handler || !label) return null;
    if (action === "recreate" && !hasPermission(nodePath("peers"), "delete")) {
      return null;
    }
    return (
      <Button
        variant="outline"
        size="sm"
        disabled={busy !== null}
        onClick={() => void handler()}
      >
        {label}
      </Button>
    );
  }

  if (!trust) {
    return (
      <Card className="p-6 text-sm text-muted-foreground">
        Você não tem permissão para ver a confiança deste node.
      </Card>
    );
  }

  return (
    <section className="grid gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">Confiança entre nodes</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            O estado de cada relação é lido nos dois nodes. Uma conexão
            confirmada precisa de autorizações de arquivos, gerenciadas na área de relacionamentos.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" onClick={() => void refreshTrust()}>
            Atualizar
          </Button>
          <Button size="sm" variant="outline" onClick={() => navigate("/relationships")}>Gerenciar relacionamentos</Button>
        </div>
      </div>

      {attention.length > 0 && (
        <div className="grid gap-3">
          <h3 className="text-sm font-medium">Requer atenção</h3>
          <div className="grid gap-3">
            {attention.map((peer) => {
              const presentation = trustPresentation(peer.trust_status);
              return (
                <Card
                  key={peer.node_id}
                  className="flex flex-wrap items-start gap-4 border-destructive/30 p-4"
                >
                  <div className="flex size-10 shrink-0 items-center justify-center rounded-full bg-destructive/10 text-destructive">
                    <ShieldAlert className="size-5" aria-hidden="true" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="font-medium">
                      {peer.name || nodeName(nodes, peer.node_id)} —{" "}
                      {presentation.label}
                    </p>
                    <p className="text-sm text-muted-foreground">
                      {presentation.explanation}
                    </p>
                    {peer.grants?.length > 0 && (
                      <p className="mt-1 text-sm text-muted-foreground">
                        {peer.grants.length} grant(s) ainda configurado(s) para
                        este peer.
                      </p>
                    )}
                  </div>
                  {actionButton(
                    peer,
                    presentation.action,
                    presentation.actionLabel,
                  )}
                </Card>
              );
            })}
          </div>
        </div>
      )}

      {pendingRequests.length > 0 && (
        <div className="grid gap-3">
          <h3 className="text-sm font-medium">Pedidos para confirmar</h3>
          <div className="grid gap-3 md:grid-cols-2">
            {pendingRequests.map((request) => (
              <Card
                key={request.request_id}
                className="flex flex-wrap items-center gap-4 border-primary/30 p-4"
              >
                <div className="flex size-10 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary">
                  <Clock3 className="size-5" aria-hidden="true" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="font-medium">
                    {request.issuer_name} quer se conectar
                  </p>
                  <p className="text-sm text-muted-foreground">
                    {request.purpose || "Sem mensagem adicional."}
                  </p>
                </div>
                {canReview(request) ? (
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={busy !== null}
                      onClick={() =>
                        void run(`reject-${request.request_id}`, async () => {
                          await api.rejectConnection(request.request_id);
                          toast.success("Pedido recusado.");
                        })
                      }
                    >
                      Recusar
                    </Button>
                    <Button size="sm" onClick={() => setReview(request)}>
                      Aceitar pedido
                    </Button>
                  </div>
                ) : (
                  <Badge variant="secondary">Aguardando administrador</Badge>
                )}
              </Card>
            ))}
          </div>
        </div>
      )}

      {outgoingInvites.length > 0 && (
        <div className="grid gap-3">
          <h3 className="text-sm font-medium">Convites enviados</h3>
          <div className="grid gap-3 md:grid-cols-2">
            {outgoingInvites.map((invite) => (
              <Card
                key={invite.invite_id}
                className="flex flex-wrap items-center gap-4 p-4"
              >
                <div className="flex size-10 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground">
                  <Clock3 className="size-5" aria-hidden="true" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="font-medium">
                    Aguardando {nodeName(nodes, invite.target_node_id)}
                  </p>
                  <p className="text-sm text-muted-foreground">
                    {invite.purpose || "Pedido de conexão enviado."} · expira{" "}
                    {formatDate(invite.expires_at)}
                  </p>
                </div>
                {hasPermission(nodePath("admin/pairing"), "sudo") && (
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={busy !== null}
                    onClick={() =>
                      void run(`invite-${invite.invite_id}`, async () => {
                        await api.revokeInvite(nodeId, invite.invite_id);
                        toast.success("Pedido cancelado.");
                      })
                    }
                  >
                    Cancelar
                  </Button>
                )}
              </Card>
            ))}
          </div>
        </div>
      )}

      <div className="grid gap-3">
        <h3 className="text-sm font-medium">
          Peers ({trustPeers.length})
        </h3>
        {trustPeers.length === 0 ? (
          <Card className="flex items-center gap-3 p-5">
            <div className="flex size-10 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground">
              <ShieldCheck className="size-5" aria-hidden="true" />
            </div>
            <div>
              <p className="font-medium">Nenhuma conexão ainda</p>
              <p className="text-sm text-muted-foreground">
                Use Conectar para enviar um pedido a outro node.
              </p>
            </div>
          </Card>
        ) : (
          <Card className="overflow-x-auto p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>Peer</TableHead>
                  <TableHead>Estado</TableHead>
                  <TableHead>Modo e papéis</TableHead>
                  <TableHead>Fingerprint</TableHead>
                  <TableHead>Último contato</TableHead>
                  <TableHead>Grants</TableHead>
                  <TableHead className="text-right">Ações</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {trustPeers.map((peer) => {
                  const presentation = trustPresentation(peer.trust_status);
                  const open = expanded === peer.node_id;
                  return [
                    <TableRow key={peer.node_id}>
                      <TableCell>
                        <button
                          type="button"
                          className="text-muted-foreground"
                          aria-label={open ? "Recolher grants" : "Ver grants"}
                          onClick={() =>
                            setExpanded(open ? null : peer.node_id)
                          }
                        >
                          {open ? (
                            <ChevronDown className="size-4" />
                          ) : (
                            <ChevronRight className="size-4" />
                          )}
                        </button>
                      </TableCell>
                      <TableCell>
                        <p className="font-medium">
                          {peer.name || nodeName(nodes, peer.node_id)}
                        </p>
                        <p className="font-mono text-xs text-muted-foreground">
                          {peer.mtls_endpoint || peer.endpoint || "—"}
                        </p>
                      </TableCell>
                      <TableCell>
                        <Badge variant={presentation.variant}>
                          {presentation.label}
                        </Badge>
                        <p className="mt-1 text-xs text-muted-foreground">
                          aqui: {peer.state}
                          {peer.remote_state
                            ? ` · lá: ${peer.remote_state}`
                            : " · lá: sem registro"}
                        </p>
                      </TableCell>
                      <TableCell className="text-sm">
                        {peer.transfer_mode || "—"}
                        <p className="text-xs text-muted-foreground">
                          {peer.local_role || "?"} ↔ {peer.remote_role || "?"}
                        </p>
                      </TableCell>
                      <TableCell>
                        <button
                          type="button"
                          className="font-mono text-xs text-muted-foreground underline-offset-2 hover:underline"
                          title="Copiar fingerprint"
                          onClick={() => {
                            void navigator.clipboard
                              ?.writeText(peer.fingerprint)
                              .then(() => toast.success("Fingerprint copiada."));
                          }}
                        >
                          {shortFingerprint(peer.fingerprint)}
                        </button>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDate(peer.last_seen_at)}
                        {peer.consecutive_failures ? (
                          <p className="text-xs">
                            {peer.consecutive_failures} falha(s) seguidas
                          </p>
                        ) : null}
                      </TableCell>
                      <TableCell className="text-sm">
                        {trust.can_list_grants
                          ? peer.grants.length
                          : "sem permissão"}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          {peer.registered && <Button variant="outline" size="sm" onClick={() => navigate(relationshipHref(nodeId, peer.registered_node_id || peer.node_id))}>Abrir relação de confiança</Button>}
                          {actionButton(
                            peer,
                            presentation.action,
                            presentation.actionLabel,
                          )}
                          {presentation.healthy &&
                            hasPermission(nodePath("peers"), "delete") && (
                              <Button
                                variant="outline"
                                size="sm"
                                disabled={busy !== null}
                                onClick={() => void revokeBoth(peer)}
                              >
                                Remover
                              </Button>
                            )}
                        </div>
                      </TableCell>
                    </TableRow>,
                    open ? (
                      <TableRow key={`${peer.node_id}-grants`}>
                        <TableCell colSpan={8} className="bg-muted/40">
                          {!trust.can_list_grants ? (
                            <p className="text-sm text-muted-foreground">
                              Você não tem permissão para listar os grants deste
                              node.
                            </p>
                          ) : peer.grants.length === 0 ? (
                            <p className="text-sm text-muted-foreground">
                              Nenhum grant para este peer. Sem grant, a conexão
                              não transfere nada.
                            </p>
                          ) : (
                            <div className="grid gap-2">
                              {peer.grants.map((grant) => (
                                <div
                                  key={grant.grant_id}
                                  className="flex flex-wrap items-center gap-3 rounded-md border border-border px-3 py-2"
                                >
                                  <Badge
                                    variant={
                                      grant.enabled ? "success" : "outline"
                                    }
                                  >
                                    {grant.enabled ? "ativo" : "desabilitado"}
                                  </Badge>
                                  <span className="font-mono text-sm">
                                    {grant.mount_id}:{grant.path}
                                  </span>
                                  <TransferDirectionBadge direction={grant.direction} />
                                  <GrantPermissionBadges value={grant.permissions} />
                                  {!Object.values(grant.permissions).some(Boolean) && <span className="text-sm text-muted-foreground">Sem permissões</span>}
                                  {grant.visible_to_peer && <span className="text-sm text-muted-foreground">Visível ao peer</span>}
                                </div>
                              ))}
                            </div>
                          )}
                          {hasPermission(nodePath("peers"), "delete") &&
                            presentation.healthy && (
                              <div className="mt-3">
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  disabled={busy !== null}
                                  onClick={() => void revokeLocally(peer)}
                                >
                                  Remover só neste node
                                </Button>
                              </div>
                            )}
                        </TableCell>
                      </TableRow>
                    ) : null,
                  ];
                })}
              </TableBody>
            </Table>
          </Card>
        )}
      </div>

      <ReviewRequestDialog
        request={review}
        onClose={() => setReview(null)}
        onComplete={refreshTrust}
      />
    </section>
  );
}
