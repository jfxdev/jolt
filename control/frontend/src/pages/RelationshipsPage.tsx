import {
  Fragment,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Info, Link2, MoreHorizontal, Plus, RefreshCw, ShieldCheck, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { nodeName } from "@/lib/peers";
import {
  connectionForPeer,
  shortFingerprint,
  trustPresentation,
} from "@/lib/trust";
import type {
  Connection,
  NodeInfo,
  PairingInvite,
  PairingRequest,
  TrustPeer,
} from "@/lib/types";
import { useConfirm } from "@/context/ConfirmProvider";
import { useNodes } from "@/context/NodesContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useApiError } from "@/hooks/useApiError";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ButtonGroup } from "@/components/ui/button-group";
import { Card, CardFooter } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Collapsible, CollapsibleContent } from "@/components/ui/collapsible";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { ConnectDialog } from "@/components/workspace/ConnectDialog";
import { ReviewRequestDialog } from "@/components/workspace/ReviewRequestDialog";
import { RelationshipTrustDialog } from "@/components/relationships/RelationshipTrustDialog";
import { relationshipAccessSummary, relationshipLinks } from "@/lib/relationships";

interface NodeTrust {
  node: NodeInfo;
  peers: TrustPeer[];
  invites: PairingInvite[];
  requests: PairingRequest[];
  canListGrants: boolean;
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
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [inventory, setInventory] = useState<NodeTrust[]>([]);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(true);
  const [connectOpen, setConnectOpen] = useState(false);
  const [review, setReview] = useState<PairingRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      await loadPermissions([
        "control-tower/connections",
        ...nodes.flatMap((node) => [
          `nodes/${node.node_id}/peers`,
          `nodes/${node.node_id}/admin/pairing`,
          `nodes/${node.node_id}/grants`,
          `nodes/${node.node_id}/mounts`,
        ]),
      ]);
      // One trust call per node replaces the peers/invites/requests fan-out,
      // and it is the only view that knows what the other side sees.
      const details = await Promise.all(
        nodes.map(async (node): Promise<NodeTrust> => {
          if (!hasPermissionNow(`nodes/${node.node_id}/peers`, "list")) {
            return { node, peers: [], invites: [], requests: [], canListGrants: false };
          }
          const trust = await api.nodeTrust(node.node_id);
          return {
            node,
            peers: trust.peers || [],
            invites: trust.invites || [],
            requests: trust.requests || [],
            canListGrants: trust.can_list_grants,
          };
        }),
      );
      const known = hasPermissionNow("control-tower/connections", "list")
        ? (await api.connections()).items || []
        : [];
      await loadPermissions(
        known.map(
          (connection) => `control-tower/connections/${connection.request_id}`,
        ),
      );
      setInventory(details);
      setConnections(known);
    } catch (error) {
      handleError(error);
    } finally {
      setLoading(false);
    }
  }, [nodes, loadPermissions, hasPermissionNow, handleError]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Each relationship is listed once, from the side that still holds a peer
  // row, so a one-sided revoke stays visible instead of disappearing.
  const links = useMemo(() => relationshipLinks(inventory, nodes), [inventory, nodes]);
  const selectedSource = nodes.find((node) => node.node_id === searchParams.get("source"));
  const selectedTarget = nodes.find((node) => node.node_id === searchParams.get("target"));

  function closeRelationship() {
    setSearchParams((previous) => {
      const next = new URLSearchParams(previous);
      next.delete("source"); next.delete("target");
      return next;
    }, { replace: true });
  }

  const incoming = useMemo<IncomingRequest[]>(
    () =>
      inventory.flatMap(({ node, requests }) =>
        requests
          .filter((request) => request.status === "pending_review")
          .map((request) => ({ node, request })),
      ),
    [inventory],
  );
  const outgoing = useMemo<OutgoingInvite[]>(
    () =>
      inventory.flatMap(({ node, invites }) =>
        invites
          .filter((invite) => invite.status === "pending")
          .map((invite) => ({ node, invite })),
      ),
    [inventory],
  );
  const unfinished = useMemo(
    () =>
      connections.filter(
        (connection) => connection.status === "partially_connected",
      ),
    [connections],
  );
  const connectedNodeIdsByIssuer = useMemo(() => {
    const byNode: Record<string, string[]> = {};
    for (const link of links) {
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
  }, [links]);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    try {
      await action();
      await refresh();
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  function connectionFor(link: (typeof links)[number]) {
    return connectionForPeer(
      connections,
      link.source.node_id,
      link.target?.node_id || link.peer.registered_node_id || link.peer.node_id,
    );
  }

  function canDrive(connection: Connection | null) {
    return (
      connection !== null &&
      hasPermission("control-tower/connections", "sudo") &&
      hasPermission(
        `control-tower/connections/${connection.request_id}`,
        "sudo",
      )
    );
  }

  async function reconcile(connection: Connection) {
    await run(async () => {
      const result = await api.reconcileConnection(connection.request_id);
      toast.success(
        result.status === "connected"
          ? "Conexão reconciliada nos dois nodes."
          : `Reconciliação terminou em ${result.status}.`,
      );
    });
  }

  async function revokeLink(link: (typeof links)[number]) {
    const connection = connectionFor(link);
    const label = link.target?.name || link.peer.name;
    if (!canDrive(connection)) {
      toast.error(
        "Sem pedido de conexão administrável: remova a confiança na aba Confiança de cada node.",
      );
      return;
    }
    if (
      !(await confirm({
        title: `Remover a conexão entre “${link.source.name}” e “${label}”?`,
        description:
          "A confiança é removida nos dois nodes e as transferências relacionadas são canceladas.",
        confirmText: "Remover nos dois nodes",
        destructive: true,
      }))
    )
      return;
    await run(async () => {
      await api.revokeConnection(connection!.request_id);
      toast.success("Conexão removida nos dois nodes.");
    });
  }

  async function revokeInvite(item: OutgoingInvite) {
    if (
      !(await confirm({
        title: "Cancelar este pedido de conexão?",
        confirmText: "Cancelar pedido",
        destructive: true,
      }))
    )
      return;
    await run(async () => {
      await api.revokeInvite(item.node.node_id, item.invite.invite_id);
      toast.success("Pedido cancelado.");
    });
  }

  async function rejectRequest(item: IncomingRequest) {
    if (
      !(await confirm({
        title: `Recusar o pedido de “${item.request.issuer_name}”?`,
        description: "O pedido será removido e a conexão não será criada.",
        confirmText: "Recusar pedido",
        destructive: true,
      }))
    )
      return;
    await run(async () => {
      await api.rejectConnection(item.request.request_id);
      toast.success("Pedido recusado.");
    });
  }

  const healthyCount = links.filter(
    (link) => trustPresentation(link.peer.trust_status).healthy,
  ).length;
  const canConnect = hasPermission("control-tower/connections", "sudo");

  return (
    <div className="grid gap-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Relacionamentos</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            Confiança e acesso a arquivos entre os nodes.
          </p>
        </div>
        <ButtonGroup aria-label="Ações dos relacionamentos">
          <Button variant="outline" size="icon-sm" aria-label="Atualizar relacionamentos" title="Atualizar relacionamentos" disabled={loading} onClick={() => void refresh()}>
            <RefreshCw />
          </Button>
          {canConnect && (
            <Button
              size="sm"
              disabled={nodes.length < 2}
              onClick={() => setConnectOpen(true)}
            >
              <Plus /> Conectar
            </Button>
          )}
        </ButtonGroup>
      </div>

      <div className="flex flex-wrap gap-2">
        <Badge variant="outline"><Link2 /> Conexões saudáveis: {healthyCount}</Badge>
        <Badge variant={incoming.length ? "warning" : "outline"}><ShieldCheck /> Aprovações pendentes: {incoming.length}</Badge>
        <Badge variant="outline"><Plus /> Possibilidades: {Math.max((nodes.length * (nodes.length - 1)) / 2 - healthyCount, 0)}</Badge>
      </div>

      {unfinished.length > 0 && (
        <section className="grid gap-3">
          <div>
            <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
              Inacabadas
            </p>
            <h2 className="text-lg font-semibold">
              Handshakes que não terminaram
            </h2>
          </div>
          {unfinished.map((connection) => (
            <Card
              key={connection.request_id}
              className="flex flex-wrap items-center gap-4 border-destructive/30 p-4"
            >
              <div className="min-w-0 flex-1">
                <p className="font-medium">
                  {nodeName(nodes, connection.issuer_node_id)} →{" "}
                  {nodeName(nodes, connection.target_node_id)}
                </p>
                <p className="text-sm text-muted-foreground">
                  O emissor confiou no alvo, mas o alvo não concluiu a conexão.
                  Criada {formatDate(connection.created_at)}.
                </p>
              </div>
              {canDrive(connection) && (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy}
                  onClick={() => void reconcile(connection)}
                >
                  Reconciliar
                </Button>
              )}
            </Card>
          ))}
        </section>
      )}

      <section className="grid gap-4">
        <div>
          <h2 className="text-lg font-semibold">Conexões entre nodes</h2>
        </div>
        {loading ? (
          <p className="text-sm text-muted-foreground">Carregando conexões…</p>
        ) : links.length ? (
          <div className="grid gap-4">
            {links.map((link) => {
              const presentation = trustPresentation(link.peer.trust_status);
              const connection = connectionFor(link);
              const sourceInventory = inventory.find((entry) => entry.node.node_id === link.source.node_id);
              const targetInventory = inventory.find((entry) => entry.node.node_id === link.target?.node_id);
              const reciprocalPeer = targetInventory?.peers.find((peer) => (peer.registered_node_id || peer.node_id) === link.source.node_id);
              const sides = [
                { node: link.source, name: link.source.name, peer: link.peer, access: relationshipAccessSummary(sourceInventory, link.target?.node_id || link.peer.registered_node_id || link.peer.node_id) },
                { node: link.target, name: link.target?.name || link.peer.name, peer: reciprocalPeer, access: relationshipAccessSummary(targetInventory, link.source.node_id) },
              ];
              return (
                <Card key={link.key} className="gap-0 py-0">
                  <Collapsible open={expanded === link.key}>
                    <div className="grid sm:grid-cols-[minmax(0,1fr)_2.5rem_minmax(0,1fr)]">
                      {sides.map((side, index) => {
                        const state = side.peer ? trustPresentation(side.peer.trust_status) : null;
                        const canReadTrust = !!side.node && hasPermission(`nodes/${side.node.node_id}/peers`, "list");
                        return <Fragment key={index}>
                          {index > 0 && <div aria-hidden="true" className="relative flex items-center justify-center py-5 sm:py-0">
                            <Separator className="absolute inset-x-4 top-1/2 data-horizontal:w-auto sm:hidden" />
                            <Separator orientation="vertical" className="absolute inset-y-0 left-1/2 hidden h-full sm:block" />
                            <span className="relative grid size-9 place-items-center rounded-full border bg-card"><Link2 className="size-5 text-muted-foreground" /></span>
                          </div>}
                          <section aria-label={side.name} className="flex min-w-0 flex-col gap-3 p-4 sm:p-5">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <h3 className="min-w-0 truncate text-base font-semibold" title={side.name}>{side.name}</h3>
                              <Badge variant={state?.variant || (canReadTrust ? "destructive" : "secondary")}>{state?.label || (!side.node ? "Não cadastrado" : canReadTrust ? "Sem conexão" : "Indisponível")}</Badge>
                            </div>
                            <Badge variant="secondary" className="max-w-full whitespace-normal">{side.access}</Badge>
                            {state && !state.healthy && <p className="text-sm text-muted-foreground">{state.explanation}</p>}
                            {!side.peer && <p className="text-sm text-muted-foreground">{!side.node ? "Este node não está cadastrado na Control Tower." : canReadTrust ? "Este lado não tem registro da relação de confiança." : "Você não tem permissão para consultar a confiança deste node."}</p>}
                            <CollapsibleContent id={`relationship-${link.key}-${index}-details`} className="grid gap-2 border-t pt-3 text-xs text-muted-foreground">
                              {side.peer && <>
                                <p>{side.peer.local_role || "peer"} ↔ {side.peer.remote_role || "peer"}{side.peer.cluster_id ? ` · ${side.peer.cluster_id}` : ""}</p>
                                <p>Identidade de {sides[index === 0 ? 1 : 0].name}</p>
                                <code className="break-all">{shortFingerprint(side.peer.fingerprint)}</code>
                              </>}
                            </CollapsibleContent>
                            {side.node && <Button variant="outline" size="sm" className="mt-auto w-fit max-w-full" onClick={() => navigate(`/nodes/${side.node!.node_id}?tab=trust`)}><span className="truncate">Abrir {side.name}</span></Button>}
                          </section>
                        </Fragment>;
                      })}
                    </div>
                    <CardFooter className="flex-wrap justify-between gap-2 border-t px-4 pb-4 [.border-t]:pt-4 sm:px-5">
                      <div className="flex min-w-0 flex-wrap gap-2">
                        <ButtonGroup aria-label={`Ações entre ${link.source.name} e ${link.target?.name || link.peer.name}`}>
                          {link.target && <Button variant="outline" size="sm" onClick={() => setSearchParams({ source: link.source.node_id, target: link.target!.node_id })}>Abrir relação de confiança</Button>}
                          <DropdownMenu>
                            <DropdownMenuTrigger render={<Button variant="outline" size="icon-sm" aria-label={`Mais opções da relação ${link.source.name} e ${link.target?.name || link.peer.name}`} disabled={busy} />}><MoreHorizontal /></DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => setExpanded(expanded === link.key ? null : link.key)}><Info /> {expanded === link.key ? "Ocultar detalhes técnicos" : "Detalhes técnicos"}</DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </ButtonGroup>
                        {presentation.action === "reconcile" && canDrive(connection) && <Button size="sm" disabled={busy} onClick={() => void reconcile(connection!)}>Reconciliar</Button>}
                      </div>
                      {canDrive(connection) && <Button variant="destructive" size="sm" disabled={busy} onClick={() => void revokeLink(link)}><Trash2 /> Remover conexão</Button>}
                    </CardFooter>
                  </Collapsible>
                </Card>
              );
            })}
          </div>
        ) : (
          <Card className="grid gap-3 p-6 text-sm text-muted-foreground">
            Nenhum node conectado ainda.
            {canConnect && (
              <Button
                size="sm"
                className="w-fit"
                disabled={nodes.length < 2}
                onClick={() => setConnectOpen(true)}
              >
                Ver possibilidades de conexão
              </Button>
            )}
          </Card>
        )}
      </section>

      {(incoming.length > 0 || outgoing.length > 0) && (
        <section className="grid gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
              Pendentes
            </p>
            <h2 className="text-lg font-semibold">Pedidos de conexão</h2>
          </div>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {incoming.map((item) => (
              <Card
                key={`request-${item.request.request_id}`}
                className="grid gap-2 p-4"
              >
                <span className="font-mono text-xs uppercase text-muted-foreground">
                  Recebido por {item.node.name}
                </span>
                <strong>{item.request.issuer_name}</strong>
                <p className="text-sm text-muted-foreground">
                  {item.request.purpose || "Sem finalidade informada"}
                </p>
                <div className="flex items-center justify-between gap-2">
                  <Badge variant="secondary">aguardando confirmação</Badge>
                  {canConnect &&
                  hasPermission(
                    `control-tower/connections/${item.request.request_id}`,
                    "sudo",
                  ) ? (
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={busy}
                        onClick={() => void rejectRequest(item)}
                      >
                        Recusar
                      </Button>
                      <Button size="sm" onClick={() => setReview(item.request)}>
                        Aceitar
                      </Button>
                    </div>
                  ) : (
                    <span className="text-xs text-muted-foreground">
                      Aguardando administrador
                    </span>
                  )}
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="justify-self-start"
                  onClick={() =>
                    navigate(`/nodes/${item.node.node_id}?tab=trust`)
                  }
                >
                  Abrir {item.node.name}
                </Button>
              </Card>
            ))}
            {outgoing.map((item) => (
              <Card
                key={`invite-${item.invite.invite_id}`}
                className="grid gap-2 p-4"
              >
                <span className="font-mono text-xs uppercase text-muted-foreground">
                  Enviado por {item.node.name}
                </span>
                <strong>{nodeName(nodes, item.invite.target_node_id)}</strong>
                <p className="text-sm text-muted-foreground">
                  {item.invite.purpose || "Pedido de conexão"}
                </p>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs text-muted-foreground">
                    Expira {formatDate(item.invite.expires_at)}
                  </span>
                  {hasPermission(
                    `nodes/${item.node.node_id}/admin/pairing`,
                    "sudo",
                  ) && (
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={busy}
                      onClick={() => void revokeInvite(item)}
                    >
                      Cancelar
                    </Button>
                  )}
                </div>
              </Card>
            ))}
          </div>
        </section>
      )}

      <ConnectDialog
        open={connectOpen}
        onOpenChange={setConnectOpen}
        connectedNodeIdsByIssuer={connectedNodeIdsByIssuer}
        onConnectionCreated={refresh}
      />
      <ReviewRequestDialog
        request={review}
        onClose={() => setReview(null)}
        onComplete={refresh}
      />
      {selectedSource && selectedTarget && selectedSource.node_id !== selectedTarget.node_id && <RelationshipTrustDialog source={selectedSource} target={selectedTarget} open onClose={closeRelationship} onChanged={() => void refresh()} />}
    </div>
  );
}
