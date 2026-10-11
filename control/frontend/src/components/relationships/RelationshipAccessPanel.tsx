import { Fragment, useEffect, useState } from "react";
import { Folder, MoreHorizontal, Pencil, Plus, SlidersHorizontal, Trash2, X } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { Grant, Mount, NodeInfo, TrustPeer } from "@/lib/types";
import { matchingTransferGrant, transferGrantAuthorization, transferSourceAccess, transferSourceFolder } from "@/lib/transfer-access";
import { usePermissions } from "@/context/PermissionsContext";
import { useConfirm } from "@/context/ConfirmProvider";
import { useApiError } from "@/hooks/useApiError";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ButtonGroup } from "@/components/ui/button-group";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Collapsible, CollapsibleContent } from "@/components/ui/collapsible";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { CONFLICT_OPTIONS, GrantFormFields, type GrantFormValue } from "@/components/workspace/GrantFormFields";
import { GrantPermissionBadges, TransferDirectionBadge, transferDirectionLabel } from "@/components/transfers/TransferAccess";

export interface RelationshipSelection {
  mount: Mount;
  paths: string[];
  operation: "copy" | "move";
}

interface Props {
  node: NodeInfo;
  otherName: string;
  peer: TrustPeer | undefined;
  canListGrants: boolean;
  error?: string;
  defaultDirection: "send" | "receive";
  selection?: RelationshipSelection;
  onChanged: () => Promise<void>;
}

export function RelationshipAccessPanel({ node, otherName, peer, canListGrants, error, defaultDirection, selection, onChanged }: Props) {
  const { hasPermission } = usePermissions();
  const confirm = useConfirm();
  const handleError = useApiError();
  const [mounts, setMounts] = useState<Mount[]>([]);
  const [mountError, setMountError] = useState("");
  const [form, setForm] = useState<GrantFormValue | null>(null);
  const [editing, setEditing] = useState<Grant | null>(null);
  const [busy, setBusy] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const grantsPath = `nodes/${node.node_id}/grants`;
  const canCreate = hasPermission(grantsPath, "create");
  const canUpdate = hasPermission(grantsPath, "update");
  const canListMounts = hasPermission(`nodes/${node.node_id}/mounts`, "list");

  useEffect(() => {
    if (!canListMounts) return;
    let active = true;
    void api.mounts(node.node_id)
      .then((result) => { if (active) setMounts(result.items || []); })
      .catch((failure) => { if (active) setMountError((failure as Error).message); });
    return () => { active = false; };
  }, [node.node_id, canListMounts]);

  function start(grant?: Grant) {
    if (!peer) return;
    setEditing(grant || null);
    setForm(grant ? grantValue(grant) : transferGrantAuthorization(
      peer.node_id,
      selection?.mount.mount_id || mounts.find((mount) => mount.enabled !== false && (defaultDirection === "send" || mount.mode === "read_write"))?.mount_id || "",
      selection ? transferSourceFolder(selection.paths) : "",
      defaultDirection,
      selection?.operation || "copy",
      "fail",
    ));
  }

  function closeForm() {
    if (busy) return;
    setForm(null);
    setEditing(null);
  }

  async function run(action: () => Promise<unknown>, message: string) {
    setBusy(true);
    try {
      await action();
      setForm(null);
      setEditing(null);
      await onChanged();
      toast.success(message);
    } catch (failure) { handleError(failure); }
    finally { setBusy(false); }
  }

  async function save() {
    if (!form || !peer) return;
    const existing = editing || matchingTransferGrant(peer.grants || [], peer.node_id, form.mount_id, form.path, form.direction);
    if (existing ? !canUpdate : !canCreate) {
      toast.error(`Você não tem permissão para ${existing ? "atualizar" : "criar"} autorizações em ${node.name}.`);
      return;
    }
    // Keep grant IDs internal; the form is already bound to this exact peer.
    const input = { ...form, peer_node_id: peer.node_id };
    await run(() => existing ? api.updateGrant(node.node_id, existing.grant_id, input) : api.createGrant(node.node_id, input), `Permissões de ${node.name} atualizadas.`);
  }

  async function remove(grant: Grant) {
    if (!(await confirm({ title: `Remover esta autorização em ${node.name}?`, description: `O acesso de ${otherName} à pasta autorizada será removido. A confiança entre os nodes será mantida.`, confirmText: "Remover autorização", destructive: true }))) return;
    await run(() => api.deleteGrant(node.node_id, grant.grant_id), "Autorização removida.");
  }

  const grants = canListGrants ? peer?.grants || [] : [];
  const sourceAccess = selection && canListGrants && peer
    ? transferSourceAccess(grants, peer.node_id, selection.mount.mount_id, selection.paths, selection.operation)
    : undefined;
  const eligibleMounts = mounts.filter((mount) => mount.enabled !== false && (form?.direction === "send" || mount.mode === "read_write"));
  const duplicate = form && !editing && peer ? matchingTransferGrant(grants, peer.node_id, form.mount_id, form.path, form.direction) : undefined;

  return <section className="grid min-w-0 content-start gap-3">
    <div className="flex flex-wrap items-start justify-between gap-2">
      <div className="flex items-center gap-2"><h3 className="font-semibold">{node.name}</h3>{canListGrants && <Badge variant="secondary" aria-label={`${grants.length} autorizações em ${node.name}`} title="Autorizações">{grants.length}</Badge>}</div>
      {peer && canCreate && !form && <Button type="button" size="sm" variant="outline" aria-label={`Adicionar autorização em ${node.name}`} disabled={busy || !canListMounts || !!mountError || peer.trust_status !== "connected"} onClick={() => start()}><Plus /> Adicionar</Button>}
    </div>
    {sourceAccess?.status === "removal_missing" && <div role="status" className="grid gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
      <p className="text-sm font-medium">A origem permite copiar. Mover precisa de mais uma permissão.</p>
      <p className="text-xs text-muted-foreground">Permita a remoção dos arquivos de origem ao mover entre hosts no envio de {node.name} · {selection!.mount.name}. A origem só será removida após validar a transferência por SHA-256.</p>
      {canUpdate && <Button type="button" size="sm" variant="outline" className="w-fit" disabled={busy || !!form || !canListMounts || !!mountError} onClick={() => start(sourceAccess.grant)}>Revisar permissão para mover</Button>}
    </div>}
    {error ? <p role="alert" className="text-sm text-muted-foreground">{error}</p> : !canListGrants ? <p className="text-sm text-muted-foreground">Você não tem permissão para listar as autorizações deste node.</p> : !grants.length ? <p className="text-sm text-muted-foreground">Nenhuma autorização de arquivos configurada.</p> : <div className="rounded-lg border">
      {grants.map((grant, index) => {
        const mountName = mounts.find((mount) => mount.mount_id === grant.mount_id)?.name || grant.mount_id;
        const label = `${transferDirectionLabel(grant.direction)} · ${mountName} em ${node.name}`;
        return <Fragment key={grant.grant_id}>
          {index > 0 && <Separator />}
          <Collapsible open={expanded === grant.grant_id} className={`grid gap-3 p-3 first:rounded-t-lg last:rounded-b-lg ${grant.enabled ? "" : "bg-muted/30"}`}>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-1">
              <TransferDirectionBadge direction={grant.direction} />
              <GrantPermissionBadges value={grant.permissions} />
            </div>
            <div className="ml-auto flex shrink-0 items-center gap-3">
              <Switch checked={grant.enabled} disabled={!canUpdate || busy || !!form} aria-label={`Ativar autorização: ${label}`} title={grant.enabled ? "Autorização ativa" : "Autorização desabilitada"} onCheckedChange={(enabled) => void run(() => api.updateGrant(node.node_id, grant.grant_id, { ...grantValue(grant), enabled }), "Autorização atualizada.")} />
              <ButtonGroup aria-label={`Ações da autorização: ${label}`}>
                {canUpdate && <Button type="button" size="icon-sm" variant="outline" aria-label={`Editar autorização: ${label}`} title="Editar autorização" disabled={busy || !!form || !canListMounts || !!mountError} onClick={() => start(grant)}><Pencil /></Button>}
                <DropdownMenu><DropdownMenuTrigger render={<Button type="button" size="icon-sm" variant="outline" aria-label={`Mais opções: ${label}`} title="Mais opções" disabled={busy || !!form} />}><MoreHorizontal /></DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="min-w-44">
                    <DropdownMenuItem onClick={() => setExpanded(expanded === grant.grant_id ? null : grant.grant_id)}><SlidersHorizontal /> {expanded === grant.grant_id ? "Ocultar detalhes" : "Ver detalhes"}</DropdownMenuItem>
                    {hasPermission(grantsPath, "delete") && <><DropdownMenuSeparator /><DropdownMenuItem variant="destructive" onClick={() => void remove(grant)}><Trash2 /> Remover autorização</DropdownMenuItem></>}
                  </DropdownMenuContent>
                </DropdownMenu>
              </ButtonGroup>
            </div>
          </div>
          <div className="flex min-w-0 items-center gap-2 text-sm"><Folder className="size-4 shrink-0 text-muted-foreground" /><span className="truncate font-medium" title={mountName}>{mountName}</span><span className="min-w-0 truncate text-muted-foreground" title={grant.path || "/"}>{grant.path && grant.path !== "." ? `/${grant.path}` : "Todas as pastas"}</span></div>
          <CollapsibleContent className="grid gap-2 border-t pt-3 text-xs text-muted-foreground">
            <p className="break-all">Pasta: {grant.path && grant.path !== "." ? `/${grant.path}` : "Todo o mount"}</p>
            {grant.conflict_policies.length > 0 && <div className="flex flex-wrap items-center gap-1"><span>Conflitos</span>{grant.conflict_policies.map((policy) => <Badge key={policy} variant="outline">{CONFLICT_OPTIONS.find((option) => option.value === policy)?.label || policy}</Badge>)}</div>}
            <p>{grant.visible_to_peer ? `Visível para ${otherName}` : `Oculta na descoberta de ${otherName}`}</p>
          </CollapsibleContent>
          </Collapsible>
        </Fragment>;
      })}
    </div>}
    {mountError && <p role="alert" className="text-sm text-destructive">{mountError}</p>}
    {canCreate && !canListMounts && <p className="text-xs text-muted-foreground">A configuração requer permissão para listar os mounts de {node.name}.</p>}
    <Dialog open={!!form} onOpenChange={(open) => { if (!open) closeForm(); }}>
      <DialogContent showCloseButton={false} className="max-h-[calc(100dvh-2rem)] w-[calc(100vw-2rem)] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <div className="flex items-center justify-between gap-3">
            <DialogTitle>{editing ? "Editar autorização" : "Nova autorização"}</DialogTitle>
            <DialogClose render={<Button type="button" variant="ghost" size="icon-sm" aria-label="Fechar autorização" title="Fechar" disabled={busy} />}><X /></DialogClose>
          </div>
          <DialogDescription>{node.name} ↔ {otherName} · Permissões em {node.name}.</DialogDescription>
        </DialogHeader>
        {form && <div className="grid gap-4">
          <GrantFormFields value={form} onChange={setForm} mounts={eligibleMounts} idPrefix={`relationship-${node.node_id}`} />
          {!eligibleMounts.length && <p className="text-sm text-muted-foreground">Nenhum mount habilitado compatível com esta direção. Para receber, o mount precisa permitir escrita.</p>}
          {duplicate && <p className="text-xs text-muted-foreground">Já existe uma autorização nesta pasta. Ela será atualizada.</p>}
          <ButtonGroup className="ml-auto" aria-label="Ações da edição"><Button type="button" variant="outline" disabled={busy} onClick={closeForm}>Cancelar</Button><Button type="button" disabled={busy || !eligibleMounts.some((mount) => mount.mount_id === form.mount_id) || (editing || duplicate ? !canUpdate : !canCreate)} onClick={() => void save()}>{busy ? "Salvando…" : "Salvar"}</Button></ButtonGroup>
        </div>}
      </DialogContent>
    </Dialog>
  </section>;
}

function grantValue(grant: Grant): GrantFormValue {
  return {
    peer_node_id: grant.peer_node_id, mount_id: grant.mount_id, path: grant.path,
    direction: grant.direction, permissions: { ...grant.permissions },
    conflict_policies: [...grant.conflict_policies], visible_to_peer: grant.visible_to_peer, enabled: grant.enabled,
  };
}
