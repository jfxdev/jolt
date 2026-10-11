import { useCallback, useEffect, useState } from "react";
import { RefreshCw, ShieldCheck, X } from "lucide-react";
import { api } from "@/lib/api";
import { transferPeer } from "@/lib/transfer-access";
import { trustPresentation } from "@/lib/trust";
import type { NodeInfo, TrustView } from "@/lib/types";
import { usePermissions } from "@/context/PermissionsContext";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ButtonGroup } from "@/components/ui/button-group";
import { RelationshipAccessPanel, type RelationshipSelection } from "./RelationshipAccessPanel";

interface Props {
  source: NodeInfo;
  target: NodeInfo;
  open: boolean;
  onClose: () => void;
  onChanged: () => void;
  selection?: RelationshipSelection;
}
interface Side { node: NodeInfo; trust: TrustView | null; error?: string }

export function RelationshipTrustDialog({ source, target, open, onClose, onChanged, selection }: Props) {
  const { loadPermissions, hasPermissionNow } = usePermissions();
  const [sides, setSides] = useState<Side[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      await loadPermissions([source, target].flatMap((node) => ["peers", "grants", "mounts"].map((resource) => `nodes/${node.node_id}/${resource}`)));
      const result = await Promise.all([source, target].map(async (node): Promise<Side> => {
        if (!hasPermissionNow(`nodes/${node.node_id}/peers`, "list")) return { node, trust: null, error: "Você não tem permissão para consultar a confiança deste node." };
        try { return { node, trust: await api.nodeTrust(node.node_id) }; }
        catch (failure) { return { node, trust: null, error: (failure as Error).message }; }
      }));
      setSides(result);
    } catch (failure) { setError((failure as Error).message); }
    finally { setLoading(false); }
  }, [source, target, loadPermissions, hasPermissionNow]);

  useEffect(() => {
    if (!open) return;
    setSides([]);
    void refresh();
  }, [open, refresh]);

  async function changed() { await refresh(); onChanged(); }
  const healthy = sides.length === 2 && sides.every((side) => {
    const other = side.node.node_id === source.node_id ? target : source;
    const peer = transferPeer(side.trust?.peers || [], other.node_id);
    return !!peer && trustPresentation(peer.trust_status).healthy;
  });

  return <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
    <DialogContent showCloseButton={false} className="max-h-[calc(100dvh-2rem)] w-[calc(100vw-2rem)] overflow-y-auto sm:max-w-4xl">
      <DialogHeader className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-2">
        <div className="col-span-2 row-start-2 flex min-w-0 items-center justify-between gap-3 sm:col-span-1 sm:row-start-1">
          <DialogTitle className="min-w-0 truncate" title={`${source.name} ↔ ${target.name}`}>{source.name} ↔ {target.name}</DialogTitle>
          {healthy && !loading && <Badge variant="success" className="shrink-0"><ShieldCheck /> Confiança confirmada</Badge>}
        </div>
        <ButtonGroup className="col-start-2 row-start-1" aria-label="Ações da relação">
          <Button type="button" variant="ghost" size="icon-sm" aria-label="Atualizar relação" title="Atualizar relação" disabled={loading} onClick={() => void refresh()}><RefreshCw /></Button>
          <DialogClose render={<Button type="button" variant="ghost" size="icon-sm" aria-label="Fechar" title="Fechar" />}><X /></DialogClose>
        </ButtonGroup>
        <DialogDescription className="col-span-2">Autorizações de arquivos entre os nodes.</DialogDescription>
      </DialogHeader>
      {loading ? <p className="text-sm text-muted-foreground">Consultando os dois nodes…</p> : <>
        {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
        <div className="grid gap-3 md:grid-cols-2">{sides.map((side) => {
          const other = side.node.node_id === source.node_id ? target : source;
          const peer = transferPeer(side.trust?.peers || [], other.node_id);
          const presentation = peer ? trustPresentation(peer.trust_status) : null;
          return <div key={side.node.node_id} className="grid min-w-0 content-start gap-3">
            {!healthy && <div className="grid gap-2"><Badge variant={presentation?.variant || "secondary"}>{side.node.name} · {presentation?.label || (side.error ? "Indisponível" : "Sem conexão")}</Badge><p className="text-xs text-muted-foreground">{presentation?.explanation || side.error || "Este node não tem uma relação de confiança com o outro."}</p></div>}
            <RelationshipAccessPanel node={side.node} otherName={other.name} peer={peer} canListGrants={side.trust?.can_list_grants || false} error={side.error} defaultDirection={side.node.node_id === source.node_id ? "send" : "receive"} selection={side.node.node_id === source.node_id ? selection : undefined} onChanged={changed} />
          </div>;
        })}</div>
      </>}
    </DialogContent>
  </Dialog>;
}
