import { useEffect, useMemo, useState } from "react";
import { ArrowRight } from "lucide-react";
import { TransferDestinationFolder } from "@/components/files/TransferDestinationFolder";
import { TransferDestinationPreview } from "@/components/files/TransferDestinationPreview";
import { RelationshipTrustDialog } from "@/components/relationships/RelationshipTrustDialog";
import { transferDestinations, type TransferDestination } from "@/lib/transfer-access";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { transferDestinationFolder } from "@/lib/transfer-preview";
import type {
  FileEntry,
  LogicalTransferRequest,
  Mount,
  TransferPlan,
} from "@/lib/types";
import { useWorkspace } from "@/context/WorkspaceContext";
import { useNodes } from "@/context/NodesContext";
import { useApiError } from "@/hooks/useApiError";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const CONFLICT_LABELS: Record<string, string> = {
  fail: "Marcar como falha",
  skip: "Pular existente",
  overwrite: "Sobrescrever",
  rename: "Renomear cópia",
  ask: "Perguntar em cada conflito",
  checksum: "Comparar SHA-256",
};

interface Props {
  open: boolean;
  operation: "copy" | "move";
  mount: Mount;
  entries: FileEntry[];
  onClose: () => void;
  onCompleted?: () => void;
  onLimitResolved?: (limit: number) => void;
}

export function CrossNodeTransferDialog({
  open,
  operation,
  mount,
  entries,
  onClose,
  onCompleted,
  onLimitResolved,
}: Props) {
  const { nodeId, node, refreshJobs, refreshTrust } = useWorkspace();
  const { nodes } = useNodes();
  const navigate = useNavigate();
  const handleError = useApiError();
  const [targets, setTargets] = useState<TransferDestination[]>([]);
  const [discoveryVersion, setDiscoveryVersion] = useState(0);
  const [relationshipOpen, setRelationshipOpen] = useState(false);
  const [limit, setLimit] = useState(1000);
  const [targetNodeId, setTargetNodeId] = useState("");
  const [targetMountId, setTargetMountId] = useState("");
  const [destinationPath, setDestinationPath] = useState("");
  const [conflictPolicy, setConflictPolicy] = useState("fail");
  const [verifyChecksum, setVerifyChecksum] = useState(false);
  const [bandwidthMiB, setBandwidthMiB] = useState(0);
  const [maxParallelFiles, setMaxParallelFiles] = useState(2);
  const [maxParallelChunks, setMaxParallelChunks] = useState(1);
  const [plan, setPlan] = useState<TransferPlan | null>(null);
  const [busy, setBusy] = useState(false);
  const [createdJobId, setCreatedJobId] = useState("");

  const paths = useMemo(() => entries.map((entry) => entry.path), [entries]);
  const target = targets.find((candidate) => candidate.node_id === targetNodeId);
  const targetNode = nodes.find((candidate) => candidate.node_id === targetNodeId);
  const targetMount = target?.mounts.find(
    (candidate) => candidate.mount_id === targetMountId,
  );

  useEffect(() => {
    if (!open || !mount || !paths.length) return;
    let active = true;
    setBusy(true);
    setPlan(null);
    setCreatedJobId("");
    void api
      .transferTargets(
        nodeId,
        { mount_id: mount.mount_id, paths },
        operation,
      )
      .then((response) => {
        if (!active) return;
        const destinations = transferDestinations(response);
        setTargets(destinations);
        setLimit(response.max_source_paths || 1000);
        onLimitResolved?.(response.max_source_paths || 1000);
        const first = destinations.find(
          (candidate) => candidate.available && candidate.mounts.some((item) => item.available),
        ) || destinations[0];
        setTargetNodeId((current) => destinations.some((candidate) => candidate.node_id === current) ? current : first?.node_id || "");
      })
      .catch((error) => {
        if (!active) return;
        setTargets([]);
        handleError(error);
      })
      .finally(() => active && setBusy(false));
    return () => {
      active = false;
    };
  }, [open, operation, mount, nodeId, paths, handleError, onLimitResolved, discoveryVersion]);

  useEffect(() => {
    // Rechecking access after closing the relationship must keep a destination
    // folder that is still covered by the refreshed authorization.
    const selectedMount = target?.mounts.find((item) => item.mount_id === targetMountId && item.available);
    const withinRoot = (path: string, root: string) => !root || path === root || path.startsWith(`${root}/`);
    if (selectedMount && withinRoot(destinationPath, selectedMount.root_path) && selectedMount.conflict_policies.includes(conflictPolicy)) {
      setPlan(null);
      return;
    }
    const firstMount = target?.mounts.find((item) => item.available);
    setTargetMountId(firstMount?.mount_id || "");
    setDestinationPath(firstMount?.root_path || "");
    setConflictPolicy(firstMount?.conflict_policies.includes("fail") ? "fail" : firstMount?.conflict_policies[0] || "fail");
    setPlan(null);
    // Only a discovery response or node change should reset an invalid folder.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target]);

  function selectTargetNode(nextNodeID: string) {
    const nextTarget = targets.find((candidate) => candidate.node_id === nextNodeID);
    const nextMount = nextTarget?.mounts.find((item) => item.available);
    setTargetNodeId(nextNodeID);
    setTargetMountId(nextMount?.mount_id || "");
    setDestinationPath(nextMount?.root_path || "");
    setConflictPolicy(nextMount?.conflict_policies.includes("fail") ? "fail" : nextMount?.conflict_policies[0] || "fail");
    setPlan(null);
    setRelationshipOpen(false);
  }

  function selectTargetMount(nextMountID: string) {
    const nextMount = target?.mounts.find((item) => item.mount_id === nextMountID);
    setTargetMountId(nextMountID);
    setDestinationPath(nextMount?.root_path || "");
    setConflictPolicy(nextMount?.conflict_policies.includes("fail") ? "fail" : nextMount?.conflict_policies[0] || "fail");
    setPlan(null);
  }

  function payload(): LogicalTransferRequest | null {
    if (!target?.available || !targetMount?.available || !paths.length) return null;
    return {
      operation,
      source: { node_id: nodeId, mount_id: mount.mount_id, paths },
      destination: { mount_id: targetMount.mount_id, path: destinationPath.trim() },
      conflict_policy: conflictPolicy,
      verify_checksum: verifyChecksum || operation === "move" || conflictPolicy === "checksum",
      bandwidth_limit_bytes_per_second: Math.round(bandwidthMiB * 1024 * 1024),
      max_parallel_files: maxParallelFiles,
      max_parallel_chunks: maxParallelChunks,
    };
  }

  async function preview() {
    if (!target || !payload()) return;
    setBusy(true);
    try {
      const result = await api.planTransfer(target.node_id, payload()!);
      setPlan(result.plan);
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  async function execute() {
    if (!target || !payload() || !plan) return;
    setBusy(true);
    try {
      const job = await api.createTransfer(target.node_id, payload()!);
      setCreatedJobId(job.job_id);
      await refreshJobs();
      onCompleted?.();
      toast.success(`${operation === "move" ? "Movimentação" : "Cópia"} adicionada à fila.`);
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  const destinationFolder = transferDestinationFolder(destinationPath);
  const destinationRoot = transferDestinationFolder(targetMount?.root_path || "") || "";
  const canSubmit = Boolean(
    target?.available &&
      targetMount?.available &&
      targetMountId &&
      targetMount.conflict_policies.includes(conflictPolicy) &&
      destinationFolder !== null &&
      (!destinationRoot || destinationFolder === destinationRoot || destinationFolder.startsWith(`${destinationRoot}/`)) &&
      paths.length &&
      paths.length <= limit,
  );

  return (
    <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Transferência entre nodes
          </p>
          <DialogTitle>{operation === "move" ? "Mover para outro node" : "Copiar para outro node"}</DialogTitle>
        </DialogHeader>
        {createdJobId ? (
          <div className="grid gap-4">
            <p className="text-sm text-muted-foreground">
              Job {createdJobId} criado no node de destino. Os bytes trafegam diretamente entre os nodes.
            </p>
            <DialogFooter>
              <Button variant="secondary" onClick={onClose}>Fechar</Button>
              <Button onClick={() => navigate(`/nodes/${targetNodeId}`)}>Abrir job <ArrowRight /></Button>
            </DialogFooter>
          </div>
        ) : (
          <form className="grid gap-4" onSubmit={(event) => {
            event.preventDefault();
            if (relationshipOpen || busy || !canSubmit) return;
            if (plan) void execute(); else void preview();
          }}>
            <p className="text-sm text-muted-foreground">
              {paths.length} raiz{paths.length === 1 ? "" : "es"} selecionada{paths.length === 1 ? "" : "s"}. O limite efetivo é {limit} por transferência; arquivos dentro de pastas não contam separadamente.
            </p>
            {!targets.length && !busy && (
              <div className="grid gap-3 rounded-md border p-3 text-sm text-muted-foreground">
                <p>Nenhum destino disponível para esta seleção. Confira as conexões e suas permissões de transferência.</p>
                <div>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => navigate("/relationships")}
                  >
                    Abrir conexões
                  </Button>
                </div>
              </div>
            )}
            <div className="grid gap-4 md:grid-cols-2">
              <div className="grid gap-2">
                <Label>Node de destino</Label>
                <Select value={targetNodeId} onValueChange={selectTargetNode} disabled={busy}>
                  <SelectTrigger className="w-full"><SelectValue placeholder={busy ? "Buscando destinos…" : "Nenhum destino disponível"}>{target?.name}</SelectValue></SelectTrigger>
                  <SelectContent>
                    {targets.map((candidate) => (
                      <SelectItem key={candidate.node_id} value={candidate.node_id} disabled={!candidate.available && !candidate.reasons?.length}>
                        {candidate.name} · {candidate.reasons?.length ? "Configurar acesso" : candidate.available ? "Disponível" : "Indisponível"}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label>Mount de destino</Label>
                <Select value={targetMountId} onValueChange={selectTargetMount} disabled={busy || !target?.mounts.length}>
                  <SelectTrigger className="w-full"><SelectValue placeholder={target?.reasons?.length ? "Configure o acesso abaixo" : "Selecione o node"}>{targetMount?.name}</SelectValue></SelectTrigger>
                  <SelectContent>
                    {target?.mounts.map((candidate) => (
                      <SelectItem key={candidate.mount_id} value={candidate.mount_id} disabled={!candidate.available}>
                        {candidate.name} · {candidate.state}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            {target?.reasons?.length && !busy && <div className="grid gap-3 rounded-md border p-4">
              <p className="font-medium">Configurar transferência de {node?.name || "origem"} para {target.name}</p>
              <p className="text-sm text-muted-foreground">Configure as autorizações na relação de confiança entre estes nodes. Sua seleção de arquivos será mantida.</p>
              {target.reasons.includes("source_grant_missing") && <div className="grid gap-2">
                <p className="text-sm">{operation === "move"
                  ? `Para mover entre hosts, o envio em ${node?.name || "origem"} · ${mount.name} precisa permitir leitura e remoção dos arquivos de origem.`
                  : `Envio pendente em ${node?.name || "origem"} · ${mount.name}.`}</p>
              </div>}
              {target.reasons.includes("destination_grant_missing") && <div className="grid gap-2">
                <p className="text-sm">Recebimento pendente em {target.name}. Escolha um mount com escrita.</p>
              </div>}
            </div>}
            {targetNode && <Button type="button" variant="outline" disabled={busy} onClick={() => setRelationshipOpen(true)}>Abrir relação de confiança · {node?.name || "origem"} ↔ {targetNode.name}</Button>}
            {target && !target.reasons?.length && !busy && !canSubmit && <p role="status" className="text-sm text-muted-foreground">O destino não está pronto. Confira se o node está online e se há um mount autorizado com escrita disponível.</p>}
            {targetMount?.available && <>
            <TransferDestinationFolder nodeId={targetNodeId} mount={targetMount} value={destinationPath} disabled={busy} onChange={(path) => { setDestinationPath(path); setPlan(null); }} />
            <TransferDestinationPreview entries={entries} destinationPath={destinationPath} operation={operation} plan={plan} />
            <div className="grid gap-4 md:grid-cols-2">
              <div className="grid gap-2">
                <Label>Conflitos</Label>
                <Select value={conflictPolicy} onValueChange={(value) => { setConflictPolicy(value); setPlan(null); }}>
                  <SelectTrigger><SelectValue>{CONFLICT_LABELS[conflictPolicy] || conflictPolicy}</SelectValue></SelectTrigger>
                  <SelectContent>
                    {(targetMount?.conflict_policies || []).map((policy) => <SelectItem key={policy} value={policy}>{CONFLICT_LABELS[policy] || policy}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <label className="mt-7 flex items-center gap-2 text-sm">
                <Checkbox checked={verifyChecksum || operation === "move"} disabled={operation === "move" || conflictPolicy === "checksum"} onCheckedChange={(value) => setVerifyChecksum(value === true)} />
                Verificar SHA-256
              </label>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div className="grid gap-1"><Label className="text-xs">Limite MiB/s</Label><Input type="number" min={0} step={0.1} value={bandwidthMiB} onChange={(event) => setBandwidthMiB(Number(event.target.value))} /></div>
              <div className="grid gap-1"><Label className="text-xs">Arquivos //</Label><Input type="number" min={1} max={32} value={maxParallelFiles} onChange={(event) => setMaxParallelFiles(Number(event.target.value))} /></div>
              <div className="grid gap-1"><Label className="text-xs">Chunks //</Label><Input type="number" min={1} max={16} value={maxParallelChunks} onChange={(event) => setMaxParallelChunks(Number(event.target.value))} /></div>
            </div>
            {plan && <div className="grid grid-cols-3 gap-2 rounded-md border p-3 text-sm md:grid-cols-6">
              <Summary label="Arquivos" value={plan.files_total} />
              <Summary label="Dados" value={formatBytes(plan.bytes_total)} />
              <Summary label={operation === "move" ? "Mover" : "Copiar"} value={plan.copy_count} />
              <Summary label="Renomear" value={plan.rename_count || 0} />
              <Summary label="Ignorar" value={plan.skip_count || 0} />
              <Summary label="Conflitos" value={plan.conflict_count} />
            </div>}</>}
            <DialogFooter>
              <Button type="button" variant="secondary" onClick={onClose}>Cancelar</Button>
              {plan && <Button type="button" variant="secondary" onClick={() => setPlan(null)}>Revisar</Button>}
              <Button type="submit" disabled={busy || relationshipOpen || !canSubmit}>{plan ? "Confirmar transferência" : "Gerar prévia"} <ArrowRight /></Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
      {node && targetNode && <RelationshipTrustDialog source={node} target={targetNode} open={open && relationshipOpen} selection={{ mount, paths, operation }} onClose={() => { setRelationshipOpen(false); setDiscoveryVersion((version) => version + 1); }} onChanged={() => { setDiscoveryVersion((version) => version + 1); void refreshTrust().catch(handleError); }} />}
    </Dialog>
  );
}

function Summary({ label, value }: { label: string; value: string | number }) {
  return <div><span className="block text-xs text-muted-foreground">{label}</span><strong>{value}</strong></div>;
}
