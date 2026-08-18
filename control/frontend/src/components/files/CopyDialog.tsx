import { useEffect, useMemo, useState } from "react";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import type { FileEntry, Grant, Mount, TransferPlan } from "@/lib/types";
import { useWorkspace } from "@/context/WorkspaceContext";
import { useNodes } from "@/context/NodesContext";
import { useApiError } from "@/hooks/useApiError";
import { remoteSourceNodes } from "@/lib/peers";
import { relativeToGrant } from "@/lib/paths";
import { formatBytes } from "@/lib/format";
import { nodeName } from "@/lib/peers";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

const CONFLICT_LABELS: Record<string, string> = {
  fail: "Marcar como falha",
  skip: "Pular existente",
  overwrite: "Sobrescrever",
  rename: "Renomear cópia",
  ask: "Perguntar em cada conflito",
  checksum: "Comparar SHA-256",
};

interface CopyForm {
  destination_node_id: string;
  destination_grant_id: string;
  destination_path: string;
  conflict_policy: string;
  source_change_policy: string;
  verify_checksum: boolean;
  bandwidth_limit_mib_per_second: number;
  max_parallel_files: number;
  max_parallel_chunks: number;
}

interface Props {
  source: FileEntry | null;
  currentPath: string;
  mount: Mount;
  operation?: "copy" | "move";
  onClose: () => void;
  onCompleted?: () => void;
}

export function CopyDialog({
  source,
  currentPath,
  mount,
  operation = "copy",
  onClose,
  onCompleted,
}: Props) {
  const { nodeId, grants, peers, refreshJobs } = useWorkspace();
  const { nodes } = useNodes();
  const handleError = useApiError();

  const [form, setForm] = useState<CopyForm>(baseForm());
  const [plan, setPlan] = useState<TransferPlan | null>(null);
  const [sourceGrant, setSourceGrant] = useState<Grant | null>(null);
  const [destGrants, setDestGrants] = useState<Grant[]>([]);
  const [destMounts, setDestMounts] = useState<Mount[]>([]);
  const [busy, setBusy] = useState(false);
  const isMove = operation === "move";

  const sources = useMemo(
    () => remoteSourceNodes(nodes, peers, nodeId),
    [nodes, peers, nodeId],
  );

  function baseForm(): CopyForm {
    return {
      destination_node_id: nodeId,
      destination_grant_id: "",
      destination_path: "",
      conflict_policy: "fail",
      source_change_policy: "fail",
      verify_checksum: false,
      bandwidth_limit_mib_per_second: 0,
      max_parallel_files: 2,
      max_parallel_chunks: 1,
    };
  }

  useEffect(() => {
    if (!source) return;
    setForm({
      ...baseForm(),
      destination_path: [currentPath, source.name].filter(Boolean).join("/"),
    });
    setPlan(null);
    setSourceGrant(null);
    setDestGrants([]);
    setDestMounts([]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [source, currentPath, isMove]);

  const isRemote =
    !isMove &&
    Boolean(form.destination_node_id) &&
    form.destination_node_id !== nodeId;

  const selectedDestGrant = destGrants.find(
    (g) => g.grant_id === form.destination_grant_id,
  );

  const conflictPolicies = useMemo(() => {
    if (isMove) return ["fail", "overwrite"];
    if (!isRemote) return ["fail", "skip", "overwrite", "rename", "ask", "checksum"];
    const policies = selectedDestGrant?.conflict_policies || [];
    return source?.type === "directory"
      ? policies
      : policies.filter((p) => p !== "ask");
  }, [isMove, isRemote, selectedDestGrant, source?.type]);

  function syncConflictPolicy(next: CopyForm): CopyForm {
    const policies = isMove
      ? ["fail", "overwrite"]
      : !isRemote
      ? ["fail", "skip", "overwrite", "rename", "ask", "checksum"]
      : source?.type === "directory"
        ? selectedDestGrant?.conflict_policies || []
        : (selectedDestGrant?.conflict_policies || []).filter((p) => p !== "ask");
    const conflict_policy = policies.includes(next.conflict_policy)
      ? next.conflict_policy
      : policies[0] || "";
    return {
      ...next,
      conflict_policy,
      verify_checksum:
        conflict_policy === "checksum" || next.verify_checksum,
    };
  }

  async function changeDestination(destinationNodeId: string) {
    setPlan(null);
    setSourceGrant(null);
    setDestGrants([]);
    setDestMounts([]);
    const remote = Boolean(destinationNodeId) && destinationNodeId !== nodeId;
    if (!remote) {
      setForm((prev) => ({
        ...prev,
        destination_node_id: destinationNodeId,
        destination_grant_id: "",
        conflict_policy: "fail",
      }));
      return;
    }
    if (!source) return;
    setBusy(true);
    try {
      const candidates = grants
        .filter(
          (grant) =>
            grant.peer_node_id === destinationNodeId &&
            grant.mount_id === mount.mount_id &&
            grant.enabled &&
            ["send", "send_receive"].includes(grant.direction) &&
            grant.permissions?.read &&
            relativeToGrant(
              source.path,
              grant.path === "." ? "" : grant.path,
            ) != null,
        )
        .sort((a, b) => b.path.length - a.path.length);
      const [grantResult, mountResult] = await Promise.all([
        api.grants(destinationNodeId),
        api.mounts(destinationNodeId),
      ]);
      const receiving = (grantResult.items || []).filter(
        (grant) =>
          grant.peer_node_id === nodeId &&
          grant.enabled &&
          ["receive", "send_receive"].includes(grant.direction) &&
          grant.permissions?.write,
      );
      setSourceGrant(candidates[0] || null);
      setDestGrants(receiving);
      setDestMounts(mountResult.items || []);
      setForm((prev) =>
        syncConflictPolicy({
          ...prev,
          destination_node_id: destinationNodeId,
          destination_grant_id: receiving[0]?.grant_id || "",
          destination_path: source.name,
        }),
      );
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  function remotePayload() {
    const sourceBase =
      sourceGrant?.path === "." ? "" : sourceGrant?.path || "";
    return {
      peer_node_id: nodeId,
      source_grant_id: sourceGrant?.grant_id || "",
      source_path: relativeToGrant(source!.path, sourceBase) || "",
      destination_grant_id: form.destination_grant_id,
      destination_path: form.destination_path,
      conflict_policy: form.conflict_policy,
      verify_checksum: form.verify_checksum,
      bandwidth_limit_bytes_per_second: Math.round(
        (form.bandwidth_limit_mib_per_second || 0) * 1024 * 1024,
      ),
      max_parallel_files: form.max_parallel_files || 1,
      max_parallel_chunks: form.max_parallel_chunks || 1,
    };
  }

  async function preview() {
    if (!source) return;
    setBusy(true);
    try {
      if (isRemote) {
        if (source.type === "directory") {
          setPlan(
            await api.planDirectoryPull(
              form.destination_node_id,
              remotePayload(),
            ),
          );
        } else {
          setPlan({
            files_total: 1,
            bytes_total: source.size || 0,
            copy_count: 1,
            conflict_count: 0,
            remote_file: true,
          });
        }
      } else {
        setPlan(
          await api.planCopy(nodeId, mount.mount_id, {
            source_path: source.path,
            destination_path: form.destination_path,
            conflict_policy: form.conflict_policy,
            verify_checksum: form.verify_checksum,
          }),
        );
      }
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  async function execute() {
    if (!source || (!isMove && !plan)) return;
    setBusy(true);
    try {
      if (isMove) {
        await api.move(nodeId, mount.mount_id, {
          source_path: source.path,
          destination_path: form.destination_path,
          overwrite: form.conflict_policy === "overwrite",
        });
      } else if (isRemote) {
        if (source.type === "directory") {
          await api.pullDirectory(form.destination_node_id, remotePayload());
        } else {
          await api.pullTransfer(form.destination_node_id, remotePayload());
        }
      } else {
        await api.copy(nodeId, mount.mount_id, {
          source_path: source.path,
          destination_path: form.destination_path,
          conflict_policy: form.conflict_policy,
          source_change_policy: form.source_change_policy,
          verify_checksum: form.verify_checksum,
          bandwidth_limit_bytes_per_second: Math.round(
            (form.bandwidth_limit_mib_per_second || 0) * 1024 * 1024,
          ),
          max_parallel_files: form.max_parallel_files || 1,
          max_parallel_chunks: form.max_parallel_chunks || 1,
        });
      }
      onClose();
      onCompleted?.();
      await refreshJobs();
      if (isMove) {
        toast.success("Movimentação adicionada à fila.");
        return;
      }
      if (isRemote) {
        toast.success(
          `Transferência adicionada à fila de ${nodeName(nodes, form.destination_node_id)}.`,
        );
      } else {
        toast.success("Cópia adicionada à fila.");
      }
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  const previewDisabled =
    busy ||
    (isRemote &&
      (!sourceGrant ||
        !form.destination_grant_id ||
        !form.conflict_policy));

  return (
    <Dialog open={source !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            {isMove ? "Mover no mount" : "Plano de cópia"}
          </p>
          <DialogTitle>{isMove ? "Mover" : "Copiar"} {source?.name}</DialogTitle>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            isMove ? execute() : plan ? execute() : preview();
          }}
        >
          {!isMove && <div className="grid gap-2">
            <Label>Node de destino</Label>
            <Select
              value={form.destination_node_id}
              onValueChange={changeDestination}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={nodeId}>
                  {nodeName(nodes, nodeId)} · este node
                </SelectItem>
                {sources.map((n) => (
                  <SelectItem key={n.node_id} value={n.node_id}>
                    {n.name} · {n.state}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>}

          {isMove ? (
            <div className="grid gap-2">
              <Label>Mount de destino</Label>
              <Input disabled value={`${mount.name} · mount atual`} />
            </div>
          ) : isRemote ? (
            <div className="grid gap-2">
              <Label>Mount de destino</Label>
              <Select
                value={form.destination_grant_id}
                onValueChange={(v) =>
                  setForm((prev) =>
                    syncConflictPolicy({ ...prev, destination_grant_id: v }),
                  )
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="Nenhum mount autorizado" />
                </SelectTrigger>
                <SelectContent>
                  {destGrants.map((grant) => (
                    <SelectItem key={grant.grant_id} value={grant.grant_id}>
                      {destMounts.find((m) => m.mount_id === grant.mount_id)
                        ?.name || grant.mount_id}{" "}
                      / {grant.path === "." ? "raiz" : grant.path}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          ) : (
            <div className="grid gap-2">
              <Label>Mount de destino</Label>
              <Input disabled value={`${mount.name} · mount atual`} />
            </div>
          )}

          {isRemote && !sourceGrant && (
            <p className="rounded-md border p-3 text-xs text-muted-foreground">
              O node de origem precisa de um grant de envio que inclua este
              arquivo e seja direcionado ao node de destino.
            </p>
          )}
          {isRemote && !destGrants.length && (
            <p className="rounded-md border p-3 text-xs text-muted-foreground">
              O node de destino precisa de um grant de recebimento direcionado a{" "}
              {nodeName(nodes, nodeId)}.
            </p>
          )}

          <div className="grid gap-2">
            <Label>
              {isRemote
                ? "Caminho dentro do mount autorizado"
                : isMove
                  ? "Novo caminho dentro do mount"
                  : "Destino dentro do mount"}
            </Label>
            <Input
              value={form.destination_path}
              required
              onChange={(e) => {
                setForm({ ...form, destination_path: e.target.value });
                setPlan(null);
              }}
            />
          </div>

          <div className="grid gap-2">
            <Label>Conflitos</Label>
            <Select
              value={form.conflict_policy}
              onValueChange={(v) =>
                setForm((prev) =>
                  syncConflictPolicy({ ...prev, conflict_policy: v }),
                )
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {conflictPolicies.map((p) => (
                  <SelectItem key={p} value={p}>
                    {CONFLICT_LABELS[p] || p}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {!isRemote && !isMove && (
            <div className="grid gap-2">
              <Label>Se a origem mudar durante o job</Label>
              <Select
                value={form.source_change_policy}
                onValueChange={(v) =>
                  setForm({ ...form, source_change_policy: v })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="fail">Falhar o item</SelectItem>
                  <SelectItem value="retry">
                    Atualizar o manifest e tentar novamente
                  </SelectItem>
                  <SelectItem value="copy_anyway">Copiar mesmo assim</SelectItem>
                </SelectContent>
              </Select>
            </div>
          )}

          {!isMove && <label className="flex items-center gap-2 text-sm">
            <Checkbox
              checked={form.verify_checksum}
              disabled={form.conflict_policy === "checksum"}
              onCheckedChange={(v) =>
                setForm({ ...form, verify_checksum: v === true })
              }
            />
            Verificar SHA-256 antes de publicar o destino
          </label>}

          {!isMove && <div className="grid grid-cols-3 gap-2">
            <div className="grid gap-2">
              <Label className="text-xs">Limite MiB/s</Label>
              <Input
                type="number"
                min={0}
                step={0.1}
                value={form.bandwidth_limit_mib_per_second}
                onChange={(e) =>
                  setForm({
                    ...form,
                    bandwidth_limit_mib_per_second: Number(e.target.value),
                  })
                }
              />
            </div>
            <div className="grid gap-2">
              <Label className="text-xs">Arquivos //</Label>
              <Input
                type="number"
                min={1}
                max={32}
                value={form.max_parallel_files}
                onChange={(e) =>
                  setForm({
                    ...form,
                    max_parallel_files: Number(e.target.value),
                  })
                }
              />
            </div>
            <div className="grid gap-2">
              <Label className="text-xs">Chunks //</Label>
              <Input
                type="number"
                min={1}
                max={16}
                value={form.max_parallel_chunks}
                onChange={(e) =>
                  setForm({
                    ...form,
                    max_parallel_chunks: Number(e.target.value),
                  })
                }
              />
            </div>
          </div>}

          {!isMove && plan && (
            <div className="grid grid-cols-3 gap-2 rounded-md border p-3 text-sm">
              <div>
                <span className="block text-xs text-muted-foreground">
                  Arquivos
                </span>
                <strong>{plan.files_total}</strong>
              </div>
              <div>
                <span className="block text-xs text-muted-foreground">
                  Dados
                </span>
                <strong>{formatBytes(plan.bytes_total)}</strong>
              </div>
              <div>
                <span className="block text-xs text-muted-foreground">
                  Conflitos
                </span>
                <strong>{plan.conflict_count}</strong>
              </div>
            </div>
          )}

          {isMove ? (
            <Button type="submit" disabled={busy}>
              Mover {source?.name} <ArrowRight />
            </Button>
          ) : !plan ? (
            <Button type="submit" disabled={previewDisabled}>
              Gerar prévia <ArrowRight />
            </Button>
          ) : (
            <div className="flex justify-end gap-2">
              <Button
                type="button"
                variant="secondary"
                onClick={() => setPlan(null)}
              >
                Revisar
              </Button>
              <Button type="submit" disabled={busy}>
                Iniciar cópia <ArrowRight />
              </Button>
            </div>
          )}
        </form>
      </DialogContent>
    </Dialog>
  );
}
