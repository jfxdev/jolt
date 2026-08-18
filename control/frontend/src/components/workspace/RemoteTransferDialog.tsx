import { useEffect, useMemo, useState } from "react";
import { ArrowRight, Folder, File as FileIcon } from "lucide-react";
import { api } from "@/lib/api";
import type { FileEntry, Grant, Mount } from "@/lib/types";
import { useWorkspace } from "@/context/WorkspaceContext";
import { useNodes } from "@/context/NodesContext";
import { useApiError } from "@/hooks/useApiError";
import { remoteSourceNodes } from "@/lib/peers";
import { joinPath, relativeToGrant } from "@/lib/paths";
import { formatBytes } from "@/lib/format";
import { cn } from "@/lib/utils";
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
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface RemoteForm {
  source_node_id: string;
  source_grant_id: string;
  source_path: string;
  destination_grant_id: string;
  destination_path: string;
  conflict_policy: string;
  verify_checksum: boolean;
  bandwidth_limit_mib_per_second: number;
  max_parallel_files: number;
  max_parallel_chunks: number;
}

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function baseForm(): RemoteForm {
  return {
    source_node_id: "",
    source_grant_id: "",
    source_path: "",
    destination_grant_id: "",
    destination_path: "",
    conflict_policy: "fail",
    verify_checksum: false,
    bandwidth_limit_mib_per_second: 0,
    max_parallel_files: 2,
    max_parallel_chunks: 1,
  };
}

export function RemoteTransferDialog({ open, onOpenChange }: Props) {
  const { nodeId, node, grants, peers, mounts, refreshJobs } = useWorkspace();
  const { nodes } = useNodes();
  const handleError = useApiError();

  const [form, setForm] = useState<RemoteForm>(baseForm());
  const [sourceGrants, setSourceGrants] = useState<Grant[]>([]);
  const [sourceMounts, setSourceMounts] = useState<Mount[]>([]);
  const [sourceFiles, setSourceFiles] = useState<FileEntry[]>([]);
  const [currentPath, setCurrentPath] = useState("");
  const [sourceEntry, setSourceEntry] = useState<FileEntry | null>(null);
  const [plan, setPlan] = useState<{
    files_total: number;
    bytes_total: number;
    copy_count: number;
    conflict_count: number;
  } | null>(null);
  const [busy, setBusy] = useState(false);

  const sources = useMemo(
    () => remoteSourceNodes(nodes, peers, nodeId),
    [nodes, peers, nodeId],
  );

  const destinationGrants = useMemo(
    () =>
      grants.filter(
        (grant) =>
          grant.peer_node_id === form.source_node_id &&
          grant.enabled &&
          ["receive", "send_receive"].includes(grant.direction) &&
          grant.permissions?.write,
      ),
    [grants, form.source_node_id],
  );

  const selectedSourceGrant = sourceGrants.find(
    (g) => g.grant_id === form.source_grant_id,
  );
  const selectedDestinationGrant = destinationGrants.find(
    (g) => g.grant_id === form.destination_grant_id,
  );

  const breadcrumbs = useMemo(() => {
    const grant = selectedSourceGrant;
    if (!grant) return [];
    const base = grant.path === "." ? "" : grant.path;
    const relative = relativeToGrant(currentPath, base) || "";
    const parts = relative.split("/").filter(Boolean);
    return [
      {
        label:
          sourceMounts.find((m) => m.mount_id === grant.mount_id)?.name ||
          "Origem",
        path: base,
      },
      ...parts.map((part, index) => ({
        label: part,
        path: joinPath(base, parts.slice(0, index + 1).join("/")),
      })),
    ];
  }, [selectedSourceGrant, currentPath, sourceMounts]);

  useEffect(() => {
    if (!open) return;
    if (!sources.length) {
      toast.error(
        "Conecte e registre na Control Tower um peer confiável para iniciar uma transferência.",
      );
      onOpenChange(false);
      return;
    }
    const initial = { ...baseForm(), source_node_id: sources[0].node_id };
    setForm(initial);
    setPlan(null);
    setSourceEntry(null);
    void loadSource(sources[0].node_id, initial);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  function syncConflictPolicy(
    next: RemoteForm,
    destGrant: Grant | undefined,
  ): RemoteForm {
    const policies = destGrant?.conflict_policies || [];
    const conflict_policy = policies.includes(next.conflict_policy)
      ? next.conflict_policy
      : policies[0] || "fail";
    return {
      ...next,
      conflict_policy,
      verify_checksum:
        conflict_policy === "checksum" || next.verify_checksum,
    };
  }

  async function loadSource(sourceNodeId: string, baseState: RemoteForm) {
    if (!sourceNodeId) return;
    setBusy(true);
    try {
      const [grantResult, mountResult] = await Promise.all([
        api.grants(sourceNodeId),
        api.mounts(sourceNodeId),
      ]);
      const visibleGrants = (grantResult.items || []).filter(
        (grant) =>
          grant.peer_node_id === nodeId &&
          grant.enabled &&
          grant.visible_to_peer &&
          ["send", "send_receive"].includes(grant.direction) &&
          grant.permissions?.read,
      );
      setSourceGrants(visibleGrants);
      setSourceMounts(mountResult.items || []);
      const destGrant = destinationGrants[0];
      const nextForm = syncConflictPolicy(
        {
          ...baseState,
          source_grant_id: visibleGrants[0]?.grant_id || "",
          destination_grant_id: destGrant?.grant_id || "",
        },
        destGrant,
      );
      setForm(nextForm);
      await loadGrantRoot(visibleGrants[0]);
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  async function loadGrantRoot(grant: Grant | undefined) {
    setPlan(null);
    setSourceEntry(null);
    setForm((prev) => ({ ...prev, source_path: "" }));
    if (!grant) {
      setSourceFiles([]);
      setCurrentPath("");
      return;
    }
    await loadFiles(grant, grant.path === "." ? "" : grant.path);
  }

  async function loadFiles(grant: Grant, path: string) {
    const base = grant.path === "." ? "" : grant.path;
    if (relativeToGrant(path, base) == null) {
      toast.error("O caminho solicitado está fora do grant de origem.");
      return;
    }
    setBusy(true);
    try {
      const result = await api.files(form.source_node_id, grant.mount_id, path);
      setSourceFiles(result.items || []);
      setCurrentPath(path);
      setSourceEntry(null);
      setPlan(null);
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  function chooseEntry(entry: FileEntry) {
    const grant = selectedSourceGrant;
    const base = grant?.path === "." ? "" : grant?.path || "";
    const relative = relativeToGrant(entry.path, base);
    if (relative == null) return;
    setSourceEntry(entry);
    setForm((prev) => ({
      ...prev,
      source_path: relative,
      destination_path: entry.name,
    }));
    setPlan(null);
  }

  function chooseDirectory() {
    const grant = selectedSourceGrant;
    const base = grant?.path === "." ? "" : grant?.path || "";
    const relative = relativeToGrant(currentPath, base);
    if (relative == null || !grant) return;
    const name =
      currentPath.split("/").filter(Boolean).at(-1) ||
      sourceMounts.find((m) => m.mount_id === grant.mount_id)?.name ||
      "transfer";
    setSourceEntry({ type: "directory", name, path: currentPath });
    setForm((prev) => ({
      ...prev,
      source_path: relative,
      destination_path: name,
    }));
    setPlan(null);
  }

  function payload() {
    return {
      peer_node_id: form.source_node_id,
      source_grant_id: form.source_grant_id,
      source_path: form.source_path,
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
    if (!sourceEntry || sourceEntry.type !== "directory") return;
    setBusy(true);
    try {
      setPlan(await api.planDirectoryPull(nodeId, payload()));
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  async function execute() {
    if (!sourceEntry) return;
    setBusy(true);
    try {
      if (sourceEntry.type === "directory") {
        if (!plan) return;
        await api.pullDirectory(nodeId, payload());
      } else {
        await api.pullTransfer(nodeId, payload());
      }
      onOpenChange(false);
      await refreshJobs();
      toast.success("Transferência direta adicionada à fila.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  const needsPreview = sourceEntry?.type === "directory" && !plan;
  const submitDisabled =
    busy ||
    !sourceEntry ||
    !form.destination_grant_id ||
    !(selectedDestinationGrant?.conflict_policies || []).includes(
      form.conflict_policy,
    );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Transferência direta por mTLS
          </p>
          <DialogTitle>Copiar de outro node</DialogTitle>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            needsPreview ? preview() : execute();
          }}
        >
          <p className="text-sm text-muted-foreground">
            A Control Tower monta o plano; os bytes seguem diretamente do peer
            para {node?.name}.
          </p>

          <div className="grid gap-6 md:grid-cols-2">
            <section className="grid gap-3">
              <h3 className="text-sm font-semibold">1. Origem</h3>
              <div className="grid gap-2">
                <Label>Peer</Label>
                <Select
                  value={form.source_node_id}
                  onValueChange={(v) => {
                    const next = { ...form, source_node_id: v };
                    setForm(next);
                    void loadSource(v, next);
                  }}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {sources.map((n) => (
                      <SelectItem key={n.node_id} value={n.node_id}>
                        {n.name} · {n.state}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label>Grant de envio</Label>
                <Select
                  value={form.source_grant_id}
                  onValueChange={(v) => {
                    setForm((prev) => ({ ...prev, source_grant_id: v }));
                    void loadGrantRoot(
                      sourceGrants.find((g) => g.grant_id === v),
                    );
                  }}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Nenhum grant compatível" />
                  </SelectTrigger>
                  <SelectContent>
                    {sourceGrants.map((grant) => (
                      <SelectItem key={grant.grant_id} value={grant.grant_id}>
                        {sourceMounts.find((m) => m.mount_id === grant.mount_id)
                          ?.name || grant.mount_id}{" "}
                        / {grant.path === "." ? "raiz" : grant.path}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {selectedSourceGrant ? (
                <div className="grid gap-2">
                  <nav className="flex flex-wrap gap-1 text-xs text-muted-foreground">
                    {breadcrumbs.map((crumb) => (
                      <button
                        key={crumb.path}
                        type="button"
                        className="hover:text-foreground"
                        onClick={() =>
                          loadFiles(selectedSourceGrant, crumb.path)
                        }
                      >
                        {crumb.label} /
                      </button>
                    ))}
                  </nav>
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    onClick={chooseDirectory}
                  >
                    Selecionar esta pasta
                  </Button>
                  <div className="max-h-48 overflow-y-auto rounded-md border">
                    {sourceFiles.map((entry) => (
                      <button
                        key={entry.path}
                        type="button"
                        className={cn(
                          "flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-sm hover:bg-accent",
                          sourceEntry?.path === entry.path && "bg-accent",
                        )}
                        onClick={() => chooseEntry(entry)}
                        onDoubleClick={() =>
                          entry.type === "directory" &&
                          loadFiles(selectedSourceGrant, entry.path)
                        }
                      >
                        <span className="flex items-center gap-2">
                          {entry.type === "directory" ? (
                            <Folder className="h-4 w-4" />
                          ) : (
                            <FileIcon className="h-4 w-4" />
                          )}
                          {entry.name}
                        </span>
                        <small className="text-muted-foreground">
                          {entry.type === "directory"
                            ? "Pasta"
                            : formatBytes(entry.size)}
                        </small>
                      </button>
                    ))}
                    {!sourceFiles.length && (
                      <div className="px-3 py-4 text-xs text-muted-foreground">
                        Pasta vazia.
                      </div>
                    )}
                  </div>
                  {sourceEntry && (
                    <p className="text-xs text-muted-foreground">
                      Selecionado: <strong>{sourceEntry.name}</strong>
                    </p>
                  )}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">
                  O peer precisa de um grant de envio visível, habilitado e
                  direcionado a este node.
                </p>
              )}
            </section>

            <section className="grid gap-3">
              <h3 className="text-sm font-semibold">2. Destino</h3>
              <div className="grid gap-2">
                <Label>Grant de recebimento</Label>
                <Select
                  value={form.destination_grant_id}
                  onValueChange={(v) =>
                    setForm((prev) =>
                      syncConflictPolicy(
                        { ...prev, destination_grant_id: v },
                        destinationGrants.find((g) => g.grant_id === v),
                      ),
                    )
                  }
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Nenhum grant compatível" />
                  </SelectTrigger>
                  <SelectContent>
                    {destinationGrants.map((grant) => (
                      <SelectItem key={grant.grant_id} value={grant.grant_id}>
                        {mounts.find((m) => m.mount_id === grant.mount_id)
                          ?.name || grant.mount_id}{" "}
                        / {grant.path === "." ? "raiz" : grant.path}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label>Caminho relativo de destino</Label>
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
                      syncConflictPolicy(
                        { ...prev, conflict_policy: v },
                        selectedDestinationGrant,
                      ),
                    )
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(selectedDestinationGrant?.conflict_policies || []).map(
                      (p) => (
                        <SelectItem key={p} value={p}>
                          {p}
                        </SelectItem>
                      ),
                    )}
                  </SelectContent>
                </Select>
              </div>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={form.verify_checksum}
                  disabled={form.conflict_policy === "checksum"}
                  onCheckedChange={(v) =>
                    setForm({ ...form, verify_checksum: v === true })
                  }
                />
                Verificar SHA-256 antes de publicar
              </label>
              <div className="grid grid-cols-3 gap-2">
                <div className="grid gap-1">
                  <Label className="text-xs">MiB/s</Label>
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
                <div className="grid gap-1">
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
                <div className="grid gap-1">
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
              </div>
              {plan && (
                <div className="grid grid-cols-4 gap-2 rounded-md border p-3 text-sm">
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
                      Copiar
                    </span>
                    <strong>{plan.copy_count}</strong>
                  </div>
                  <div>
                    <span className="block text-xs text-muted-foreground">
                      Conflitos
                    </span>
                    <strong>{plan.conflict_count}</strong>
                  </div>
                </div>
              )}
            </section>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="secondary"
              onClick={() => onOpenChange(false)}
            >
              Cancelar
            </Button>
            <Button type="submit" disabled={submitDisabled}>
              {needsPreview ? "Gerar prévia" : "Iniciar transferência"}{" "}
              <ArrowRight />
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
