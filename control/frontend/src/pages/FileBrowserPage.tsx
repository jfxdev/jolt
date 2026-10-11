import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { Copy, MoveRight } from "lucide-react";
import { api } from "@/lib/api";
import type { FileEntry } from "@/lib/types";
import { useWorkspace } from "@/context/WorkspaceContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm } from "@/context/ConfirmProvider";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { FileTable } from "@/components/files/FileTable";
import { CrossNodeTransferDialog } from "@/components/files/CrossNodeTransferDialog";
import { MediaPreviewDialog } from "@/components/files/MediaPreviewDialog";
import { TextEditorDialog } from "@/components/files/TextEditorDialog";

type TransferSelection = {
  entries: FileEntry[];
  operation: "copy" | "move";
};

export default function FileBrowserPage() {
  const { mountId } = useParams();
  const { nodeId, mounts, refreshJobs } = useWorkspace();
  const { loadPermissions, hasPermission, hasPermissionNow } = usePermissions();
  const handleError = useApiError();
  const confirm = useConfirm();

  const mount = useMemo(
    () => mounts.find((m) => m.mount_id === mountId),
    [mounts, mountId],
  );

  const [currentPath, setCurrentPath] = useState("");
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [newDirectory, setNewDirectory] = useState("");
  const [selectedEntries, setSelectedEntries] = useState<FileEntry[]>([]);
  const [transfer, setTransfer] = useState<TransferSelection | null>(null);
  const [transferLimit, setTransferLimit] = useState(1000);
  const [preview, setPreview] = useState<FileEntry | null>(null);
  const [editor, setEditor] = useState<FileEntry | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const filePolicyPath = mount
    ? `nodes/${nodeId}/files/mounts/${mount.mount_id}`
    : "";
  const editorMountID = mount?.mount_id;

  const loadFiles = useCallback(
    async (path: string) => {
      if (!mountId) return;
      setLoading(true);
      try {
        const result = await api.files(nodeId, mountId, path);
        setFiles(result.items || []);
        setSelectedEntries([]);
        setCurrentPath(path);
      } catch (error) {
        handleError(error);
      } finally {
        setLoading(false);
      }
    },
    [nodeId, mountId, handleError],
  );

  useEffect(() => {
    if (!mount) return;
    let active = true;
    (async () => {
      const path = `nodes/${nodeId}/files/mounts/${mount.mount_id}`;
      await loadPermissions([path]);
      if (!active) return;
      if (hasPermissionNow(path, "list")) await loadFiles("");
      else setFiles([]);
    })();
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeId, mount?.mount_id]);

  const breadcrumbs = useMemo(() => {
    const parts = currentPath.split("/").filter(Boolean);
    return [
      { label: mount?.name || "Mount", path: "" },
      ...parts.map((part, index) => ({
        label: part,
        path: parts.slice(0, index + 1).join("/"),
      })),
    ];
  }, [currentPath, mount?.name]);

  async function downloadEntry(entry: FileEntry) {
    if (entry.type === "directory") {
      await loadFiles(entry.path);
    } else {
      if (!hasPermission(filePolicyPath, "read")) {
        toast.error("A policy atual não permite baixar arquivos deste mount.");
        return;
      }
      window.location.href = api.downloadUrl(nodeId, mount!.mount_id, entry.path);
    }
  }

  function previewEntry(entry: FileEntry) {
    setPreview(entry);
  }

  function editEntry(entry: FileEntry) {
    setEditor(entry);
  }

  const loadEditorContent = useCallback(
    (entry: FileEntry) => {
      if (!editorMountID) return Promise.reject(new Error("Mount não encontrado."));
      return api.editorContent(nodeId, editorMountID, entry.path);
    },
    [editorMountID, nodeId],
  );

  const saveEditorContent = useCallback(
    async (entry: FileEntry, content: string) => {
      if (!editorMountID) throw new Error("Mount não encontrado.");
      await api.saveEditorContent(nodeId, editorMountID, entry.path, content);
      await Promise.all([loadFiles(currentPath), refreshJobs()]);
      toast.success("Arquivo salvo.");
    },
    [currentPath, editorMountID, loadFiles, nodeId, refreshJobs],
  );

  async function createDirectory(event: React.FormEvent) {
    event.preventDefault();
    const name = newDirectory.trim();
    if (!name || !mount) return;
    const path = [currentPath, name].filter(Boolean).join("/");
    try {
      await api.mkdir(nodeId, mount.mount_id, path);
      setNewDirectory("");
      await Promise.all([loadFiles(currentPath), refreshJobs()]);
      toast.success("Pasta criada.");
    } catch (error) {
      handleError(error);
    }
  }

  async function upload(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file || !mount) return;
    const path = [currentPath, file.name].filter(Boolean).join("/");
    try {
      await api.upload(nodeId, mount.mount_id, path, file);
      await Promise.all([loadFiles(currentPath), refreshJobs()]);
      toast.success(`${file.name} enviado.`);
    } catch (error) {
      handleError(error);
    } finally {
      event.target.value = "";
    }
  }

  async function removeEntry(entry: FileEntry) {
    if (
      !(await confirm({
        title: `Remover “${entry.name}”?`,
        confirmText: "Remover",
        destructive: true,
      }))
    )
      return;
    if (!mount) return;
    try {
      await api.removeFile(
        nodeId,
        mount.mount_id,
        entry.path,
        entry.type === "directory",
      );
      await Promise.all([loadFiles(currentPath), refreshJobs()]);
      toast.success("Item removido.");
    } catch (error) {
      handleError(error);
    }
  }

  if (!mount) {
    return <p className="text-sm text-muted-foreground">Carregando mount…</p>;
  }

  const writable = mount.mode === "read_write";
  const canCreate = writable && hasPermission(filePolicyPath, "create");
  const canTransferCopy = hasPermission(filePolicyPath, "read");
  const canTransferMove = writable && canTransferCopy && hasPermission(filePolicyPath, "delete");

  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <Breadcrumb>
          <BreadcrumbList>
            {breadcrumbs.map((crumb, index) => (
              <BreadcrumbItem key={crumb.path}>
                {index > 0 && <BreadcrumbSeparator />}
                <button
                  className="transition-colors hover:text-foreground"
                  onClick={() => loadFiles(crumb.path)}
                >
                  {crumb.label}
                </button>
              </BreadcrumbItem>
            ))}
          </BreadcrumbList>
        </Breadcrumb>

        {canCreate && (
          <div className="flex items-center gap-2">
            <form className="flex gap-2" onSubmit={createDirectory}>
              <Input
                value={newDirectory}
                placeholder="Nova pasta"
                className="h-9 w-40"
                onChange={(e) => setNewDirectory(e.target.value)}
              />
              <Button variant="secondary" size="sm" type="submit">
                Criar
              </Button>
            </form>
            <Button size="sm" onClick={() => fileInput.current?.click()}>
              Enviar arquivo
            </Button>
            <input
              ref={fileInput}
              type="file"
              hidden
              onChange={upload}
            />
          </div>
        )}
      </div>

      {selectedEntries.length > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border bg-muted/30 px-3 py-2">
          <p className="text-sm">
            {selectedEntries.length} item{selectedEntries.length === 1 ? "" : "ns"} selecionado{selectedEntries.length === 1 ? "" : "s"}
          </p>
          <div className="flex gap-2">
            <Button size="sm" variant="secondary" disabled={!canTransferCopy} onClick={() => setTransfer({ entries: selectedEntries, operation: "copy" })}>
              <Copy /> Copiar para…
            </Button>
            <Button size="sm" disabled={!canTransferMove} onClick={() => setTransfer({ entries: selectedEntries, operation: "move" })}>
              <MoveRight /> Mover para…
            </Button>
          </div>
        </div>
      )}

      <FileTable
        files={files}
        loading={loading}
        writable={writable}
        filePolicyPath={filePolicyPath}
        onDownload={downloadEntry}
        onPreview={previewEntry}
        onEdit={editEntry}
        onTransferCopy={(entries) => setTransfer({ entries, operation: "copy" })}
        onTransferMove={(entries) => setTransfer({ entries, operation: "move" })}
        onRemove={removeEntry}
        selectedPaths={selectedEntries.map((entry) => entry.path)}
        selectionLimit={transferLimit}
        onSelectionChange={setSelectedEntries}
        onSelectionLimitReached={() => toast.error(`O limite de ${transferLimit} raízes selecionadas foi atingido. Remova uma seleção para adicionar outra.`)}
      />
      <MediaPreviewDialog
        entry={preview}
        url={
          preview && mount
            ? api.previewUrl(nodeId, mount.mount_id, preview.path)
            : null
        }
        onClose={() => setPreview(null)}
      />
      <TextEditorDialog
        entry={editor}
        load={loadEditorContent}
        save={saveEditorContent}
        onClose={() => setEditor(null)}
        onError={handleError}
      />

      <CrossNodeTransferDialog
        open={transfer !== null}
        entries={transfer?.entries || []}
        mount={mount}
        operation={transfer?.operation || "copy"}
        onClose={() => setTransfer(null)}
        onLimitResolved={setTransferLimit}
      />
    </div>
  );
}
