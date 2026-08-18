import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
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
import { CopyDialog } from "@/components/files/CopyDialog";
import { MediaPreviewDialog } from "@/components/files/MediaPreviewDialog";
import { TextEditorDialog } from "@/components/files/TextEditorDialog";

type ClipboardItem = {
  entry: FileEntry;
  operation: "copy" | "move";
  mountId: string;
};

export default function FileBrowserPage() {
  const { mountId } = useParams();
  const { nodeId, mounts, nodePath, refreshJobs } = useWorkspace();
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
  const [clipboard, setClipboard] = useState<ClipboardItem | null>(null);
  const [pasteSource, setPasteSource] = useState<FileEntry | null>(null);
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
      if (clipboard?.entry.path === entry.path) setClipboard(null);
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
  const canPaste =
    Boolean(clipboard) &&
    clipboard?.mountId === mount.mount_id &&
    writable &&
    hasPermission(nodePath("jobs"), "create") &&
    (clipboard?.operation === "copy"
      ? hasPermission(filePolicyPath, "create") &&
        hasPermission(filePolicyPath, "read")
      : hasPermission(filePolicyPath, "update"));

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

      {clipboard && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border bg-muted/30 px-3 py-2 text-sm">
          <span>
            {clipboard.operation === "copy" ? "Copiado" : "Recortado"}: {clipboard.entry.name}
          </span>
          <div className="flex gap-2">
            <Button size="sm" onClick={() => setPasteSource(clipboard.entry)} disabled={!canPaste}>
              Colar aqui
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setClipboard(null)}>
              Cancelar
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
        onCopy={(entry) =>
          setClipboard({ entry, operation: "copy", mountId: mount.mount_id })
        }
        onMove={(entry) =>
          setClipboard({ entry, operation: "move", mountId: mount.mount_id })
        }
        onRemove={removeEntry}
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

      <CopyDialog
        source={pasteSource}
        currentPath={currentPath}
        mount={mount}
        operation={clipboard?.operation || "copy"}
        onClose={() => setPasteSource(null)}
        onCompleted={() => {
          if (clipboard?.operation === "move") setClipboard(null);
        }}
      />
    </div>
  );
}
