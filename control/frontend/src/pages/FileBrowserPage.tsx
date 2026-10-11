import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { Copy, FolderArchive, MoveRight } from "lucide-react";
import { api } from "@/lib/api";
import type { FileEntry, SearchResponse } from "@/lib/types";
import { useWorkspace } from "@/context/WorkspaceContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm } from "@/context/ConfirmProvider";
import { formatBytes } from "@/lib/format";
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
import { FileSearchBar } from "@/components/files/FileSearchBar";
import { ShareDialog } from "@/components/files/ShareDialog";
import { UploadQueue, type UploadItem } from "@/components/files/UploadQueue";
import { useResumableUploads } from "@/hooks/useResumableUploads";

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
  const [sharing, setSharing] = useState<FileEntry | null>(null);
  const [searchResult, setSearchResult] = useState<SearchResponse | null>(null);
  const [searching, setSearching] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  // The mount root is what existing policies name; the current folder is what
  // a subpath policy names. Both are evaluated so the UI reflects whichever
  // grants access.
  const mountPolicyPath = mount
    ? `nodes/${nodeId}/files/mounts/${mount.mount_id}`
    : "";
  const filePolicyPath = useMemo(() => {
    if (!mountPolicyPath) return "";
    return currentPath ? `${mountPolicyPath}/${currentPath}` : mountPolicyPath;
  }, [mountPolicyPath, currentPath]);
  const editorMountID = mount?.mount_id;

  const { uploads, start: startUpload, cancel, retry, dismiss } =
    useResumableUploads({
      nodeId,
      mountId: mount?.mount_id,
      onFinished: async () => {
        await Promise.all([loadFilesRef.current(currentPath), refreshJobs()]);
      },
      onError: handleError,
    });

  const loadFiles = useCallback(
    async (path: string) => {
      if (!mountId) return;
      setLoading(true);
      setSearchResult(null);
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
  // Upload completion refreshes the listing; a ref keeps that callback stable.
  const loadFilesRef = useRef(loadFiles);
  useEffect(() => {
    loadFilesRef.current = loadFiles;
  }, [loadFiles]);

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

  // Permissions for the folder being viewed are loaded as the user navigates,
  // so a subpath rule that narrows or widens access is reflected in the UI.
  useEffect(() => {
    if (!filePolicyPath || filePolicyPath === mountPolicyPath) return;
    void loadPermissions([filePolicyPath]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filePolicyPath]);

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
        toast.error("A policy atual não permite baixar arquivos desta pasta.");
        return;
      }
      window.location.href = api.downloadUrl(nodeId, mount!.mount_id, entry.path);
    }
  }

  /** downloadArchive confirms the size first: a mistaken click on a multi-
   * terabyte folder should not silently start streaming it. */
  async function downloadArchive(entries: FileEntry[]) {
    if (!mount) return;
    if (!hasPermission(filePolicyPath, "read")) {
      toast.error("A policy atual não permite baixar arquivos desta pasta.");
      return;
    }
    const names = entries.map((entry) => entry.name);
    try {
      const plan = await api.archivePlan(nodeId, mount.mount_id, currentPath, names);
      const target =
        names.length === 1 ? `“${names[0]}”` : `${names.length} itens`;
      if (
        !(await confirm({
          title: `Baixar ${target} como .zip?`,
          description: `${plan.files} arquivo${plan.files === 1 ? "" : "s"} · ${formatBytes(plan.bytes)}${
            plan.skipped_symlinks > 0
              ? ` · ${plan.skipped_symlinks} link simbólico ignorado${plan.skipped_symlinks === 1 ? "" : "s"}`
              : ""
          }`,
          confirmText: "Baixar",
        }))
      )
        return;
      window.location.href = api.archiveUrl(
        nodeId,
        mount.mount_id,
        currentPath,
        names,
      );
    } catch (error) {
      handleError(error);
    }
  }

  const runSearch = useCallback(
    async (query: string, type: "" | "file" | "directory") => {
      if (!mount) return;
      setSearching(true);
      try {
        const result = await api.search(nodeId, mount.mount_id, currentPath, {
          query,
          type: type || undefined,
        });
        setSearchResult(result);
      } catch (error) {
        handleError(error);
        setSearchResult(null);
      } finally {
        setSearching(false);
      }
    },
    [currentPath, handleError, mount, nodeId],
  );

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

  function upload(event: React.ChangeEvent<HTMLInputElement>) {
    const chosen = Array.from(event.target.files || []);
    event.target.value = "";
    if (chosen.length === 0 || !mount) return;
    for (const file of chosen) {
      const path = [currentPath, file.name].filter(Boolean).join("/");
      startUpload(file, path);
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
  const canRead = hasPermission(filePolicyPath, "read");
  const canTransferCopy = canRead;
  const canTransferMove =
    writable && canTransferCopy && hasPermission(filePolicyPath, "delete");
  const visibleFiles = searchResult ? searchResult.entries : files;

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

        <div className="flex items-center gap-2">
          {canRead && files.length > 0 && (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => downloadArchive([])}
            >
              <FolderArchive /> Baixar pasta (.zip)
            </Button>
          )}
          {canCreate && (
            <>
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
                Enviar arquivos
              </Button>
              <input ref={fileInput} type="file" hidden multiple onChange={upload} />
            </>
          )}
        </div>
      </div>

      <FileSearchBar
        scopeLabel={breadcrumbs[breadcrumbs.length - 1]?.label || "Mount"}
        searching={searching}
        result={searchResult}
        onSearch={runSearch}
        onClear={() => setSearchResult(null)}
      />

      <UploadQueue
        items={uploads}
        onCancel={cancel}
        onRetry={retry}
        onDismiss={dismiss}
      />

      {selectedEntries.length > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border bg-muted/30 px-3 py-2">
          <p className="text-sm">
            {selectedEntries.length} item{selectedEntries.length === 1 ? "" : "ns"} selecionado{selectedEntries.length === 1 ? "" : "s"}
          </p>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="secondary"
              disabled={!canRead}
              onClick={() => downloadArchive(selectedEntries)}
            >
              <FolderArchive /> Baixar .zip
            </Button>
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
        files={visibleFiles}
        loading={loading}
        writable={writable}
        filePolicyPath={filePolicyPath}
        onDownload={downloadEntry}
        onPreview={previewEntry}
        onEdit={editEntry}
        onShare={canRead ? (entry) => setSharing(entry) : undefined}
        onArchive={canRead ? (entry) => downloadArchive([entry]) : undefined}
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
      <ShareDialog
        entry={sharing}
        mount={mount}
        nodeId={nodeId}
        onClose={() => setSharing(null)}
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

export type { UploadItem };
