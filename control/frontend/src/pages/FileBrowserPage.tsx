import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { ArrowUpDown, ChartColumn, Copy, FolderArchive, MoreHorizontal, MoveRight, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import { fileEntryDisplayName, safeDisplayName } from "@/lib/display-name";
import type { DiskUsageResponse, FileEntry, SearchResponse } from "@/lib/types";
import { useWorkspace } from "@/context/WorkspaceContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm } from "@/context/ConfirmProvider";
import { formatBytes } from "@/lib/format";
import { destructivePlanDescription, planUnavailable, type DestructivePlan } from "@/lib/destructive-plan";
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
import { DiskUsageNotices, DiskUsageTotal } from "@/components/files/DiskUsageSummary";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Separator } from "@/components/ui/separator";
import { Toggle } from "@/components/ui/toggle";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { CrossNodeTransferDialog } from "@/components/files/CrossNodeTransferDialog";
import { MediaPreviewDialog } from "@/components/files/MediaPreviewDialog";
import { TextEditorDialog } from "@/components/files/TextEditorDialog";
import { FileSearchBar } from "@/components/files/FileSearchBar";
import { ShareDialog } from "@/components/files/ShareDialog";
import { UploadQueue, type UploadItem } from "@/components/files/UploadQueue";
import { useResumableUploads } from "@/hooks/useResumableUploads";
import { asPendingApproval, pendingToast } from "@/lib/approvals";
import { removeDescription, removedNotice, trashDays } from "@/lib/trash";
import { TrashDialog } from "@/components/files/TrashDialog";

type TransferSelection = {
  entries: FileEntry[];
  operation: "copy" | "move";
};

export default function FileBrowserPage() {
  const { mountId } = useParams();
  const { nodeId, node, mounts, refreshJobs } = useWorkspace();
  const { loadPermissions, hasPermission, hasPermissionNow } = usePermissions();
  const handleError = useApiError();
  const confirm = useConfirm();

  const mount = useMemo(
    () => mounts.find((m) => m.mount_id === mountId),
    [mounts, mountId],
  );

  // Names the target of every destructive confirmation: mount names repeat
  // across nodes, so the path alone does not say where an action lands.
  const where = [node?.name, mount?.name].filter(Boolean).join(" / ");

  useEffect(() => {
    const previous = document.title;
    if (where) document.title = `${where} · Jolt`;
    return () => {
      document.title = previous;
    };
  }, [where]);

  const [currentPath, setCurrentPath] = useState("");
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [diskUsageMode, setDiskUsageMode] = useState(false);
  const [diskUsage, setDiskUsage] = useState<DiskUsageResponse | null>(null);
  const [largestFirst, setLargestFirst] = useState(false);
  // The disk usage view filters its own folder listing, since search results
  // carry no allocated sizes.
  const [usageFilter, setUsageFilter] = useState<{ query: string; type: "" | "file" | "directory" } | null>(null);
  const [loading, setLoading] = useState(false);
  const [nextAfter, setNextAfter] = useState("");
  const listingSequence = useRef(0);
  const targetRef = useRef("");
  targetRef.current = `${nodeId}:${mountId}`;
  const [newDirectory, setNewDirectory] = useState("");
  const [selectedEntries, setSelectedEntries] = useState<FileEntry[]>([]);
  const [transfer, setTransfer] = useState<TransferSelection | null>(null);
  const [transferLimit, setTransferLimit] = useState(1000);
  const [preview, setPreview] = useState<FileEntry | null>(null);
  const [editor, setEditor] = useState<FileEntry | null>(null);
  const [sharing, setSharing] = useState<FileEntry | null>(null);
  const [trashOpen, setTrashOpen] = useState(false);
  const [searchResult, setSearchResult] = useState<SearchResponse | null>(null);
  const [searching, setSearching] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const searchSequence = useRef(0);

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

  // An upload can outlive the folder it started in, so completion refreshes
  // whatever folder is on screen rather than the one captured at start.
  const currentPathRef = useRef(currentPath);
  useEffect(() => {
    currentPathRef.current = currentPath;
  }, [currentPath]);

  const { uploads, start: startUpload, cancel, retry, replace, dismiss, reselect, recoveryError, refreshSessions } =
    useResumableUploads({
      nodeId,
      mountId: mount?.mount_id,
      destinationLabel: [node?.name, mount?.name].filter(Boolean).join(" / "),
      onFinished: async () => {
        await Promise.all([
          loadDirectoryRef.current(currentPathRef.current),
          refreshJobs(),
        ]);
      },
      onError: handleError,
    });

  const loadFiles = useCallback(
    async (path: string, after = "") => {
      if (!mountId) return;
      const sequence = ++listingSequence.current;
      const target = `${nodeId}:${mountId}`;
      setLoading(true);
      // Navigating away invalidates a search in flight for the old folder.
      searchSequence.current += 1;
      setSearchResult(null);
      setSearching(false);
      try {
        const result = await api.files(nodeId, mountId, path, after);
        if (sequence !== listingSequence.current || targetRef.current !== target) return;
        setFiles(previous => {
          if (!after) return result.items || [];
          const seen = new Set(previous.map(item => item.path));
          return [...previous, ...(result.items || []).filter(item => !seen.has(item.path))];
        });
        setNextAfter(result.next_after || "");
        if (!after) setSelectedEntries([]);
        setCurrentPath(path);
      } catch (error) {
        if (sequence === listingSequence.current && targetRef.current === target) handleError(error);
      } finally {
        if (sequence === listingSequence.current && targetRef.current === target) setLoading(false);
      }
    },
    [nodeId, mountId, handleError],
  );

  const loadDiskUsage = useCallback(
    async (path: string) => {
      if (!mountId) return;
      const sequence = ++listingSequence.current;
      const target = `${nodeId}:${mountId}`;
      setLoading(true);
      searchSequence.current += 1;
      setSearchResult(null);
      setSearching(false);
      try {
        const result = await api.diskUsage(nodeId, mountId, path);
        if (sequence !== listingSequence.current || targetRef.current !== target) return;
        setDiskUsage(result);
        setNextAfter("");
        setSelectedEntries([]);
        setCurrentPath(path);
      } catch (error) {
        if (sequence === listingSequence.current && targetRef.current === target) handleError(error);
      } finally {
        if (sequence === listingSequence.current && targetRef.current === target) setLoading(false);
      }
    },
    [nodeId, mountId, handleError],
  );

  const loadDirectory = useCallback(
    async (path: string, after = "") => {
      if (diskUsageMode && !after) await loadDiskUsage(path);
      else await loadFiles(path, after);
    },
    [diskUsageMode, loadDiskUsage, loadFiles],
  );

  // Upload completion refreshes whichever view is active; a ref keeps that callback stable.
  const loadDirectoryRef = useRef(loadDirectory);
  useEffect(() => {
    loadDirectoryRef.current = loadDirectory;
  }, [loadDirectory]);

  useEffect(() => {
    listingSequence.current++;
    searchSequence.current++;
    setFiles([]); setNextAfter(""); setSelectedEntries([]); setCurrentPath("");
    setDiskUsageMode(false); setDiskUsage(null);
    setPreview(null); setEditor(null); setSharing(null); setTransfer(null); setSearchResult(null);
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
        label: safeDisplayName(part),
        path: parts.slice(0, index + 1).join("/"),
      })),
    ];
  }, [currentPath, mount?.name]);

  const usageEntries = useMemo(() => {
    const entries = diskUsage?.entries || [];
    if (!usageFilter) return entries;
    const query = usageFilter.query.toLowerCase();
    return entries.filter(
      (entry) =>
        (!usageFilter.type || entry.type === usageFilter.type) &&
        fileEntryDisplayName(entry).toLowerCase().includes(query),
    );
  }, [diskUsage, usageFilter]);
  const listed = diskUsageMode ? usageEntries : searchResult ? searchResult.entries : files;
  const visibleFiles = useMemo(() => {
    if (!largestFirst) return listed;
    const weight = (entry: FileEntry) => entry.disk_usage ?? (entry.type === "directory" ? 0 : entry.size ?? 0);
    return [...listed].sort((a, b) => weight(b) - weight(a) || a.name.localeCompare(b.name));
  }, [listed, largestFirst]);

  async function downloadEntry(entry: FileEntry) {
    if (entry.type === "directory") {
      await loadDirectory(entry.path);
    } else {
      if (!hasPermission(filePolicyPath, "read")) {
        toast.error("A policy atual não permite baixar arquivos desta pasta.");
        return;
      }
      window.location.href = api.downloadUrl(nodeId, mount!.mount_id, entry.path);
    }
  }

  async function changeDiskUsageMode(checked: boolean) {
    setDiskUsageMode(checked);
    setSelectedEntries([]);
    // Disk usage is mostly asked to find what is big, so it starts sorted that way.
    setLargestFirst(checked);
    if (checked) {
      // A previous scan must not stay listed (or selectable) while this one
      // runs, or after it fails.
      setDiskUsage(null);
      await loadDiskUsage(currentPath);
    }
    else await loadFiles(currentPath);
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
      // An empty selection archives the whole folder.
      const target =
        names.length === 0
          ? `a pasta “${breadcrumbs[breadcrumbs.length - 1]?.label || "Mount"}”`
          : names.length === 1
            ? `“${fileEntryDisplayName(entries[0])}”`
            : `${names.length} itens`;
      if (
        !(await confirm({
          title: `Baixar ${target} como .zip?`,
          description: `Em ${where}. ${plan.files} arquivo${plan.files === 1 ? "" : "s"} · ${formatBytes(plan.bytes)}${
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
      // Responses can arrive out of order, so only the newest request is
      // allowed to publish its result or clear the spinner.
      const sequence = searchSequence.current + 1;
      searchSequence.current = sequence;
      setSearching(true);
      try {
        const result = await api.search(nodeId, mount.mount_id, currentPath, {
          query,
          type: type || undefined,
        });
        if (searchSequence.current === sequence) setSearchResult(result);
      } catch (error) {
        if (searchSequence.current === sequence) {
          handleError(error);
          setSearchResult(null);
        }
      } finally {
        if (searchSequence.current === sequence) setSearching(false);
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
      await Promise.all([loadDirectory(currentPath), refreshJobs()]);
      toast.success("Arquivo salvo.");
    },
    [currentPath, editorMountID, loadDirectory, nodeId, refreshJobs],
  );

  async function createDirectory(event: React.FormEvent) {
    event.preventDefault();
    const name = newDirectory.trim();
    if (!name || !mount) return;
    const path = [currentPath, name].filter(Boolean).join("/");
    try {
      await api.mkdir(nodeId, mount.mount_id, path);
      setNewDirectory("");
      await Promise.all([loadDirectory(currentPath), refreshJobs()]);
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

  // A directory goes through a plan: the node counts what would be removed, the
  // operator confirms those numbers, and the node checks the tree is unchanged
  // before it deletes anything. Without plans on the Control Tower, the direct
  // route applies as before.
  async function removeDirectory(entry: FileEntry): Promise<boolean> {
    if (!mount) return true;
    let plan: DestructivePlan;
    try {
      const answer = await api.planDestructive(nodeId, mount.mount_id, {
        operation: "delete",
        source_path: entry.path,
      });
      // A policy may ask a person to approve a folder delete: no plan, no
      // confirmation here, and the approver sees the counts.
      const pending = asPendingApproval(answer);
      if (pending) {
        toast.info(pendingToast(pending));
        return true;
      }
      plan = answer as DestructivePlan;
    } catch (error) {
      if (planUnavailable(error as { code?: string; status?: number })) return false;
      handleError(error);
      return true;
    }
    try {
      const approved = await confirm({
        title: `Remover a pasta “${fileEntryDisplayName(entry)}”?`,
        description: `Em ${where}. ${destructivePlanDescription(plan, trashDays(mount))}`,
        confirmText: "Remover pasta",
        destructive: true,
      });
      if (!approved) return true;
      await api.confirmDestructive(nodeId, mount.mount_id, plan.plan_id, plan.token);
      await Promise.all([loadDirectory(currentPath), refreshJobs()]);
      toast.success(trashDays(mount) ? "A pasta será movida para a lixeira. Acompanhe nos jobs." : "Remoção iniciada. Acompanhe o andamento nos jobs.");
    } catch (error) {
      handleError(error);
    }
    return true;
  }

  async function removeEntry(entry: FileEntry) {
    if (entry.type === "directory" && (await removeDirectory(entry))) return;
    if (
      !(await confirm({
        title: `Remover “${fileEntryDisplayName(entry)}”?`,
        description: `Em ${where}. ${removeDescription(mount) ?? ""}`.trim(),
        confirmText: "Remover",
        destructive: true,
      }))
    )
      return;
    if (!mount) return;
    try {
      const answer = await api.removeFile(
        nodeId,
        mount.mount_id,
        entry.path,
        entry.type === "directory",
      );
      // A policy may ask a person to approve the delete first; nothing was
      // removed yet, so the listing stays as it is.
      const pending = asPendingApproval(answer);
      if (pending) {
        toast.info(pendingToast(pending));
        return;
      }
      await Promise.all([loadDirectory(currentPath), refreshJobs()]);
      toast.success(removedNotice(mount));
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
  // Disk usage and the selection actions share one floating bar.
  const floatingBar = diskUsageMode || selectedEntries.length > 0;

  return (
    <div className={floatingBar ? "grid gap-4 pb-28" : "grid gap-4"}>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <Breadcrumb>
          <BreadcrumbList>
            {breadcrumbs.map((crumb, index) => (
              <BreadcrumbItem key={crumb.path}>
                {index > 0 && <BreadcrumbSeparator />}
                <button
                  className="transition-colors hover:text-foreground"
                  onClick={() => void loadDirectory(crumb.path)}
                >
                  {crumb.label}
                </button>
              </BreadcrumbItem>
            ))}
          </BreadcrumbList>
        </Breadcrumb>

        <div className="flex items-center gap-2">
          {trashDays(mount) > 0 && canRead && (
            <Button variant="secondary" size="sm" onClick={() => setTrashOpen(true)}>
              <Trash2 /> Lixeira
            </Button>
          )}
          <Tooltip>
            <TooltipTrigger
              render={
                <Toggle
                  variant="outline"
                  size="sm"
                  aria-label="Maiores itens primeiro"
                  pressed={largestFirst}
                  onPressedChange={setLargestFirst}
                />
              }
            >
              <ArrowUpDown />
            </TooltipTrigger>
            <TooltipContent>
              {largestFirst && !diskUsageMode && !searchResult && nextAfter
                ? "Maiores itens primeiro (só entre os itens já carregados)"
                : "Maiores itens primeiro"}
            </TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger
              render={
                <Toggle
                  variant="outline"
                  size="sm"
                  aria-label="Exibir uso de disco"
                  pressed={diskUsageMode}
                  onPressedChange={(pressed) => void changeDiskUsageMode(pressed)}
                />
              }
            >
              <ChartColumn />
            </TooltipTrigger>
            <TooltipContent>Uso de disco</TooltipContent>
          </Tooltip>
          {canRead && (diskUsageMode ? diskUsage?.entries.length ?? 0 : files.length) > 0 && (
            <DropdownMenu>
              <DropdownMenuTrigger
                render={
                  <Button
                    variant="secondary"
                    size="icon-sm"
                    aria-label="Mais ações"
                    title="Mais ações"
                  />
                }
              >
                <MoreHorizontal />
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => void downloadArchive([])}>
                  <FolderArchive /> Baixar pasta (.zip)
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
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
        // Remounting on folder or view change clears the query text, so the box never
        // shows a stale term with no results beneath it.
        key={`${currentPath}:${diskUsageMode}`}
        scopeLabel={breadcrumbs[breadcrumbs.length - 1]?.label || "Mount"}
        searching={searching}
        result={diskUsageMode ? null : searchResult}
        onSearch={(query, type) => {
          if (diskUsageMode) setUsageFilter({ query, type });
          else void runSearch(query, type);
        }}
        onClear={() => {
          searchSequence.current += 1;
          // The invalidated search no longer reaches its own `finally`.
          setSearching(false);
          setSearchResult(null);
          setUsageFilter(null);
        }}
      />

      {recoveryError && <p role="status" className="text-sm text-destructive">{recoveryError} <Button variant="link" onClick={() => void refreshSessions()}>Tentar novamente</Button></p>}
      <UploadQueue
        items={uploads}
        onCancel={cancel}
        onRetry={retry}
        onReplace={replace}
        onDismiss={dismiss}
        onReselect={reselect}
      />

      {diskUsageMode && <DiskUsageNotices result={diskUsage} />}
      <FileTable
          files={visibleFiles}
          diskUsageTotal={diskUsageMode ? diskUsage?.total_bytes ?? 0 : undefined}
          emptyMessage={diskUsageMode ? (diskUsage ? (usageFilter ? "Nenhum resultado." : undefined) : loading ? "Analisando uso de disco…" : "Não foi possível analisar o uso de disco desta pasta.") : undefined}
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
      {!diskUsageMode && !searchResult && nextAfter && (
        <>
          {largestFirst && <p className="text-xs text-muted-foreground">Ordenado só entre os itens carregados. Carregue mais para incluir os demais.</p>}
          <Button variant="outline" disabled={loading} onClick={() => void loadFiles(currentPath, nextAfter)}>{loading ? "Carregando…" : "Carregar mais"}</Button>
        </>
      )}
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
      <TrashDialog
        open={trashOpen}
        nodeId={nodeId}
        nodeName={node?.name}
        mount={mount}
        canRestore={canCreate}
        canPurge={hasPermission(filePolicyPath, "delete")}
        onClose={() => setTrashOpen(false)}
        onRestored={() => void loadDirectory(currentPath)}
      />
      <ShareDialog
        entry={sharing}
        mount={mount}
        nodeId={nodeId}
        onClose={() => setSharing(null)}
      />

      {floatingBar && (
        <div className="fixed bottom-4 left-1/2 z-30 flex w-max max-w-[calc(100vw-2rem)] -translate-x-1/2 flex-wrap items-center justify-center gap-x-4 gap-y-2 rounded-lg border bg-popover px-4 py-3 text-popover-foreground shadow-lg">
          {diskUsageMode && <DiskUsageTotal result={diskUsage} loading={loading} />}
          {diskUsageMode && selectedEntries.length > 0 && (
            <Separator orientation="vertical" className="hidden h-8 sm:block" />
          )}
          {selectedEntries.length > 0 && (
            <div className="flex flex-wrap items-center justify-center gap-3">
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
        </div>
      )}

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
