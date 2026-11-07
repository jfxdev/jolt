import {
  Copy,
  Download,
  Eye,
  FilePenLine,
  FolderArchive,
  FolderOpen,
  Link2,
  Lock,
  MoveRight,
  Trash2,
} from "lucide-react";
import { mediaInfoForFilename } from "@/lib/media";
import { fileEntryDisplayName } from "@/lib/display-name";
import { FileEntryIcon } from "@/components/files/FileEntryIcon";
import {
  isEditableTextFilename,
  isWithinTextEditorLimit,
  TEXT_EDITOR_MAX_BYTES,
} from "@/lib/text-editor";
import type { FileEntry } from "@/lib/types";
import { usePermissions } from "@/context/PermissionsContext";
import { formatBytes, formatDate } from "@/lib/format";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const BLOCKED_MESSAGE = "Bloqueado pela política de acesso: o arquivo aparece, mas não pode ser aberto, baixado nem alterado.";

interface Props {
  files: FileEntry[];
  /** Set while the disk usage view is on: sizes become allocated bytes and a
   * Participação column shows each entry's share of this total. */
  diskUsageTotal?: number;
  emptyMessage?: string;
  loading: boolean;
  writable: boolean;
  filePolicyPath: string;
  onDownload: (entry: FileEntry) => void;
  onPreview: (entry: FileEntry) => void;
  onEdit: (entry: FileEntry) => void;
  /** onShare and onArchive are omitted when the caller cannot read the path,
   * so the actions never render as enabled-but-forbidden. */
  onShare?: (entry: FileEntry) => void;
  onArchive?: (entry: FileEntry) => void;
  onTransferCopy: (entries: FileEntry[]) => void;
  onTransferMove: (entries: FileEntry[]) => void;
  onRemove: (entry: FileEntry) => void;
  selectedPaths: string[];
  selectionLimit: number;
  onSelectionChange: (entries: FileEntry[]) => void;
  onSelectionLimitReached: () => void;
}

const percentage = new Intl.NumberFormat("pt-BR", {
  minimumFractionDigits: 0,
  maximumFractionDigits: 1,
});

export function FileTable({
  files,
  diskUsageTotal,
  emptyMessage = "Esta pasta está vazia.",
  loading,
  writable,
  filePolicyPath,
  onDownload,
  onPreview,
  onShare,
  onArchive,
  onEdit,
  onTransferCopy,
  onTransferMove,
  onRemove,
  selectedPaths,
  selectionLimit,
  onSelectionChange,
  onSelectionLimitReached,
}: Props) {
  const { hasPermission } = usePermissions();
  const usageMode = diskUsageTotal !== undefined;
  const columns = usageMode ? 5 : 4;

  const canRemove = writable && hasPermission(filePolicyPath, "delete");
  const canRead = hasPermission(filePolicyPath, "read");
  const canTransferCopy = canRead;
  const canTransferMove = canRead && canRemove;
  const selected = new Set(selectedPaths);
  const selectable = files.filter((entry) => entry.type !== "symlink" && !entry.blocked);
  const allSelected = selectable.length > 0 && selectable.every((entry) => selected.has(entry.path));

  function setSelected(entry: FileEntry, checked: boolean) {
    if (entry.type === "symlink" || entry.blocked) return;
    const next = new Set(selectedPaths);
    if (checked) {
      if (!next.has(entry.path) && next.size >= selectionLimit) {
        onSelectionLimitReached();
        return;
      }
      next.add(entry.path);
    } else {
      next.delete(entry.path);
    }
    onSelectionChange(files.filter((item) => next.has(item.path)));
  }

  function selectAll(checked: boolean) {
    if (!checked) {
      onSelectionChange([]);
      return;
    }
    if (selectable.length > selectionLimit) {
      onSelectionChange(selectable.slice(0, selectionLimit));
      onSelectionLimitReached();
      return;
    }
    onSelectionChange(selectable);
  }

  return (
    <div className="rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-10">
              <Checkbox
                aria-label="Selecionar todos os itens desta pasta"
                checked={allSelected}
                disabled={!selectable.length}
                onCheckedChange={(checked) => selectAll(checked === true)}
              />
            </TableHead>
            <TableHead>Nome</TableHead>
            <TableHead className="w-32">{usageMode ? "Uso em disco" : "Tamanho"}</TableHead>
            {usageMode && <TableHead className="w-56">Participação</TableHead>}
            <TableHead className="w-44">Modificado</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {files.map((entry) => (
            <ContextMenu key={entry.path}>
              <ContextMenuTrigger
                render={
                  <TableRow
                    className={entry.blocked ? "cursor-not-allowed text-muted-foreground" : "cursor-pointer"}
                    tabIndex={0}
                    aria-label={`Ações para ${fileEntryDisplayName(entry)}`}
                    title={entry.blocked ? BLOCKED_MESSAGE : undefined}
                    data-blocked={entry.blocked ? "true" : undefined}
                    onDoubleClick={() => {
                      if (!entry.blocked) onDownload(entry);
                    }}
                  />
                }
              >
                <TableCell onClick={(event) => event.stopPropagation()}>
                  <Checkbox
                    aria-label={`Selecionar ${fileEntryDisplayName(entry)}`}
                    checked={selected.has(entry.path)}
                    disabled={entry.type === "symlink" || entry.blocked}
                    title={
                      entry.blocked
                        ? BLOCKED_MESSAGE
                        : entry.type === "symlink"
                          ? "Links simbólicos não podem ser transferidos"
                          : undefined
                    }
                    onCheckedChange={(checked) => setSelected(entry, checked === true)}
                  />
                </TableCell>
                <TableCell>
                  <button
                    className="flex items-center gap-2 text-left hover:underline disabled:no-underline"
                    disabled={entry.blocked}
                    onClick={() => onDownload(entry)}
                  >
                    <FileEntryIcon entry={entry} />
                    {fileEntryDisplayName(entry)}
                    {entry.blocked && (
                      <>
                        <Lock aria-hidden="true" className="size-3.5 shrink-0" />
                        <span className="sr-only">Bloqueado pela política de acesso</span>
                      </>
                    )}
                  </button>
                </TableCell>
                {usageMode ? (
                  <>
                    <TableCell className="font-medium" title={`Tamanho aparente: ${formatBytes(entry.size)}`}>
                      {formatBytes(entry.disk_usage || 0)}
                    </TableCell>
                    <TableCell>
                      <UsageShare usage={entry.disk_usage || 0} total={diskUsageTotal} />
                    </TableCell>
                  </>
                ) : (
                  <TableCell className="text-muted-foreground">
                    {entry.type === "directory" ? "—" : formatBytes(entry.size)}
                  </TableCell>
                )}
                <TableCell className="text-muted-foreground">
                  {formatDate(entry.modified_at)}
                </TableCell>
              </ContextMenuTrigger>
              <ContextMenuContent>
                {entry.blocked ? (
                  <ContextMenuItem disabled>
                    <Lock />
                    Bloqueado pela política de acesso
                  </ContextMenuItem>
                ) : (
                  <>
                <ContextMenuItem onClick={() => onDownload(entry)}>
                  {entry.type === "directory" ? <FolderOpen /> : <Download />}
                  {entry.type === "directory" ? "Abrir" : "Baixar"}
                </ContextMenuItem>
                {entry.type === "file" &&
                  canRead &&
                  mediaInfoForFilename(entry.name) && (
                    <ContextMenuItem onClick={() => onPreview(entry)}>
                      <Eye />
                      Ver
                    </ContextMenuItem>
                  )}
                {entry.type === "file" && canRead && isEditableTextFilename(entry.name) && (
                  <ContextMenuItem
                    disabled={!isWithinTextEditorLimit(entry.size)}
                    title={
                      isWithinTextEditorLimit(entry.size)
                        ? "Editar arquivo"
                        : `O editor aceita arquivos de até ${TEXT_EDITOR_MAX_BYTES / 1024} KB`
                    }
                    onClick={() => onEdit(entry)}
                  >
                    <FilePenLine />
                    Editar
                  </ContextMenuItem>
                )}
                {onArchive && entry.type === "directory" && (
                  <ContextMenuItem onClick={() => onArchive(entry)}>
                    <FolderArchive />
                    Baixar como .zip
                  </ContextMenuItem>
                )}
                {onShare && entry.type !== "symlink" && (
                  <ContextMenuItem onClick={() => onShare(entry)}>
                    <Link2 />
                    Criar link público…
                  </ContextMenuItem>
                )}
                {(canTransferCopy || canTransferMove || canRemove) && <ContextMenuSeparator />}
                {canTransferCopy && entry.type !== "symlink" && (
                  <ContextMenuItem onClick={() => onTransferCopy([entry])}>
                    <Copy />
                    Copiar para…
                  </ContextMenuItem>
                )}
                {canTransferMove && entry.type !== "symlink" && (
                  <ContextMenuItem onClick={() => onTransferMove([entry])}>
                    <MoveRight />
                    Mover para…
                  </ContextMenuItem>
                )}
                {canRemove && (
                  <ContextMenuItem variant="destructive" onClick={() => onRemove(entry)}>
                    <Trash2 />
                    Remover
                  </ContextMenuItem>
                )}
                  </>
                )}
              </ContextMenuContent>
            </ContextMenu>
          ))}
          {!files.length && !loading && (
            <TableRow>
              <TableCell
                colSpan={columns}
                className="py-8 text-center text-sm text-muted-foreground"
              >
                {emptyMessage}
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  );
}

function UsageShare({ usage, total }: { usage: number; total: number }) {
  const share = total > 0 ? (usage / total) * 100 : 0;
  return (
    <div className="flex items-center gap-3">
      <div className="h-2 min-w-20 flex-1 overflow-hidden rounded-full bg-muted" aria-hidden="true">
        <div className="h-full rounded-full bg-primary" style={{ width: `${Math.min(100, share)}%` }} />
      </div>
      <span className="w-12 text-right text-xs text-muted-foreground">{percentage.format(share)}%</span>
    </div>
  );
}
