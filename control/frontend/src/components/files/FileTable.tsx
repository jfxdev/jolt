import {
  Copy,
  Download,
  Eye,
  FilePenLine,
  FolderOpen,
  MoveRight,
  Trash2,
} from "lucide-react";
import { mediaInfoForFilename } from "@/lib/media";
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

interface Props {
  files: FileEntry[];
  loading: boolean;
  writable: boolean;
  filePolicyPath: string;
  onDownload: (entry: FileEntry) => void;
  onPreview: (entry: FileEntry) => void;
  onEdit: (entry: FileEntry) => void;
  onTransferCopy: (entries: FileEntry[]) => void;
  onTransferMove: (entries: FileEntry[]) => void;
  onRemove: (entry: FileEntry) => void;
  selectedPaths: string[];
  selectionLimit: number;
  onSelectionChange: (entries: FileEntry[]) => void;
  onSelectionLimitReached: () => void;
}

export function FileTable({
  files,
  loading,
  writable,
  filePolicyPath,
  onDownload,
  onPreview,
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

  const canRemove = writable && hasPermission(filePolicyPath, "delete");
  const canRead = hasPermission(filePolicyPath, "read");
  const canTransferCopy = canRead;
  const canTransferMove = canRead && canRemove;
  const selected = new Set(selectedPaths);
  const selectable = files.filter((entry) => entry.type !== "symlink");
  const allSelected = selectable.length > 0 && selectable.every((entry) => selected.has(entry.path));

  function setSelected(entry: FileEntry, checked: boolean) {
    if (entry.type === "symlink") return;
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
            <TableHead className="w-32">Tamanho</TableHead>
            <TableHead className="w-44">Modificado</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {files.map((entry) => (
            <ContextMenu key={entry.path}>
              <ContextMenuTrigger
                render={
                  <TableRow
                    className="cursor-pointer"
                    tabIndex={0}
                    aria-label={`Ações para ${entry.name}`}
                    onDoubleClick={() => onDownload(entry)}
                  />
                }
              >
                <TableCell onClick={(event) => event.stopPropagation()}>
                  <Checkbox
                    aria-label={`Selecionar ${entry.name}`}
                    checked={selected.has(entry.path)}
                    disabled={entry.type === "symlink"}
                    title={entry.type === "symlink" ? "Links simbólicos não podem ser transferidos" : undefined}
                    onCheckedChange={(checked) => setSelected(entry, checked === true)}
                  />
                </TableCell>
                <TableCell>
                  <button
                    className="flex items-center gap-2 text-left hover:underline"
                    onClick={() => onDownload(entry)}
                  >
                    <FileEntryIcon entry={entry} />
                    {entry.name}
                  </button>
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {entry.type === "directory" ? "—" : formatBytes(entry.size)}
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {formatDate(entry.modified_at)}
                </TableCell>
              </ContextMenuTrigger>
              <ContextMenuContent>
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
              </ContextMenuContent>
            </ContextMenu>
          ))}
          {!files.length && !loading && (
            <TableRow>
              <TableCell
                colSpan={4}
                className="py-8 text-center text-sm text-muted-foreground"
              >
                Esta pasta está vazia.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  );
}
