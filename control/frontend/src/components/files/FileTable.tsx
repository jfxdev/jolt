import { Download, Eye, FilePenLine, Folder, File as FileIcon } from "lucide-react";
import { mediaInfoForFilename } from "@/lib/media";
import {
  isEditableTextFilename,
  isWithinTextEditorLimit,
  TEXT_EDITOR_MAX_BYTES,
} from "@/lib/text-editor";
import type { FileEntry } from "@/lib/types";
import { useWorkspace } from "@/context/WorkspaceContext";
import { usePermissions } from "@/context/PermissionsContext";
import { formatBytes, formatDate } from "@/lib/format";
import { Button } from "@/components/ui/button";
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
  onCopy: (entry: FileEntry) => void;
  onMove: (entry: FileEntry) => void;
  onRemove: (entry: FileEntry) => void;
}

export function FileTable({
  files,
  loading,
  writable,
  filePolicyPath,
  onDownload,
  onPreview,
  onEdit,
  onCopy,
  onMove,
  onRemove,
}: Props) {
  const { nodePath } = useWorkspace();
  const { hasPermission } = usePermissions();

  const canCopy =
    writable &&
    hasPermission(filePolicyPath, "read") &&
    hasPermission(filePolicyPath, "create") &&
    hasPermission(nodePath("jobs"), "create");
  const canRemove = writable && hasPermission(filePolicyPath, "delete");
  const canMove =
    writable &&
    hasPermission(filePolicyPath, "update") &&
    hasPermission(nodePath("jobs"), "create");
  const canRead = hasPermission(filePolicyPath, "read");

  return (
    <div className="rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Nome</TableHead>
            <TableHead className="w-32">Tamanho</TableHead>
            <TableHead className="w-44">Modificado</TableHead>
            <TableHead className="w-40 text-right"></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {files.map((entry) => (
            <TableRow
              key={entry.path}
              className="cursor-pointer"
              onDoubleClick={() => onDownload(entry)}
            >
              <TableCell>
                <button
                  className="flex items-center gap-2 text-left hover:underline"
                  onClick={() => onDownload(entry)}
                >
                  {entry.type === "directory" ? (
                    <Folder className="h-4 w-4 shrink-0 text-muted-foreground" />
                  ) : (
                    <FileIcon className="h-4 w-4 shrink-0 text-muted-foreground" />
                  )}
                  {entry.name}
                </button>
              </TableCell>
              <TableCell className="text-muted-foreground">
                {entry.type === "directory" ? "—" : formatBytes(entry.size)}
              </TableCell>
              <TableCell className="text-muted-foreground">
                {formatDate(entry.modified_at)}
              </TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-1">
                  {entry.type === "file" && canRead && mediaInfoForFilename(entry.name) && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        onPreview(entry);
                      }}
                    >
                      <Eye className="mr-1 h-4 w-4" />
                      Ver
                    </Button>
                  )}
                  {entry.type === "file" && canRead && isEditableTextFilename(entry.name) && (
                    <Button
                      variant="ghost"
                      size="sm"
                      title={
                        isWithinTextEditorLimit(entry.size)
                          ? "Editar arquivo"
                          : `O editor aceita arquivos de até ${TEXT_EDITOR_MAX_BYTES / 1024} KB`
                      }
                      disabled={!isWithinTextEditorLimit(entry.size)}
                      onClick={(e) => {
                        e.stopPropagation();
                        onEdit(entry);
                      }}
                    >
                      <FilePenLine className="mr-1 h-4 w-4" />
                      Editar
                    </Button>
                  )}
                  {entry.type === "file" && canRead && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        onDownload(entry);
                      }}
                    >
                      <Download className="mr-1 h-4 w-4" />
                      Baixar
                    </Button>
                  )}
                  {canCopy && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        onCopy(entry);
                      }}
                    >
                      Copiar
                    </Button>
                  )}
                  {canMove && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        onMove(entry);
                      }}
                    >
                      Mover
                    </Button>
                  )}
                  {canRemove && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        onRemove(entry);
                      }}
                    >
                      Remover
                    </Button>
                  )}
                </div>
              </TableCell>
            </TableRow>
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
