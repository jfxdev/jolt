import { useEffect, useState } from "react";
import { Folder, Home, ArrowUp, File, Link2, Check } from "lucide-react";
import { api } from "@/lib/api";
import type { FileEntry } from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  nodeId: string;
  onSelect: (path: string) => void;
}

export function NodeFileBrowserDialog({
  open,
  onOpenChange,
  nodeId,
  onSelect,
}: Props) {
  const handleError = useApiError();
  const [path, setPath] = useState<string | null>(null);
  const [home, setHome] = useState("");
  const [parent, setParent] = useState("");
  const [items, setItems] = useState<FileEntry[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open) return;
    setPath(null);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    let active = true;
    setLoading(true);
    api
      .browseFilesystem(nodeId, path ?? "")
      .then((result) => {
        if (!active) return;
        setHome(result.home);
        setPath(result.path);
        setParent(result.parent);
        setItems(result.items);
      })
      .catch((error) => {
        if (active) handleError(error);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, nodeId, path === null]);

  function navigate(nextPath: string) {
    setPath(nextPath);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Filesystem do node
          </p>
          <DialogTitle>Selecionar pasta</DialogTitle>
          <DialogDescription>
            Navegação a partir da home do node. Apenas pastas podem ser
            montadas.
          </DialogDescription>
        </DialogHeader>

        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="icon"
            title="Ir para a home"
            onClick={() => navigate(home)}
            disabled={loading || path === home}
          >
            <Home className="h-4 w-4" />
          </Button>
          <Button
            type="button"
            variant="outline"
            size="icon"
            title="Subir um nível"
            onClick={() => navigate(parent)}
            disabled={loading || !parent}
          >
            <ArrowUp className="h-4 w-4" />
          </Button>
          <p className="truncate font-mono text-xs text-muted-foreground">
            {path ?? "…"}
          </p>
        </div>

        <div className="max-h-80 overflow-y-auto rounded-md border">
          {loading && (
            <p className="p-4 text-sm text-muted-foreground">Carregando…</p>
          )}
          {!loading && items.length === 0 && (
            <p className="p-4 text-sm text-muted-foreground">Pasta vazia.</p>
          )}
          {!loading &&
            items.map((item) => (
              <div
                key={item.path}
                className="flex items-center justify-between gap-2 border-b px-3 py-2 text-sm last:border-b-0"
              >
                <button
                  type="button"
                  disabled={item.type !== "directory"}
                  onClick={() => navigate(item.path)}
                  className="flex min-w-0 flex-1 items-center gap-2 text-left disabled:cursor-not-allowed disabled:text-muted-foreground/60"
                >
                  {item.type === "directory" && (
                    <Folder className="h-4 w-4 shrink-0" />
                  )}
                  {item.type === "file" && (
                    <File className="h-4 w-4 shrink-0" />
                  )}
                  {item.type === "symlink" && (
                    <Link2 className="h-4 w-4 shrink-0" />
                  )}
                  <span className="truncate">{item.name}</span>
                </button>
                {item.type === "directory" && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      onSelect(item.path);
                      onOpenChange(false);
                    }}
                  >
                    <Check className="h-4 w-4" />
                    Selecionar
                  </Button>
                )}
              </div>
            ))}
        </div>

        <DialogFooter>
          <Button
            type="button"
            disabled={!path || loading}
            onClick={() => {
              if (!path) return;
              onSelect(path);
              onOpenChange(false);
            }}
          >
            <Check className="h-4 w-4" />
            Selecionar pasta atual
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
