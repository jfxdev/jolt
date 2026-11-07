import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { entryFolder, entryName, remainingRetention, restoreErrorMessage } from "@/lib/trash";
import type { ApiError, Mount, TrashEntry } from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm } from "@/context/ConfirmProvider";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface Props {
  open: boolean;
  nodeId: string;
  nodeName?: string;
  mount: Mount;
  canRestore: boolean;
  canPurge: boolean;
  onClose: () => void;
  onRestored: () => void;
}

// What this mount kept when something was deleted. Restoring puts an entry back
// where it was and never overwrites; purging removes it for good.
export function TrashDialog({ open, nodeId, nodeName, mount, canRestore, canPurge, onClose, onRestored }: Props) {
  const handleError = useApiError();
  const confirm = useConfirm();
  const [entries, setEntries] = useState<TrashEntry[] | null>(null);
  const [busy, setBusy] = useState("");
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(async () => {
    try {
      setEntries((await api.trashEntries(nodeId, mount.mount_id)).items ?? []);
      setNow(Date.now());
    } catch (error) {
      setEntries([]);
      handleError(error);
    }
  }, [handleError, mount.mount_id, nodeId]);

  useEffect(() => {
    if (!open) {
      setEntries(null);
      return;
    }
    void load();
  }, [open, load]);

  async function restore(entry: TrashEntry) {
    setBusy(entry.trash_id);
    try {
      await api.restoreTrashEntry(nodeId, mount.mount_id, entry.trash_id);
      toast.success(`“${entryName(entry)}” voltou para ${entryFolder(entry)}.`);
      onRestored();
    } catch (error) {
      const message = restoreErrorMessage((error as ApiError)?.code);
      if (message) toast.error(message);
      else handleError(error);
    } finally {
      setBusy("");
      await load();
    }
  }

  async function purge(entry: TrashEntry) {
    const accepted = await confirm({
      title: `Apagar “${entryName(entry)}” de vez?`,
      description: `Ele está na lixeira de ${[nodeName, mount.name].filter(Boolean).join(" / ")}, vindo de ${entryFolder(entry)}. Depois disto não há como recuperar.`,
      confirmText: "Apagar de vez",
      destructive: true,
    });
    if (!accepted) return;
    setBusy(entry.trash_id);
    try {
      await api.purgeTrashEntry(nodeId, mount.mount_id, entry.trash_id);
      toast.success("Apagado de vez.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy("");
      await load();
    }
  }

  return (
    <Dialog open={open} onOpenChange={(value) => !value && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Lixeira</DialogTitle>
          <DialogDescription>
            O que foi apagado em {mount.name} fica aqui por {mount.trash?.retention_days ?? 30} dias. Restaurar nunca
            substitui algo que já exista com o mesmo nome.
          </DialogDescription>
        </DialogHeader>
        {entries === null ? (
          <p className="text-sm text-muted-foreground">Carregando…</p>
        ) : entries.length === 0 ? (
          <p className="text-sm text-muted-foreground" data-testid="trash-empty">
            A lixeira está vazia.
          </p>
        ) : (
          <ul className="grid max-h-[60vh] gap-2 overflow-y-auto" aria-label="Itens na lixeira">
            {entries.map((entry) => (
              <li key={entry.trash_id} className="grid gap-1 rounded-md border p-3" data-testid="trash-entry">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <strong className="break-all text-sm">{entryName(entry)}</strong>
                  <span className="text-xs text-muted-foreground">
                    {entry.type === "directory" ? "pasta" : formatBytes(entry.size ?? 0)} · some em{" "}
                    {remainingRetention(entry.expires_at, now)}
                  </span>
                </div>
                <p className="break-all text-xs text-muted-foreground">Estava em {entryFolder(entry)}</p>
                <div className="flex gap-2">
                  {canRestore && (
                    <Button size="sm" disabled={busy === entry.trash_id} onClick={() => void restore(entry)}>
                      Restaurar
                    </Button>
                  )}
                  {canPurge && (
                    <Button size="sm" variant="secondary" disabled={busy === entry.trash_id} onClick={() => void purge(entry)}>
                      Apagar de vez
                    </Button>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </DialogContent>
    </Dialog>
  );
}
