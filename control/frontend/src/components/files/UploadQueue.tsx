import { AlertTriangle, CheckCircle2, RotateCcw, X } from "lucide-react";
import { uploadPercent } from "@/lib/resumable-upload";
import { formatBytes } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";

export interface UploadItem {
  id: string;
  name: string;
  destination?: string;
  needsFile?: boolean;
  uploaded: number;
  total: number;
  status: "uploading" | "retrying" | "verifying" | "done" | "failed" | "cancelled" | "conflict";
  error?: string;
  /** resumable marks an item whose session still exists on the node, so the
   * same file can continue instead of starting over. */
  resumable?: boolean;
}

interface Props {
  items: UploadItem[];
  onCancel: (id: string) => void;
  onRetry: (id: string) => void;
  onReselect?: (id: string, file: File) => void;
  /** onReplace retries an upload that stopped on a conflict, this time
   * authorizing it to replace the file already at the destination. */
  onReplace: (id: string) => void;
  onDismiss: (id: string) => void;
}

const statusLabel: Record<UploadItem["status"], string> = {
  verifying: "Verificando arquivo",
  uploading: "Enviando",
  retrying: "Reconectando",
  done: "Concluído",
  failed: "Falhou",
  cancelled: "Cancelado",
  conflict: "Já existe",
};

export function UploadQueue({ items, onCancel, onRetry, onReplace, onDismiss, onReselect }: Props) {
  if (items.length === 0) return null;

  return (
    <div className="grid gap-2 rounded-md border bg-muted/30 p-3">
      {items.map((item) => {
        const percent = uploadPercent(item.uploaded, item.total);
        const active = item.status === "uploading" || item.status === "retrying" || item.status === "verifying";
        return (
          <div key={item.id} className="grid gap-1">
            <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
              <span className="min-w-0"><span className="block truncate font-medium">{item.name}</span>{item.destination && <span className="block truncate text-xs text-muted-foreground">Destino: {item.destination}</span>}</span>
              <span className="flex shrink-0 items-center gap-2 text-muted-foreground">
                {item.status === "done" && (
                  <CheckCircle2 className="size-4 text-emerald-600 dark:text-emerald-500" />
                )}
                {(item.status === "failed" || item.status === "conflict") && (
                  <AlertTriangle className="size-4 text-destructive" />
                )}
                <span>
                  {statusLabel[item.status]}
                  {active && ` · ${formatBytes(item.uploaded)} de ${formatBytes(item.total)}`}
                </span>
                {active && (
                  <Button
                    size="sm"
                    variant="ghost"
                    aria-label={`Cancelar o envio de ${item.name}`}
                    onClick={() => onCancel(item.id)}
                  >
                    <X className="size-4" />
                  </Button>
                )}
                {item.status === "conflict" && (
                  <>
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => onReplace(item.id)}
                    >
                      Substituir
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-label={`Manter o arquivo existente e descartar ${item.name}`}
                      onClick={() => onDismiss(item.id)}
                    >
                      <X className="size-4" />
                    </Button>
                  </>
                )}
                {item.needsFile && !active && (
                  <label className="cursor-pointer rounded-md border px-3 py-2 text-xs font-medium text-foreground">
                    Selecionar arquivo para retomar
                    <input type="file" className="sr-only" aria-label={`Selecionar arquivo para retomar ${item.name}`} onChange={event => { const file = event.currentTarget.files?.[0]; if (file) onReselect?.(item.id, file); event.currentTarget.value = ""; }} />
                  </label>
                )}
                {(item.status === "failed" || item.status === "cancelled") && (
                  <>
                    {!item.needsFile && <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => onRetry(item.id)}
                    >
                      <RotateCcw className="size-4" />
                      {item.resumable ? "Retomar" : "Tentar de novo"}
                    </Button>}
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-label={`Descartar ${item.name}`}
                      onClick={() => onDismiss(item.id)}
                    >
                      <X className="size-4" />
                    </Button>
                  </>
                )}
                {item.status === "done" && (
                  <Button
                    size="sm"
                    variant="ghost"
                    aria-label={`Descartar ${item.name}`}
                    onClick={() => onDismiss(item.id)}
                  >
                    <X className="size-4" />
                  </Button>
                )}
              </span>
            </div>
            {active && <Progress value={percent} />}
            {item.error && (
              <p className="text-xs text-destructive">{item.error}</p>
            )}
          </div>
        );
      })}
    </div>
  );
}
