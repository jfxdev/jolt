import { AlertTriangle, CheckCircle2, RotateCcw, X } from "lucide-react";
import { uploadPercent } from "@/lib/resumable-upload";
import { formatBytes } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";

export interface UploadItem {
  id: string;
  name: string;
  uploaded: number;
  total: number;
  status: "uploading" | "retrying" | "done" | "failed" | "cancelled";
  error?: string;
  /** resumable marks an item whose session still exists on the node, so the
   * same file can continue instead of starting over. */
  resumable?: boolean;
}

interface Props {
  items: UploadItem[];
  onCancel: (id: string) => void;
  onRetry: (id: string) => void;
  onDismiss: (id: string) => void;
}

const statusLabel: Record<UploadItem["status"], string> = {
  uploading: "Enviando",
  retrying: "Reconectando",
  done: "Concluído",
  failed: "Falhou",
  cancelled: "Cancelado",
};

export function UploadQueue({ items, onCancel, onRetry, onDismiss }: Props) {
  if (items.length === 0) return null;

  return (
    <div className="grid gap-2 rounded-md border bg-muted/30 p-3">
      {items.map((item) => {
        const percent = uploadPercent(item.uploaded, item.total);
        const active = item.status === "uploading" || item.status === "retrying";
        return (
          <div key={item.id} className="grid gap-1">
            <div className="flex items-center justify-between gap-3 text-sm">
              <span className="truncate font-medium">{item.name}</span>
              <span className="flex shrink-0 items-center gap-2 text-muted-foreground">
                {item.status === "done" && (
                  <CheckCircle2 className="size-4 text-emerald-600 dark:text-emerald-500" />
                )}
                {item.status === "failed" && (
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
                {(item.status === "failed" || item.status === "cancelled") && (
                  <>
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => onRetry(item.id)}
                    >
                      <RotateCcw className="size-4" />
                      {item.resumable ? "Retomar" : "Tentar de novo"}
                    </Button>
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
