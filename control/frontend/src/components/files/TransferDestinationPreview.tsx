import { Copy, FolderPlus, FolderSync, MoveRight, PenLine, Replace, SkipForward, TriangleAlert, type LucideIcon } from "lucide-react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { FileEntryIcon } from "@/components/files/FileEntryIcon";
import { formatBytes } from "@/lib/format";
import { transferPreviewEntries } from "@/lib/transfer-preview";
import type { FileEntry, TransferPlan } from "@/lib/types";

const actions: Record<string, { label: string; Icon: LucideIcon; className: string }> = {
  copy: { label: "Copiar", Icon: Copy, className: "text-sky-700 dark:text-sky-300" },
  create: { label: "Criar pasta", Icon: FolderPlus, className: "text-sky-700 dark:text-sky-300" },
  merge: { label: "Mesclar pasta", Icon: FolderSync, className: "text-sky-700 dark:text-sky-300" },
  rename: { label: "Renomear", Icon: PenLine, className: "text-amber-700 dark:text-amber-300" },
  overwrite: { label: "Sobrescrever", Icon: Replace, className: "text-amber-700 dark:text-amber-300" },
  skip: { label: "Manter existente", Icon: SkipForward, className: "text-muted-foreground" },
  conflict: { label: "Conflito · não transferir", Icon: TriangleAlert, className: "text-rose-700 dark:text-rose-300" },
};

interface Props {
  entries: FileEntry[];
  destinationPath: string;
  operation: "copy" | "move";
  plan: TransferPlan | null;
}

export function TransferDestinationPreview({ entries, destinationPath, operation, plan }: Props) {
  const items = transferPreviewEntries(entries, destinationPath, plan);
  return <section aria-label="Como ficará no destino" className="min-w-0 rounded-md border">
    <div className="grid gap-1 border-b px-3 py-2">
      <h3 className="text-sm font-medium">Como ficará no destino</h3>
    </div>
    <ul className="max-h-60 overflow-y-auto divide-y" aria-label="Arquivos e pastas no destino">
      {items.map((item) => {
        const action = item.action ? actions[item.action] : undefined;
        const label = item.action === "copy" && operation === "move" ? "Mover" : action?.label;
        const ActionIcon = item.action === "copy" && operation === "move" ? MoveRight : action?.Icon;
        const inactiveText = item.action === "conflict" || item.action === "skip" ? "opacity-50 line-through" : "";
        return <li key={item.key} className="flex min-w-0 items-start gap-2 px-3 py-2">
          <FileEntryIcon entry={item} className="mt-0.5" />
          <div className="grid min-w-0 flex-1 gap-0.5">
            <Tooltip>
              <TooltipTrigger render={<span tabIndex={0} />} className={`block w-fit max-w-full break-all text-xs text-muted-foreground focus-visible:rounded-sm focus-visible:outline-2 focus-visible:outline-ring ${inactiveText}`}>/{item.path}</TooltipTrigger>
              <TooltipContent>Nome original: {item.originalName}</TooltipContent>
            </Tooltip>
            {!plan && item.type === "directory" && <p className="text-xs text-muted-foreground">Conteúdo incluído ao gerar a prévia.</p>}
          </div>
          <div className="flex h-5 shrink-0 items-center gap-2">
            {item.type === "file" && item.size !== undefined && <span className={`text-xs text-muted-foreground ${inactiveText}`}>{formatBytes(item.size)}</span>}
            {action && ActionIcon && <Tooltip>
              <TooltipTrigger type="button" aria-label={`${label}: ${item.name}`} className={`inline-flex size-6 items-center justify-center rounded-sm hover:bg-accent focus-visible:outline-2 focus-visible:outline-ring ${action.className}`}><ActionIcon aria-hidden="true" className="size-4" /></TooltipTrigger>
              <TooltipContent>{label}</TooltipContent>
            </Tooltip>}
          </div>
        </li>;
      })}
      {!items.length && <li className="px-3 py-2 text-xs text-muted-foreground">{plan ? "Nenhum item retornado na prévia." : "Confira a pasta de destino para visualizar os arquivos."}</li>}
    </ul>
    {!plan && <p className="border-t px-3 py-2 text-xs text-muted-foreground">Nomes previstos. Gere a prévia para verificar conflitos e incluir o conteúdo das pastas.</p>}
    {plan?.truncated && <p className="border-t px-3 py-2 text-xs text-muted-foreground">Exibindo os primeiros 500 itens. Os totais incluem toda a seleção.</p>}
  </section>;
}
