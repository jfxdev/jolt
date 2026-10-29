import { FolderOpen, LoaderCircle } from "lucide-react";
import type { DiskUsageResponse, FileEntry } from "@/lib/types";
import { formatBytes, formatDate } from "@/lib/format";
import { FileEntryIcon } from "@/components/files/FileEntryIcon";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface Props {
  result: DiskUsageResponse | null;
  loading: boolean;
  onOpen: (entry: FileEntry) => void;
}

const percentage = new Intl.NumberFormat("pt-BR", {
  minimumFractionDigits: 0,
  maximumFractionDigits: 1,
});

export function DiskUsageTable({ result, loading, onOpen }: Props) {
  const entries = result?.entries || [];
  const total = result?.total_bytes || 0;

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border bg-muted/30 px-4 py-3">
        <div>
          <p className="text-sm font-medium">
            {result ? `${formatBytes(total)} em disco` : loading ? "Analisando espaço em disco…" : "Sem dados de uso de disco"}
          </p>
          <p className="text-xs text-muted-foreground">
            {result
              ? `${result.scanned.toLocaleString("pt-BR")} ${result.scanned === 1 ? "item analisado" : "itens analisados"} · blocos alocados`
              : loading
                ? "Somando arquivos e subpastas sem seguir links simbólicos"
                : "A análise não retornou dados"}
          </p>
        </div>
        {loading && <LoaderCircle className="size-4 animate-spin text-muted-foreground" aria-label="Atualizando análise" />}
      </div>

      {result?.truncated && (
        <p role="status" className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">
          Análise parcial: o limite de {result.truncated_reason === "timeout" ? "tempo" : "itens"} foi atingido. Os valores abaixo não representam todo o conteúdo.
        </p>
      )}
      {!!result?.read_errors && (
        <p role="status" className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">
          {result.read_errors} {result.read_errors === 1 ? "item não pôde" : "itens não puderam"} ser lido. O total pode estar incompleto.
        </p>
      )}

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Nome</TableHead>
              <TableHead className="w-36">Uso em disco</TableHead>
              <TableHead className="w-56">Participação</TableHead>
              <TableHead className="w-44">Modificado</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {entries.map((entry) => {
              const usage = entry.disk_usage || 0;
              const share = total > 0 ? (usage / total) * 100 : 0;
              return (
                <TableRow key={entry.path}>
                  <TableCell>
                    <button
                      className="flex items-center gap-2 text-left enabled:hover:underline disabled:cursor-default"
                      disabled={entry.type !== "directory"}
                      onClick={() => onOpen(entry)}
                    >
                      <FileEntryIcon entry={entry} />
                      {entry.name}
                      {entry.type === "directory" && <FolderOpen className="size-3.5 text-muted-foreground" />}
                    </button>
                  </TableCell>
                  <TableCell className="font-medium" title={`Tamanho aparente: ${formatBytes(entry.size)}`}>
                    {formatBytes(usage)}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <div className="h-2 min-w-20 flex-1 overflow-hidden rounded-full bg-muted" aria-hidden="true">
                        <div className="h-full rounded-full bg-primary" style={{ width: `${Math.min(100, share)}%` }} />
                      </div>
                      <span className="w-12 text-right text-xs text-muted-foreground">{percentage.format(share)}%</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{formatDate(entry.modified_at)}</TableCell>
                </TableRow>
              );
            })}
            {!entries.length && !loading && result && (
              <TableRow>
                <TableCell colSpan={4} className="py-8 text-center text-sm text-muted-foreground">
                  Esta pasta está vazia.
                </TableCell>
              </TableRow>
            )}
            {!result && !loading && (
              <TableRow>
                <TableCell colSpan={4} className="py-8 text-center text-sm text-muted-foreground">
                  Não foi possível analisar o uso de disco desta pasta.
                </TableCell>
              </TableRow>
            )}
            {!entries.length && loading && (
              <TableRow>
                <TableCell colSpan={4} className="py-8 text-center text-sm text-muted-foreground">
                  Calculando o espaço ocupado…
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
