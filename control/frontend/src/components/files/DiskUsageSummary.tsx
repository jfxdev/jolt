import { LoaderCircle } from "lucide-react";
import type { DiskUsageResponse } from "@/lib/types";
import { formatBytes } from "@/lib/format";

interface Props {
  result: DiskUsageResponse | null;
  loading: boolean;
}

/** The total as inline content; the page places it in its floating bar. */
export function DiskUsageTotal({ result, loading }: Props) {
  const total = result?.total_bytes || 0;

  return (
    <div className="flex items-center gap-3">
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
  );
}

export function DiskUsageNotices({ result }: Pick<Props, "result">) {
  return (
    <>
      {result?.truncated && (
        <p role="status" className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm">
          Análise parcial: o limite de {result.truncated_reason === "timeout" ? "tempo" : "itens"} foi atingido. Os valores abaixo não representam todo o conteúdo.
        </p>
      )}
      {!!result?.read_errors && (
        <p role="status" className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm">
          {result.read_errors} {result.read_errors === 1 ? "item não pôde" : "itens não puderam"} ser lido. O total pode estar incompleto.
        </p>
      )}
    </>
  );
}
