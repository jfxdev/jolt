import { useEffect, useRef, useState } from "react";
import { Loader2, Search, X } from "lucide-react";
import type { SearchResponse } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface Props {
  /** scopeLabel names the folder being searched, so it is obvious the search
   * is scoped to the current subtree rather than the whole mount. */
  scopeLabel: string;
  searching: boolean;
  result: SearchResponse | null;
  onSearch: (query: string, type: "" | "file" | "directory") => void;
  onClear: () => void;
}

const truncationMessage: Record<string, string> = {
  results: "Mostrando os primeiros resultados. Refine a busca para ver o resto.",
  entries: "A busca parou após varrer o limite de itens. Refine a busca.",
  timeout: "A busca atingiu o tempo limite. Refine a busca ou busque em uma subpasta.",
};

export function FileSearchBar({
  scopeLabel,
  searching,
  result,
  onSearch,
  onClear,
}: Props) {
  const [query, setQuery] = useState("");
  const [type, setType] = useState<"" | "file" | "directory">("");
  const debounce = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Debounce so typing does not launch a filesystem walk per keystroke.
  useEffect(() => {
    if (debounce.current) clearTimeout(debounce.current);
    const trimmed = query.trim();
    if (trimmed === "") {
      onClear();
      return;
    }
    debounce.current = setTimeout(() => onSearch(trimmed, type), 350);
    return () => {
      if (debounce.current) clearTimeout(debounce.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, type]);

  function clear() {
    setQuery("");
    setType("");
    onClear();
  }

  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-56 flex-1">
          {searching ? (
            <Loader2 className="absolute left-2.5 top-1/2 size-4 -translate-y-1/2 animate-spin text-muted-foreground" />
          ) : (
            <Search className="absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          )}
          <Input
            className="h-9 pl-8"
            value={query}
            placeholder={`Buscar em ${scopeLabel}…`}
            aria-label={`Buscar em ${scopeLabel}`}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
        <Select
          value={type || "all"}
          onValueChange={(value) =>
            setType(value === "all" ? "" : (value as "file" | "directory"))
          }
        >
          <SelectTrigger className="h-9 w-36" aria-label="Tipo">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Tudo</SelectItem>
            <SelectItem value="file">Arquivos</SelectItem>
            <SelectItem value="directory">Pastas</SelectItem>
          </SelectContent>
        </Select>
        {query !== "" && (
          <Button variant="ghost" size="sm" onClick={clear}>
            <X className="size-4" /> Limpar
          </Button>
        )}
      </div>

      {result && (
        <p className="text-sm text-muted-foreground">
          {result.entries.length === 0
            ? "Nenhum resultado."
            : `${result.entries.length} resultado${result.entries.length === 1 ? "" : "s"} · ${result.scanned} itens varridos`}
          {result.truncated && result.truncated_reason && (
            <span className="ml-1 text-amber-600 dark:text-amber-500">
              {truncationMessage[result.truncated_reason]}
            </span>
          )}
        </p>
      )}
    </div>
  );
}
