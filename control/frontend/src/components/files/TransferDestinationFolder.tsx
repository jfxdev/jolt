import { useEffect, useId, useState, useRef } from "react";
import { ArrowUp, Folder } from "lucide-react";
import { FileEntryIcon } from "@/components/files/FileEntryIcon";
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput, InputGroupText } from "@/components/ui/input-group";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { useApiError } from "@/hooks/useApiError";
import { api } from "@/lib/api";
import { transferDestinationFolder } from "@/lib/transfer-preview";
import type { ApiError, FileEntry, TransferTargetMount } from "@/lib/types";

interface Props {
  nodeId: string;
  mount: TransferTargetMount;
  value: string;
  onChange: (value: string) => void;
  disabled: boolean;
}

export function TransferDestinationFolder({ nodeId, mount, value, onChange, disabled }: Props) {
  const id = useId();
  const handleError = useApiError();
  const [directories, setDirectories] = useState<FileEntry[]>([]);
  const [nextAfter, setNextAfter] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const folder = transferDestinationFolder(value);
  const current = useRef(""); current.current = `${nodeId}:${mount.mount_id}:${folder}`;
  const root = transferDestinationFolder(mount.root_path) || "";
  const withinRoot = folder !== null && (!root || folder === root || folder.startsWith(`${root}/`));
  const parent = folder?.split("/").slice(0, -1).join("/") || "";
  const canGoUp = withinRoot && folder !== root && (!root || parent === root || parent.startsWith(`${root}/`));

  useEffect(() => {
    setDirectories([]);
    setNextAfter("");
    setError("");
    if (!mount.can_browse || !withinRoot) {
      setLoading(false);
      return;
    }
    let active = true;
    setLoading(true);
    const timer = setTimeout(() => {
      void api.files(nodeId, mount.mount_id, folder!).then((response) => {
        if (active) { setDirectories((response.items || []).filter((entry) => entry.type === "directory")); setNextAfter(response.next_after || ""); }
      }).catch((failure: unknown) => {
        if (!active) return;
        const apiError = failure as ApiError;
        setError(apiError.status === 404 ? "Nenhuma pasta existente encontrada neste caminho." : "Não foi possível listar as subpastas deste destino.");
        if (apiError.status === 401) handleError(failure);
      }).finally(() => { if (active) setLoading(false); });
    }, 250);
    return () => { active = false; clearTimeout(timer); };
  }, [nodeId, mount.mount_id, mount.can_browse, folder, withinRoot, handleError]);

  async function loadMore() {
    const target = current.current; setLoading(true); setError("");
    try {
      const response = await api.files(nodeId, mount.mount_id, folder!, nextAfter);
      if (current.current !== target) return;
      setDirectories(previous => [...previous, ...(response.items || []).filter(entry => entry.type === "directory")]);
      setNextAfter(response.next_after || "");
    } catch { if (current.current === target) setError("Não foi possível carregar mais subpastas."); }
    finally { if (current.current === target) setLoading(false); }
  }

  return <div className="grid gap-2">
    <Label htmlFor={id}>Pasta de destino</Label>
    <div className="overflow-hidden rounded-md border">
      <InputGroup className="rounded-none border-0 shadow-none">
        <InputGroupAddon aria-hidden="true"><Folder /><InputGroupText>/</InputGroupText></InputGroupAddon>
        <InputGroupInput id={id} value={value} disabled={disabled} aria-invalid={!withinRoot} placeholder="Raiz do mount" onChange={(event) => onChange(event.target.value)} />
        <InputGroupAddon align="inline-end"><InputGroupButton disabled={disabled || !canGoUp} onClick={() => onChange(parent)}><ArrowUp /> Subir</InputGroupButton></InputGroupAddon>
      </InputGroup>
      {mount.can_browse && withinRoot && <div className="max-h-36 overflow-y-auto border-t" aria-label="Subpastas do destino" aria-busy={loading}>
        {loading ? <p role="status" className="px-3 py-2 text-xs text-muted-foreground">Buscando subpastas…</p> : error ? <p role="status" className="px-3 py-2 text-xs text-muted-foreground">{error}</p> : directories.length ? directories.map((entry) => <button key={entry.path} type="button" disabled={disabled} className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-accent disabled:opacity-50" onClick={() => onChange(entry.path)}><FileEntryIcon entry={entry} />{entry.name}</button>) : <p className="px-3 py-2 text-xs text-muted-foreground">Nenhuma subpasta.</p>}
      </div>}
    </div>
    {nextAfter && <Button size="sm" variant="outline" disabled={disabled || loading} onClick={() => void loadMore()}>Carregar mais subpastas</Button>}
    {!withinRoot && <p role="alert" className="text-xs text-destructive">Informe uma pasta relativa dentro de /{root}.</p>}
    {!mount.can_browse && <p className="text-xs text-muted-foreground">Informe uma pasta relativa sob a raiz autorizada.</p>}
  </div>;
}
