import { useEffect, useState } from "react";
import { Check, Copy, Link2 } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { CreatedShare, FileEntry, Mount } from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface Props {
  entry: FileEntry | null;
  mount: Mount;
  nodeId: string;
  onClose: () => void;
}

/** expiryChoices keeps the common cases one click away. "never" is offered but
 * not the default: a link nobody remembers is the one most likely to leak. */
const expiryChoices: { value: string; label: string; seconds: number }[] = [
  { value: "1h", label: "1 hora", seconds: 3600 },
  { value: "24h", label: "24 horas", seconds: 86_400 },
  { value: "7d", label: "7 dias", seconds: 604_800 },
  { value: "30d", label: "30 dias", seconds: 2_592_000 },
  { value: "never", label: "Sem expiração", seconds: 0 },
];

export function ShareDialog({ entry, mount, nodeId, onClose }: Props) {
  const handleError = useApiError();
  const [expiry, setExpiry] = useState("7d");
  const [password, setPassword] = useState("");
  const [maxDownloads, setMaxDownloads] = useState("");
  const [allowArchive, setAllowArchive] = useState(true);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<CreatedShare | null>(null);
  const [copied, setCopied] = useState(false);

  // Reset the form whenever a different entry is shared, so settings from the
  // previous link never carry over silently.
  useEffect(() => {
    if (entry) {
      setExpiry("7d");
      setPassword("");
      setMaxDownloads("");
      setAllowArchive(entry.type === "directory");
      setCreated(null);
      setCopied(false);
    }
  }, [entry]);

  async function create() {
    if (!entry) return;
    const choice = expiryChoices.find((option) => option.value === expiry);
    const downloads = Number(maxDownloads);
    if (maxDownloads !== "" && (!Number.isInteger(downloads) || downloads < 1)) {
      toast.error("O limite de downloads precisa ser um número inteiro positivo.");
      return;
    }
    if (password !== "" && password.length < 8) {
      toast.error("A senha do link precisa ter ao menos 8 caracteres.");
      return;
    }
    setCreating(true);
    try {
      const result = await api.createShare({
        node_id: nodeId,
        mount_id: mount.mount_id,
        path: entry.path,
        kind: entry.type === "directory" ? "directory" : "file",
        password: password || undefined,
        allow_archive: allowArchive,
        max_downloads: maxDownloads === "" ? 0 : downloads,
        expires_in_seconds: choice?.seconds ?? 0,
      });
      setCreated(result);
    } catch (error) {
      handleError(error);
    } finally {
      setCreating(false);
    }
  }

  async function copyLink() {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.url);
      setCopied(true);
      toast.success("Link copiado.");
    } catch {
      // Clipboard access is denied in some browsers and over plain HTTP; the
      // input stays selectable so the link is never unreachable.
      toast.error("Não foi possível copiar. Selecione o link manualmente.");
    }
  }

  return (
    <Dialog open={entry !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Link2 className="size-4" /> Compartilhar “{entry?.name}”
          </DialogTitle>
          <DialogDescription>
            Gera um link público somente de leitura. Quem tiver o link acessa sem
            entrar na Control Tower.
          </DialogDescription>
        </DialogHeader>

        {created ? (
          <div className="grid gap-3">
            <Label htmlFor="share-url">Link gerado</Label>
            <div className="flex gap-2">
              <Input
                id="share-url"
                readOnly
                value={created.url}
                onFocus={(event) => event.currentTarget.select()}
              />
              <Button variant="secondary" onClick={copyLink}>
                {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
              </Button>
            </div>
            <p className="text-sm text-muted-foreground">
              Guarde o link agora: ele não pode ser exibido novamente. Para
              encerrar o acesso, revogue o link em Acesso → Links públicos.
            </p>
          </div>
        ) : (
          <div className="grid gap-4">
            <div className="grid gap-2">
              <Label htmlFor="share-expiry">Expira em</Label>
              <Select value={expiry} onValueChange={setExpiry}>
                <SelectTrigger id="share-expiry">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {expiryChoices.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="share-password">Senha (opcional)</Label>
              <Input
                id="share-password"
                type="password"
                autoComplete="new-password"
                placeholder="Mínimo de 8 caracteres"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="share-downloads">Limite de downloads (opcional)</Label>
              <Input
                id="share-downloads"
                inputMode="numeric"
                placeholder="Sem limite"
                value={maxDownloads}
                onChange={(event) => setMaxDownloads(event.target.value.replace(/\D/g, ""))}
              />
            </div>

            {entry?.type === "directory" && (
              <label className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={allowArchive}
                  onCheckedChange={(value) => setAllowArchive(value === true)}
                />
                Permitir baixar a pasta inteira como .zip
              </label>
            )}
          </div>
        )}

        <DialogFooter>
          {created ? (
            <Button onClick={onClose}>Concluir</Button>
          ) : (
            <>
              <Button variant="secondary" onClick={onClose}>
                Cancelar
              </Button>
              <Button disabled={creating} onClick={create}>
                {creating ? "Gerando…" : "Gerar link"}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
