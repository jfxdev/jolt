import { useEffect, useState } from "react";
import type { FileEntry } from "@/lib/types";
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
  entry: FileEntry | null;
  load: (entry: FileEntry) => Promise<string>;
  save: (entry: FileEntry, content: string) => Promise<void>;
  onClose: () => void;
  onError: (error: unknown) => void;
}

export function TextEditorDialog({ entry, load, save, onClose, onError }: Props) {
  const [content, setContent] = useState("");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!entry) return;
    let active = true;
    setLoading(true);
    setContent("");
    load(entry)
      .then((value) => active && setContent(value))
      .catch(onError)
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [entry, load, onError]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!entry) return;
    setSaving(true);
    try {
      await save(entry, content);
      onClose();
    } catch (error) {
      onError(error);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={entry !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>Editar {entry?.name}</DialogTitle>
          <DialogDescription>Arquivos de texto de até 512 KB.</DialogDescription>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={submit}>
          <textarea
            className="min-h-[50vh] w-full rounded-md border bg-background p-3 font-mono text-sm outline-none focus-visible:ring-1 focus-visible:ring-ring"
            value={content}
            onChange={(event) => setContent(event.target.value)}
            disabled={loading || saving}
            spellCheck={false}
          />
          <DialogFooter>
            <Button type="button" variant="secondary" onClick={onClose} disabled={saving}>
              Cancelar
            </Button>
            <Button type="submit" disabled={loading || saving}>
              {saving ? "Salvando…" : "Salvar"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
