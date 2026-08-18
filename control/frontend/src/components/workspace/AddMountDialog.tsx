import { useState, type FormEvent } from "react";
import { ArrowRight, FolderOpen } from "lucide-react";
import { api } from "@/lib/api";
import type { MountMode } from "@/lib/types";
import { useWorkspace } from "@/context/WorkspaceContext";
import { useApiError } from "@/hooks/useApiError";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NodeFileBrowserDialog } from "@/components/workspace/NodeFileBrowserDialog";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface MountForm {
  name: string;
  local_path: string;
  mode: MountMode;
  published: boolean;
  enabled: boolean;
}

const EMPTY: MountForm = {
  name: "",
  local_path: "/mnt/files",
  mode: "read_write",
  published: true,
  enabled: true,
};

export function AddMountDialog({ open, onOpenChange }: Props) {
  const { nodeId, refreshMounts } = useWorkspace();
  const handleError = useApiError();
  const [form, setForm] = useState<MountForm>(EMPTY);
  const [saving, setSaving] = useState(false);
  const [browserOpen, setBrowserOpen] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    try {
      await api.createMount(nodeId, form);
      await refreshMounts();
      setForm(EMPTY);
      onOpenChange(false);
      toast.success("Mount criado no node.");
    } catch (error) {
      handleError(error);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Filesystem do node
          </p>
          <DialogTitle>Criar mount</DialogTitle>
          <DialogDescription>
            O caminho precisa existir e estar montado dentro do container do
            node. Ele não será exibido depois da criação.
          </DialogDescription>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={handleSubmit}>
          <div className="grid gap-2">
            <Label htmlFor="mount-name">Nome amigável</Label>
            <Input
              id="mount-name"
              value={form.name}
              placeholder="Filmes"
              required
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="mount-path">Caminho local no node</Label>
            <div className="flex gap-2">
              <Input
                id="mount-path"
                value={form.local_path}
                placeholder="/mnt/media"
                required
                onChange={(e) => setForm({ ...form, local_path: e.target.value })}
              />
              <Button
                type="button"
                variant="outline"
                onClick={() => setBrowserOpen(true)}
              >
                <FolderOpen className="h-4 w-4" />
                Procurar
              </Button>
            </div>
          </div>
          <div className="grid gap-2">
            <Label>Permissão</Label>
            <Select
              value={form.mode}
              onValueChange={(v) => setForm({ ...form, mode: v as MountMode })}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="read_write">Leitura e escrita</SelectItem>
                <SelectItem value="read_only">Somente leitura</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <Checkbox
              checked={form.published}
              onCheckedChange={(v) => setForm({ ...form, published: v === true })}
            />
            Visível para operações remotas
          </label>
          <Button type="submit" disabled={saving}>
            Validar e criar <ArrowRight />
          </Button>
        </form>
      </DialogContent>
      <NodeFileBrowserDialog
        open={browserOpen}
        onOpenChange={setBrowserOpen}
        nodeId={nodeId}
        onSelect={(path) => setForm((f) => ({ ...f, local_path: path }))}
      />
    </Dialog>
  );
}
