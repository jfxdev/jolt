import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "@/lib/api";
import { useWorkspace } from "@/context/WorkspaceContext";
import { useNodes } from "@/context/NodesContext";
import { useApiError } from "@/hooks/useApiError";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function DeleteNodeDialog({ open, onOpenChange }: Props) {
  const { nodeId, node } = useWorkspace();
  const { loadNodes } = useNodes();
  const handleError = useApiError();
  const navigate = useNavigate();
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => setConfirmation(""), [open]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!node || confirmation.trim() !== node.name) return;
    setBusy(true);
    try {
      await api.removeNode(nodeId);
      onOpenChange(false);
      navigate("/");
      await loadNodes();
      toast.success(
        "Node removido da Control Tower. O node e seus dados não foram alterados.",
      );
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Ação administrativa
          </p>
          <DialogTitle>Remover node?</DialogTitle>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={handleSubmit}>
          <p className="text-sm text-muted-foreground">
            O cadastro de <strong>{node?.name}</strong> e seus dados de conexão
            serão removidos somente desta Control Tower.
          </p>
          <div className="rounded-md border p-3 text-sm text-muted-foreground">
            O node continuará funcionando. Arquivos, mounts, jobs, identidade,
            peers e grants armazenados nele não serão apagados.
          </div>
          <div className="grid gap-2">
            <Label htmlFor="delete-confirm">
              Digite <strong>{node?.name}</strong> para confirmar
            </Label>
            <Input
              id="delete-confirm"
              value={confirmation}
              placeholder={node?.name}
              autoComplete="off"
              required
              autoFocus
              onChange={(e) => setConfirmation(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              Cancelar
            </Button>
            <Button
              type="submit"
              variant="destructive"
              disabled={busy || confirmation.trim() !== node?.name}
            >
              Remover da Control Tower
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
