import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { PairingRequest } from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm } from "@/context/ConfirmProvider";
import { toast } from "sonner";
import { ArrowRight } from "lucide-react";
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
  request: PairingRequest | null;
  onClose: () => void;
  onComplete?: () => void | Promise<void>;
}

export function ReviewRequestDialog({ request, onClose, onComplete }: Props) {
  const handleError = useApiError();
  const confirm = useConfirm();
  const [fingerprint, setFingerprint] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => setFingerprint(""), [request]);

  async function approve() {
    if (!request) return;
    setBusy(true);
    try {
      await api.approveConnection(request.request_id, fingerprint.trim());
      onClose();
      await onComplete?.();
      toast.success("Conexão aprovada. Nenhum mount foi compartilhado.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  async function reject() {
    if (!request) return;
    if (
      !(await confirm({
        title: "Rejeitar definitivamente este pedido?",
        confirmText: "Rejeitar",
        destructive: true,
      }))
    )
      return;
    setBusy(true);
    try {
      await api.rejectConnection(request.request_id);
      onClose();
      await onComplete?.();
      toast.success("Pedido rejeitado.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  const matches = fingerprint.trim() === request?.issuer_fingerprint;

  return (
    <Dialog open={request !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Confirmação humana
          </p>
          <DialogTitle>Revisar conexão</DialogTitle>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            approve();
          }}
        >
          <p className="text-sm text-muted-foreground">
            Compare a fingerprint abaixo com a exibida diretamente pelo
            responsável do node emissor.
          </p>
          <div className="grid gap-1 rounded-md border p-3">
            <span className="text-xs text-muted-foreground">
              Fingerprint esperada
            </span>
            <code className="break-all text-sm">
              {request?.issuer_fingerprint}
            </code>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="fp">Digite a fingerprint para confirmar</Label>
            <Input
              id="fp"
              value={fingerprint}
              placeholder={request?.issuer_fingerprint}
              autoComplete="off"
              required
              onChange={(e) => setFingerprint(e.target.value)}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            A aprovação cria confiança entre as identidades, mas não cria grants
            nem libera mounts.
          </p>
          <DialogFooter>
            <Button
              type="button"
              variant="destructive"
              disabled={busy}
              onClick={reject}
            >
              Rejeitar
            </Button>
            <Button type="submit" disabled={busy || !matches}>
              Aprovar conexão <ArrowRight />
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
