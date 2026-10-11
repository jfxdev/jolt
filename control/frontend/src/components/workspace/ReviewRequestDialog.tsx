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
      toast.success("Conexão confirmada. Nenhum arquivo foi compartilhado.");
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
            Confirmar conexão
          </p>
          <DialogTitle>Aceitar pedido de conexão</DialogTitle>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            approve();
          }}
        >
          <p className="text-sm text-muted-foreground">
            Para proteger a conexão, compare este código com o informado pelo
            responsável pelo outro node antes de aceitar.
          </p>
          <div className="grid gap-1 rounded-md border p-3">
            <span className="text-xs text-muted-foreground">
              Código de verificação
            </span>
            <code className="break-all text-sm">
              {request?.issuer_fingerprint}
            </code>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="fp">Cole o código para confirmar</Label>
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
            A confirmação apenas estabelece a conexão. Os arquivos continuam
            protegidos até que você autorize uma transferência.
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
              Aceitar conexão <ArrowRight />
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
