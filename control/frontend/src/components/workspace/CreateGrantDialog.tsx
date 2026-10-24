import { useEffect, useState, type FormEvent } from "react";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import { useWorkspace } from "@/context/WorkspaceContext";
import { useApiError } from "@/hooks/useApiError";
import { activePeers } from "@/lib/peers";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  GrantFormFields,
  defaultGrantForm,
  type GrantFormValue,
} from "@/components/workspace/GrantFormFields";
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

export function CreateGrantDialog({ open, onOpenChange }: Props) {
  const { nodeId, node, mounts, trustPeers, refreshTrust } = useWorkspace();
  const managed = node?.configuration?.grants_mutable === false;
  const handleError = useApiError();
  const trusted = activePeers(trustPeers.filter((peer) => peer.registered));
  const [form, setForm] = useState<GrantFormValue>(defaultGrantForm());
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setForm({
      ...defaultGrantForm(),
      peer_node_id: trusted[0]?.node_id || "",
      mount_id: mounts[0]?.mount_id || "",
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (managed) return;
    setSaving(true);
    try {
      await api.createGrant(nodeId, form);
      onOpenChange(false);
      await refreshTrust();
      toast.success("Acesso para transferência configurado.");
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
            Transferência de arquivos
          </p>
          <DialogTitle>Autorizar transferências</DialogTitle>
          <DialogDescription>
            Escolha qual node conectado pode enviar ou receber arquivos neste
            mount.
          </DialogDescription>
        </DialogHeader>
        {managed ? <p className="text-sm text-muted-foreground">Gerenciado por arquivo. Edite as autorizações no node.yaml e reinicie o node.</p> : <form className="grid gap-4" onSubmit={handleSubmit}>
          <GrantFormFields
            value={form}
            onChange={setForm}
            mounts={mounts}
            peers={trusted}
          />
          <Button type="submit" disabled={saving}>
            Criar grant <ArrowRight />
          </Button>
        </form>}
      </DialogContent>
    </Dialog>
  );
}
