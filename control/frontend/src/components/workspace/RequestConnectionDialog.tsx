import { useEffect, useState, type FormEvent } from "react";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import { useNodes } from "@/context/NodesContext";
import { useApiError } from "@/hooks/useApiError";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
  /** Preselects the source node when the dialog is opened from a workspace. */
  issuerNodeId?: string;
  /** Trusted peers are excluded so Connect only presents new relationships. */
  connectedNodeIdsByIssuer?: Record<string, string[]>;
  onConnectionCreated?: () => void | Promise<void>;
}

interface ConnectionForm {
  issuer_node_id: string;
  target_node_id: string;
  transfer_mode: string;
  issuer_role: string;
  invitee_role: string;
  purpose: string;
  cluster_id: string;
  expiry_minutes: number;
}

function baseForm(): ConnectionForm {
  return {
    issuer_node_id: "",
    target_node_id: "",
    transfer_mode: "dual_channel",
    issuer_role: "sender_receiver",
    invitee_role: "sender_receiver",
    purpose: "",
    cluster_id: "",
    expiry_minutes: 20,
  };
}

export function RequestConnectionDialog({
  open,
  onOpenChange,
  issuerNodeId,
  connectedNodeIdsByIssuer = {},
  onConnectionCreated,
}: Props) {
  const { nodes } = useNodes();
  const handleError = useApiError();
  const [form, setForm] = useState<ConnectionForm>(baseForm());
  const [saving, setSaving] = useState(false);

  const sourceNode = nodes.find((n) => n.node_id === form.issuer_node_id);
  const targets = nodes.filter(
    (node) =>
      node.node_id !== form.issuer_node_id &&
      !connectedNodeIdsByIssuer[form.issuer_node_id]?.includes(node.node_id),
  );

  useEffect(() => {
    if (!open) return;
    const issuer = issuerNodeId || nodes[0]?.node_id || "";
    const target = nodes.find(
      (node) =>
        node.node_id !== issuer &&
        !connectedNodeIdsByIssuer[issuer]?.includes(node.node_id),
    )?.node_id || "";
    setForm({
      ...baseForm(),
      issuer_node_id: issuer,
      target_node_id: target,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, issuerNodeId, nodes, connectedNodeIdsByIssuer]);

  function changeMode(mode: string) {
    setForm((prev) => ({
      ...prev,
      transfer_mode: mode,
      issuer_role: mode === "dual_channel" ? "sender_receiver" : "sender",
      invitee_role: mode === "dual_channel" ? "sender_receiver" : "receiver",
    }));
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    try {
      await api.createConnection(form);
      onOpenChange(false);
      await onConnectionCreated?.();
      toast.success("Pedido entregue ao node alvo para revisão.");
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
            Confiança entre identidades
          </p>
          <DialogTitle>Novo pedido de conexão</DialogTitle>
          <DialogDescription>
            O node alvo receberá um pedido pendente com fingerprint e expiração.
            Nenhum mount será compartilhado automaticamente.
          </DialogDescription>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={handleSubmit}>
          {!issuerNodeId && (
            <div className="grid gap-2">
              <Label>Node de origem</Label>
              <Select
                value={form.issuer_node_id}
                onValueChange={(issuer_node_id) => {
                  const target =
                    nodes.find(
                      (node) =>
                        node.node_id !== issuer_node_id &&
                        !connectedNodeIdsByIssuer[issuer_node_id]?.includes(
                          node.node_id,
                        ),
                    )?.node_id || "";
                  setForm((current) => ({
                    ...current,
                    issuer_node_id,
                    target_node_id: target,
                  }));
                }}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Selecione um node" />
                </SelectTrigger>
                <SelectContent>
                  {nodes.map((node) => (
                    <SelectItem key={node.node_id} value={node.node_id}>
                      {node.name} · {node.state}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          <div className="grid gap-2">
            <Label>Node alvo</Label>
            <Select
              value={form.target_node_id}
              onValueChange={(v) => setForm({ ...form, target_node_id: v })}
            >
              <SelectTrigger>
                <SelectValue placeholder="Selecione um node" />
              </SelectTrigger>
              <SelectContent>
                {targets.map((n) => (
                  <SelectItem key={n.node_id} value={n.node_id}>
                    {n.name} · {n.state}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {!targets.length && form.issuer_node_id && (
              <p className="text-xs text-muted-foreground">
                Este node já está conectado a todos os demais nodes conhecidos.
              </p>
            )}
          </div>
          <div className="grid gap-2">
            <Label>Modo operacional</Label>
            <Select value={form.transfer_mode} onValueChange={changeMode}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="dual_channel">
                  Dual channel — ambos enviam e recebem
                </SelectItem>
                <SelectItem value="one_sided">
                  One sided — fluxo em uma direção
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
          {form.transfer_mode === "one_sided" && (
            <div className="grid grid-cols-2 gap-2">
              <div className="grid gap-2">
                <Label>{sourceNode?.name || "Node de origem"}</Label>
                <Select
                  value={form.issuer_role}
                  onValueChange={(v) => setForm({ ...form, issuer_role: v })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="sender">Envia</SelectItem>
                    <SelectItem value="receiver">Recebe</SelectItem>
                    <SelectItem value="requester">Solicita cópia</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label>Node alvo</Label>
                <Select
                  value={form.invitee_role}
                  onValueChange={(v) => setForm({ ...form, invitee_role: v })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="receiver">Recebe</SelectItem>
                    <SelectItem value="sender">Envia</SelectItem>
                    <SelectItem value="requester">Solicita cópia</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}
          <div className="grid gap-2">
            <Label htmlFor="purpose">Finalidade</Label>
            <Input
              id="purpose"
              value={form.purpose}
              placeholder="Backup do notebook para o NAS"
              required
              onChange={(e) => setForm({ ...form, purpose: e.target.value })}
            />
          </div>
          <div className="grid gap-2">
            <Label>Expiração</Label>
            <Select
              value={String(form.expiry_minutes)}
              onValueChange={(v) =>
                setForm({ ...form, expiry_minutes: Number(v) })
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="10">10 minutos</SelectItem>
                <SelectItem value="20">20 minutos</SelectItem>
                <SelectItem value="30">30 minutos</SelectItem>
                <SelectItem value="60">1 hora</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <Button
            type="submit"
            disabled={
              saving || !form.issuer_node_id || !form.target_node_id
            }
          >
            Criar e entregar pedido <ArrowRight />
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
}
