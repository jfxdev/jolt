import { useEffect, useMemo, useState, type FormEvent } from "react";
import { ArrowRight, Check } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { Mount, NodeInfo } from "@/lib/types";
import { useNodes } from "@/context/NodesContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useApiError } from "@/hooks/useApiError";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
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
import {
  GrantFormFields,
  defaultGrantForm,
  type GrantFormValue,
} from "@/components/workspace/GrantFormFields";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Preselects the source node when opened from a node's own screen. */
  issuerNodeId?: string;
  /** Already trusted targets are hidden so Connect only offers new pairs. */
  connectedNodeIdsByIssuer?: Record<string, string[]>;
  /** Mounts of the issuer node, enabling the optional first grant. */
  issuerMounts?: Mount[];
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

type Step = 1 | 2 | 3;

const stepTitles: Record<Step, string> = {
  1: "Nodes e modo",
  2: "Confirmar identidades",
  3: "Primeiro grant",
};

/**
 * One flow for the whole relationship: pick the nodes, confirm the identity,
 * then authorize the first transfer. Connection and grant live in the same
 * path because a connection without a grant transfers nothing.
 */
export function ConnectDialog({
  open,
  onOpenChange,
  issuerNodeId,
  connectedNodeIdsByIssuer = {},
  issuerMounts = [],
  onConnectionCreated,
}: Props) {
  const { nodes } = useNodes();
  const { hasPermission, loadPermissions } = usePermissions();
  const handleError = useApiError();
  const [step, setStep] = useState<Step>(1);
  const [form, setForm] = useState<ConnectionForm>(baseForm());
  const [fingerprints, setFingerprints] = useState<{
    issuer: string;
    target: string;
  }>({ issuer: "", target: "" });
  const [confirmed, setConfirmed] = useState("");
  const [grant, setGrant] = useState<GrantFormValue>(defaultGrantForm());
  const [busy, setBusy] = useState(false);
  const [awaitingPeer, setAwaitingPeer] = useState(false);

  const sourceNode = nodes.find((node) => node.node_id === form.issuer_node_id);
  const targetNode = nodes.find((node) => node.node_id === form.target_node_id);
  const targets = useMemo(
    () =>
      nodes.filter(
        (node) =>
          node.node_id !== form.issuer_node_id &&
          !connectedNodeIdsByIssuer[form.issuer_node_id]?.includes(
            node.node_id,
          ),
      ),
    [connectedNodeIdsByIssuer, form.issuer_node_id, nodes],
  );

  useEffect(() => {
    if (!open) return;
    const issuer = issuerNodeId || nodes[0]?.node_id || "";
    const target =
      nodes.find(
        (node) =>
          node.node_id !== issuer &&
          !connectedNodeIdsByIssuer[issuer]?.includes(node.node_id),
      )?.node_id || "";
    setStep(1);
    setForm({ ...baseForm(), issuer_node_id: issuer, target_node_id: target });
    setFingerprints({ issuer: "", target: "" });
    setConfirmed("");
    setAwaitingPeer(false);
    setGrant({ ...defaultGrantForm(), mount_id: issuerMounts[0]?.mount_id || "" });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, issuerNodeId, nodes, connectedNodeIdsByIssuer]);

  function changeMode(mode: string) {
    setForm((previous) => ({
      ...previous,
      transfer_mode: mode,
      issuer_role: mode === "dual_channel" ? "sender_receiver" : "sender",
      invitee_role: mode === "dual_channel" ? "sender_receiver" : "receiver",
    }));
  }

  function nodeLabel(node?: NodeInfo) {
    return node ? `${node.name} · ${node.state}` : "—";
  }

  // The dialog shows both fingerprints so the operator verifies the identity
  // instead of the Control Tower silently confirming it to itself.
  async function goToConfirmation(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await loadPermissions([
        `nodes/${form.target_node_id}/admin/pairing`,
      ]);
      const [issuerIdentity, targetIdentity] = await Promise.all([
        api.identityState(form.issuer_node_id).catch(() => null),
        api.identityState(form.target_node_id).catch(() => null),
      ]);
      setFingerprints({
        issuer: issuerIdentity?.active?.fingerprint || "",
        target: targetIdentity?.active?.fingerprint || "",
      });
      setStep(2);
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  const canAdministerTarget = hasPermission(
    `nodes/${form.target_node_id}/admin/pairing`,
    "sudo",
  );
  const fingerprintMatches =
    fingerprints.issuer !== "" && confirmed.trim() === fingerprints.issuer;

  async function createConnection(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const result = await api.createConnection(form);
      await onConnectionCreated?.();
      if (result.auto_approved) {
        toast.success("Conexão confirmada nos dois nodes.");
        setStep(3);
        return;
      }
      if (result.status === "partially_connected") {
        toast.warning(
          "O emissor confiou no alvo, mas o alvo não concluiu. Reconcilie na aba Confiança.",
        );
        onOpenChange(false);
        return;
      }
      setAwaitingPeer(true);
      toast.success("Pedido entregue ao node alvo para confirmação.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  async function createGrant(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const trust = await api.nodeTrust(form.issuer_node_id);
      const peer = trust.peers.find((candidate) =>
        (candidate.registered_node_id || candidate.node_id) === form.target_node_id &&
        candidate.trust_status === "connected",
      );
      if (!peer) {
        toast.error("Atualize a confiança entre os nodes antes de criar o grant.");
        return;
      }
      await api.createGrant(form.issuer_node_id, {
        ...grant,
        peer_node_id: peer.node_id,
      });
      await onConnectionCreated?.();
      toast.success("Grant criado neste node. A transferência também precisa de um grant compatível no outro node.");
      onOpenChange(false);
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
            Passo {step} de 3 · {stepTitles[step]}
          </p>
          <DialogTitle>Conectar nodes</DialogTitle>
          <DialogDescription>
            A conexão estabelece confiança de identidade. Nenhum arquivo é
            compartilhado até existir um grant.
          </DialogDescription>
        </DialogHeader>

        {step === 1 && (
          <form className="grid gap-4" onSubmit={goToConfirmation}>
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
                        {nodeLabel(node)}
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
                onValueChange={(target_node_id) =>
                  setForm({ ...form, target_node_id })
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="Selecione um node" />
                </SelectTrigger>
                <SelectContent>
                  {targets.map((node) => (
                    <SelectItem key={node.node_id} value={node.node_id}>
                      {nodeLabel(node)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {!targets.length && form.issuer_node_id && (
                <p className="text-xs text-muted-foreground">
                  Este node já está conectado a todos os demais nodes
                  conhecidos.
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
                    onValueChange={(issuer_role) =>
                      setForm({ ...form, issuer_role })
                    }
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
                  <Label>{targetNode?.name || "Node alvo"}</Label>
                  <Select
                    value={form.invitee_role}
                    onValueChange={(invitee_role) =>
                      setForm({ ...form, invitee_role })
                    }
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
              <Label htmlFor="connect-purpose">Finalidade</Label>
              <Input
                id="connect-purpose"
                value={form.purpose}
                placeholder="Backup do notebook para o NAS"
                required
                onChange={(event) =>
                  setForm({ ...form, purpose: event.target.value })
                }
              />
            </div>
            <div className="grid gap-2">
              <Label>Expiração do convite</Label>
              <Select
                value={String(form.expiry_minutes)}
                onValueChange={(value) =>
                  setForm({ ...form, expiry_minutes: Number(value) })
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
              disabled={busy || !form.issuer_node_id || !form.target_node_id}
            >
              Continuar <ArrowRight />
            </Button>
          </form>
        )}

        {step === 2 && (
          <form className="grid gap-4" onSubmit={createConnection}>
            <div className="grid gap-3 sm:grid-cols-2">
              {(
                [
                  [sourceNode?.name || "Origem", fingerprints.issuer],
                  [targetNode?.name || "Alvo", fingerprints.target],
                ] as [string, string][]
              ).map(([name, fingerprint]) => (
                <div
                  key={name}
                  className="grid gap-1 rounded-md border border-border p-3"
                >
                  <p className="text-sm font-medium">{name}</p>
                  <p className="break-all font-mono text-xs text-muted-foreground">
                    {fingerprint || "fingerprint indisponível"}
                  </p>
                </div>
              ))}
            </div>
            {awaitingPeer ? (
              <div className="grid gap-3">
                <Badge variant="secondary" className="w-fit">
                  Aguardando o outro node
                </Badge>
                <p className="text-sm text-muted-foreground">
                  O pedido foi entregue a {targetNode?.name || "o node alvo"}.
                  Quem administra aquele node precisa confirmar a fingerprint de{" "}
                  {sourceNode?.name || "origem"} na aba Confiança.
                </p>
                <Button type="button" onClick={() => onOpenChange(false)}>
                  Fechar
                </Button>
              </div>
            ) : canAdministerTarget ? (
              <div className="grid gap-2">
                <Label htmlFor="connect-fingerprint">
                  Digite a fingerprint de {sourceNode?.name || "origem"} para
                  confirmar
                </Label>
                <Input
                  id="connect-fingerprint"
                  value={confirmed}
                  autoComplete="off"
                  placeholder={fingerprints.issuer}
                  onChange={(event) => setConfirmed(event.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Você administra os dois nodes, então a confiança é
                  estabelecida agora. Confirme a fingerprint comparando-a fora
                  desta tela.
                </p>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setStep(1)}
                  >
                    Voltar
                  </Button>
                  <Button type="submit" disabled={busy || !fingerprintMatches}>
                    Estabelecer conexão <Check />
                  </Button>
                </div>
              </div>
            ) : (
              <div className="grid gap-3">
                <p className="text-sm text-muted-foreground">
                  Você não administra {targetNode?.name || "o node alvo"}, então
                  o pedido será entregue para confirmação de quem administra.
                </p>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setStep(1)}
                  >
                    Voltar
                  </Button>
                  <Button type="submit" disabled={busy}>
                    Entregar pedido <ArrowRight />
                  </Button>
                </div>
              </div>
            )}
          </form>
        )}

        {step === 3 && (
          <form className="grid gap-4" onSubmit={createGrant}>
            <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-muted-foreground">
              A conexão está estabelecida, mas sem grant ela não transfere
              nada. Você pode criar o primeiro agora ou depois na aba
              Confiança.
            </p>
            {issuerMounts.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                {sourceNode?.name || "O node de origem"} ainda não tem mounts,
                então nenhum grant pode ser criado agora.
              </p>
            ) : (
              <GrantFormFields
                value={grant}
                onChange={setGrant}
                mounts={issuerMounts}
                idPrefix="connect-grant"
              />
            )}
            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
              >
                Concluir sem grant
              </Button>
              {issuerMounts.length > 0 && (
                <Button type="submit" disabled={busy || !grant.mount_id}>
                  Criar grant <Check />
                </Button>
              )}
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
