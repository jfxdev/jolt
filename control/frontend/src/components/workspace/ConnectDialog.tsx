import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
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
import { Separator } from "@/components/ui/separator";
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

// The Select trigger renders the item label for the selected value, so these
// keep raw ids and mode keys out of the closed control.
const modeItems = [
  { value: "dual_channel", label: "Dual channel" },
  { value: "one_sided", label: "One sided" },
];

const expiryItems = [
  { value: "10", label: "10 minutos" },
  { value: "20", label: "20 minutos" },
  { value: "30", label: "30 minutos" },
  { value: "60", label: "1 hora" },
];

const stepTitles: Record<Step, string> = {
  1: "Nodes e modo",
  2: "Confirmar identidades",
  3: "Acesso a arquivos",
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
  // Set when the chosen target stopped being valid (it got connected), so the
  // defaulting effect does not quietly pick another node under the same purpose.
  const targetInvalidated = useRef(false);

  const sourceNode = nodes.find((node) => node.node_id === form.issuer_node_id);
  const managedGrants = sourceNode?.configuration?.grants_mutable === false;
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

  // Resets only when the dialog opens. Creating a connection refreshes `nodes`
  // and `connectedNodeIdsByIssuer` while the dialog is still on step 2 or 3, and
  // resetting on those would send the operator back to an empty step 1.
  useEffect(() => {
    if (!open) return;
    targetInvalidated.current = false;
    setStep(1);
    setForm({ ...baseForm(), issuer_node_id: issuerNodeId || "" });
    setFingerprints({ issuer: "", target: "" });
    setConfirmed("");
    setAwaitingPeer(false);
    setGrant(defaultGrantForm());
  }, [open, issuerNodeId]);

  // Fills defaults once the data is there, and again if it arrives after the
  // dialog opened, but only while the operator is still choosing nodes.
  useEffect(() => {
    if (!open || step !== 1) return;
    setForm((current) => {
      // Until the inventory loads there is nothing to validate against.
      // A fixed issuer that is not in the inventory is cleared rather than
      // replaced, since its selector is hidden and the operator could not
      // see the swap.
      const issuer =
        nodes.length === 0 || nodes.some((node) => node.node_id === current.issuer_node_id)
          ? current.issuer_node_id || nodes[0]?.node_id || ""
          : issuerNodeId
            ? ""
            : nodes[0].node_id;
      const firstTarget = () =>
        (issuer &&
          nodes.find(
            (node) =>
              node.node_id !== issuer &&
              !connectedNodeIdsByIssuer[issuer]?.includes(node.node_id),
          )?.node_id) ||
        "";
      let target = current.target_node_id;
      if (issuer !== current.issuer_node_id) target = firstTarget();
      else if (!target && !targetInvalidated.current) target = firstTarget();
      if (issuer === current.issuer_node_id && target === current.target_node_id) {
        return current;
      }
      return { ...current, issuer_node_id: issuer, target_node_id: target };
    });
  }, [open, step, nodes, connectedNodeIdsByIssuer, issuerNodeId]);

  // A target that became connected while the dialog was open is dropped, and
  // the operator has to pick again: the purpose was written for that node.
  useEffect(() => {
    if (!open || step !== 1 || !nodes.length) return;
    if (!form.target_node_id || targets.some((node) => node.node_id === form.target_node_id)) return;
    targetInvalidated.current = true;
    setForm((current) => ({ ...current, target_node_id: "" }));
    toast.warning("O node alvo selecionado já foi conectado. Escolha outro node alvo.");
  }, [open, step, nodes, targets, form.target_node_id]);

  useEffect(() => {
    if (!open) return;
    setGrant((current) =>
      current.mount_id || !issuerMounts[0]
        ? current
        : { ...current, mount_id: issuerMounts[0].mount_id },
    );
  }, [open, issuerMounts]);

  function changeMode(mode: string) {
    setForm((previous) => ({
      ...previous,
      transfer_mode: mode,
      issuer_role: mode === "dual_channel" ? "sender_receiver" : "sender",
      invitee_role: mode === "dual_channel" ? "sender_receiver" : "receiver",
    }));
  }

  function nodeItems(list: NodeInfo[]) {
    return list.map((node) => ({ value: node.node_id, label: node.name }));
  }

  function nodeOption(node: NodeInfo) {
    return (
      <SelectItem key={node.node_id} value={node.node_id}>
        {node.name}
        <span className="text-xs text-muted-foreground">{node.state}</span>
      </SelectItem>
    );
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
    if (managedGrants) return;
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
                  items={nodeItems(nodes)}
                  value={form.issuer_node_id}
                  onValueChange={(issuer_node_id) => {
                    targetInvalidated.current = false;
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
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Selecione um node" />
                  </SelectTrigger>
                  <SelectContent>
                    {nodes.map(nodeOption)}
                  </SelectContent>
                </Select>
              </div>
            )}
            <div className="grid gap-2">
              <Label>Node alvo</Label>
              <Select
                items={nodeItems(targets)}
                value={form.target_node_id}
                onValueChange={(target_node_id) => {
                  targetInvalidated.current = false;
                  setForm({ ...form, target_node_id });
                }}
              >
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Selecione um node" />
                </SelectTrigger>
                <SelectContent>
                  {targets.map(nodeOption)}
                </SelectContent>
              </Select>
              {!targets.length && form.issuer_node_id && (
                <p className="text-xs text-muted-foreground">
                  Este node já está conectado a todos os demais nodes
                  conhecidos.
                </p>
              )}
            </div>
            <div className="flex items-start gap-4">
              <div className="grid flex-1 gap-2">
                <Label>Modo operacional</Label>
                <Select
                  items={modeItems}
                  value={form.transfer_mode}
                  onValueChange={changeMode}
                >
                  <SelectTrigger className="w-full">
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
              <Separator orientation="vertical" className="h-14 self-end" />
              <div className="grid flex-1 gap-2">
                <Label>Expiração do convite</Label>
                <Select
                  items={expiryItems}
                  value={String(form.expiry_minutes)}
                  onValueChange={(value) =>
                    setForm({ ...form, expiry_minutes: Number(value) })
                  }
                >
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {expiryItems.map((item) => (
                      <SelectItem key={item.value} value={item.value}>
                        {item.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
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

        {step === 3 && managedGrants && (
          <div className="grid gap-4">
            <p className="text-sm text-muted-foreground">Gerenciado por arquivo. A conexão foi estabelecida. Os arquivos disponíveis dependem das autorizações definidas no node.yaml de cada node. Alterações exigem reinício.</p>
            <Button type="button" onClick={() => onOpenChange(false)}>Concluir <Check /></Button>
          </div>
        )}
        {step === 3 && !managedGrants && (
          <form className="grid gap-4" onSubmit={createGrant}>
            <p className="rounded-md border border-warning/40 bg-warning/10 p-3 text-xs text-muted-foreground">
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
