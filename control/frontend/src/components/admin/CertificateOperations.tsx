import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { authModeLabel, nodeStatus, nodesOnToken, rotationSummary, type Tone } from "@/lib/certificates";
import { formatDate } from "@/lib/format";
import type { ApiError, CertificateInventory, Revocation } from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm, usePrompt } from "@/context/ConfirmProvider";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

const TONE_CLASS: Record<Tone, string> = {
  ok: "text-muted-foreground",
  neutral: "text-muted-foreground",
  warning: "text-amber-600 dark:text-amber-400",
  critical: "font-medium text-destructive",
};

// What a person does by hand with the authority, and only when something went
// wrong or a root is being replaced: nothing here is part of the everyday
// renewal, which needs no one.
export function CertificateOperations({ inventory, now, onChanged }: { inventory: CertificateInventory; now: number; onChanged: () => Promise<void> }) {
  const handleError = useApiError();
  const confirm = useConfirm();
  const prompt = usePrompt();
  const [revocations, setRevocations] = useState<Revocation[]>([]);
  const [busy, setBusy] = useState("");
  const nodes = inventory.nodes ?? [];
  const rotation = inventory.rotation;
  const summary = rotationSummary(rotation);
  const onToken = nodesOnToken(nodes);

  const loadRevocations = useCallback(async () => {
    try {
      setRevocations((await api.revocations()).items ?? []);
    } catch (error) {
      handleError(error);
    }
  }, [handleError]);

  useEffect(() => {
    void loadRevocations();
  }, [loadRevocations, inventory.bundle_version]);

  async function run(key: string, action: () => Promise<unknown>, done: string) {
    setBusy(key);
    try {
      await action();
      toast.success(done);
      await Promise.all([onChanged(), loadRevocations()]);
    } catch (error) {
      handleError(error);
    } finally {
      setBusy("");
    }
  }

  async function revokeNode(nodeId: string, name: string) {
    const reason = await prompt({
      title: `Revogar o certificado do node ${name}?`,
      description:
        "Use quando a chave do node pode ter sido copiada. O Control Tower deixa de falar com ele e os outros nodes passam a recusá-lo. Para voltar, o node precisa ser enrolado de novo com um token novo.",
      confirmText: "Revogar",
      label: "Motivo (opcional)",
    });
    if (reason === null) return;
    await run(`revoke-${nodeId}`, () => api.revokeCertificate({ node_id: nodeId, reason: reason.trim() }), "Certificado revogado.");
  }

  async function rotateIntermediate(revoke: boolean) {
    const accepted = await confirm(
      revoke
        ? {
            title: "Girar a intermediária e revogar a atual?",
            description:
              "Para o caso de a chave emissora ter vazado. A intermediária atual sai do pacote na hora, e o Control Tower reemite os próprios certificados e os de cada node no próximo ciclo. Navegadores e nodes não precisam fazer nada.",
            confirmText: "Girar e revogar",
            destructive: true,
          }
        : {
            title: "Girar a intermediária?",
            description: "Uma intermediária nova passa a assinar. A atual continua no pacote até vencer, e nada precisa ser reemitido.",
            confirmText: "Girar",
          },
    );
    if (!accepted) return;
    await run(revoke ? "rotate-revoke" : "rotate", () => api.rotateIntermediate({ revoke_previous: revoke, reason: revoke ? "gira e revoga" : "" }), "Intermediária nova em uso.");
  }

  async function promote() {
    setBusy("promote");
    try {
      await api.promoteRoot(false);
      toast.success("Raiz nova em uso.");
      await onChanged();
    } catch (error) {
      if ((error as ApiError)?.code === "nodes_behind") {
        setBusy("");
        const accepted = await confirm({
          title: "Promover mesmo com nodes atrasados?",
          description: `${(error as ApiError).message} Um node que não recebeu a raiz nova deixa de confiar no Control Tower e precisa ser enrolado de novo.`,
          confirmText: "Promover mesmo assim",
          destructive: true,
        });
        if (accepted) await run("promote", () => api.promoteRoot(true), "Raiz nova em uso.");
        return;
      }
      handleError(error);
    } finally {
      setBusy("");
    }
  }

  async function beginRotation() {
    const accepted = await confirm({
      title: "Começar a troca da raiz?",
      description:
        "A raiz nova é publicada ao lado da atual e nada muda ainda. Instale-a nos dispositivos pela página /ca; quando os nodes tiverem confirmado, promova-a.",
      confirmText: "Começar a troca",
    });
    if (!accepted) return;
    await run("begin", () => api.beginRootRotation(), "Raiz nova publicada.");
  }

  return (
    <div className="grid gap-6" data-testid="certificate-operations">
      <div className="grid gap-2">
        <h2 className="text-sm font-medium">Nodes enrolados</h2>
        {nodes.length === 0 ? (
          <p className="text-sm text-muted-foreground">Nenhum node usa a autoridade ainda.</p>
        ) : (
          <>
            {onToken > 0 && (
              <p className="text-xs text-muted-foreground" data-testid="nodes-on-token">
                {onToken === 1 ? "1 node ainda aceita" : `${onToken} nodes ainda aceitam`} o token compartilhado. Com tls_mode: managed-only no YAML do node, só o certificado do Control Tower vale.
              </p>
            )}
            <ul className="grid gap-2">
              {nodes.map((node) => {
                const status = nodeStatus(node, now);
                return (
                  <li key={node.node_id} className="grid gap-1 rounded-md border p-3" data-testid="managed-node">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <strong className="text-sm">{node.name}</strong>
                      <Badge variant={node.auth_mode === "certificate" ? "secondary" : "outline"}>{authModeLabel(node.auth_mode)}</Badge>
                    </div>
                    <p className={`text-xs ${TONE_CLASS[status.tone]}`} data-tone={status.tone}>
                      {status.label}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Pacote {node.bundle_version} · certificado vence em {formatDate(node.cert_not_after)}
                    </p>
                    <div>
                      <Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void revokeNode(node.node_id, node.name)}>
                        Revogar certificado
                      </Button>
                    </div>
                  </li>
                );
              })}
            </ul>
          </>
        )}
      </div>

      <div className="grid gap-2" data-testid="root-rotation">
        <h2 className="text-sm font-medium">Troca da raiz</h2>
        {summary ? (
          <div className="grid gap-1 rounded-md border p-3">
            <strong className="text-sm">{summary.title}</strong>
            <p className="text-xs text-muted-foreground">{summary.detail}</p>
            {rotation?.phase === "prepared" && inventory.next_root_fingerprint_display && (
              <code className="break-all font-mono text-xs" data-testid="next-root-fingerprint">
                {inventory.next_root_fingerprint_display}
              </code>
            )}
          </div>
        ) : (
          <p className="max-w-3xl text-xs text-muted-foreground">
            A raiz vale por dez anos. Troque-a só se a chave dela saiu do seu controle ou o prazo está perto; a troca é feita em passos, sem parada.
          </p>
        )}
        <div className="flex flex-wrap gap-2">
          {(!rotation || rotation.phase === "none") && (
            <Button size="sm" variant="secondary" disabled={busy !== ""} onClick={() => void beginRotation()}>
              Começar a troca da raiz
            </Button>
          )}
          {rotation?.phase === "prepared" && (
            <Button size="sm" disabled={busy !== ""} onClick={() => void promote()}>
              Promover a raiz nova
            </Button>
          )}
        </div>
      </div>

      <div className="grid gap-2">
        <h2 className="text-sm font-medium">Intermediária</h2>
        <p className="max-w-3xl text-xs text-muted-foreground">
          Ela é renovada sozinha aos dois terços da vida. Gire-a por conta própria só se a chave emissora vazou.
        </p>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="secondary" disabled={busy !== ""} onClick={() => void rotateIntermediate(false)}>
            Girar a intermediária
          </Button>
          <Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void rotateIntermediate(true)}>
            Girar e revogar (chave vazada)
          </Button>
        </div>
      </div>

      {revocations.length > 0 && (
        <div className="grid gap-2" data-testid="revocations">
          <h2 className="text-sm font-medium">Revogados</h2>
          <ul className="grid gap-2">
            {revocations.map((item) => (
              <li key={item.serial} className="grid gap-1 rounded-md border p-3" data-testid="revocation">
                <p className="break-all text-sm">{item.subject || item.serial}</p>
                <p className="text-xs text-muted-foreground">
                  {item.reason || "Sem motivo informado"} · revogado em {formatDate(item.revoked_at)}
                </p>
                <p className="break-all font-mono text-xs text-muted-foreground">{item.serial}</p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
