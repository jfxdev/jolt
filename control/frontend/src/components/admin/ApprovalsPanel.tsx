import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { decisionMessage, describePending, operationLabel, remainingLabel, stateLabel } from "@/lib/approvals";
import type { PendingOperation } from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { useAuth } from "@/context/AuthContext";
import { useConfirm, usePrompt } from "@/context/ConfirmProvider";
import { usePermissions } from "@/context/PermissionsContext";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

const POLL_MS = 10_000;

// Requests that a policy lets someone make only once a person approves them.
// The approver runs the stored request with their own permissions.
export function ApprovalsPanel({ active }: { active: boolean }) {
  const handleError = useApiError();
  const confirm = useConfirm();
  const prompt = usePrompt();
  const { user } = useAuth();
  const { hasPermission } = usePermissions();
  const canDecide = hasPermission("control-tower/approvals", "sudo");
  const [enabled, setEnabled] = useState<boolean>();
  const [items, setItems] = useState<PendingOperation[]>([]);
  const [now, setNow] = useState(() => Date.now());
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    try {
      setItems((await api.pendingOperations({ state: "pending" })).items ?? []);
    } catch (error) {
      handleError(error);
    }
  }, [handleError]);

  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    void api
      .about()
      .then((about) => {
        if (!cancelled) setEnabled(about.features?.approvals === true);
      })
      .catch(() => {
        if (!cancelled) setEnabled(false);
      });
    return () => {
      cancelled = true;
    };
  }, [active]);

  useEffect(() => {
    if (!active || !enabled) return;
    void load();
    const refresh = window.setInterval(() => void load(), POLL_MS);
    const tick = window.setInterval(() => setNow(Date.now()), 1000);
    return () => {
      window.clearInterval(refresh);
      window.clearInterval(tick);
    };
  }, [active, enabled, load]);

  async function approve(op: PendingOperation) {
    const own = op.requester_type === "user" && op.requester_id === user?.user_id;
    const accepted = await confirm({
      title: `${operationLabel(op.summary.operation)}: aprovar?`,
      description: `${describePending(op)}. Pedido de ${op.requester_name ?? op.requester_id}. Será executado agora, com as suas permissões.${own ? " Este pedido é seu: você está aprovando o seu próprio pedido." : ""}`,
      confirmText: own ? "Aprovo o meu pedido" : "Aprovar e executar",
      destructive: true,
    });
    if (!accepted) return;
    setBusy(op.pending_operation_id);
    try {
      const decision = await api.approvePendingOperation(op.pending_operation_id, own);
      const message = decisionMessage(decision.result.status, decision.replayed);
      if (decision.result.status >= 200 && decision.result.status < 300) toast.success(message);
      else toast.warning(message);
      await load();
    } catch (error) {
      handleError(error);
      await load();
    } finally {
      setBusy("");
    }
  }

  async function reject(op: PendingOperation) {
    const note = await prompt({
      title: "Rejeitar o pedido?",
      description: `${describePending(op)}. Pedido de ${op.requester_name ?? op.requester_id}.`,
      confirmText: "Rejeitar",
      label: "Motivo (opcional)",
    });
    if (note === null) return;
    setBusy(op.pending_operation_id);
    try {
      await api.rejectPendingOperation(op.pending_operation_id, note.trim());
      toast.success("Pedido rejeitado.");
      await load();
    } catch (error) {
      handleError(error);
      await load();
    } finally {
      setBusy("");
    }
  }

  if (enabled === false) {
    return (
      <p className="text-sm text-muted-foreground" role="status">
        As aprovações humanas não estão habilitadas neste Control Tower (CONTROL_TOWER_APPROVALS).
      </p>
    );
  }

  return (
    <section className="grid gap-4" aria-label="Aprovações">
      <p className="max-w-3xl text-sm text-muted-foreground">
        Quando uma regra exige aprovação, apagar ou mover um arquivo espera aqui por cinco minutos. Quem aprova executa o
        pedido guardado com as próprias permissões; nada é executado antes.
      </p>
      {items.length === 0 && (
        <p className="text-sm text-muted-foreground" data-testid="approvals-empty">
          Nenhum pedido aguardando aprovação.
        </p>
      )}
      <ul className="grid gap-2">
        {items.map((op) => (
          <li key={op.pending_operation_id} className="grid gap-2 rounded-md border p-3" data-testid="pending-operation">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <strong className="text-sm">{operationLabel(op.summary.operation)}</strong>
              <Badge variant="outline">
                {stateLabel(op.state)} · {remainingLabel(op.expires_at, now)}
              </Badge>
            </div>
            <p className="break-all text-sm">{describePending(op)}</p>
            <p className="text-xs text-muted-foreground">
              Pedido de {op.requester_name ?? op.requester_id}
              {op.requester_type === "user" && op.requester_id === user?.user_id ? " (você)" : ""}
            </p>
            {canDecide && (
              <div className="flex gap-2">
                <Button size="sm" disabled={busy === op.pending_operation_id} onClick={() => void approve(op)}>
                  Aprovar
                </Button>
                <Button size="sm" variant="secondary" disabled={busy === op.pending_operation_id} onClick={() => void reject(op)}>
                  Rejeitar
                </Button>
              </div>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
