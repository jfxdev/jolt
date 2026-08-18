import { Settings, Fingerprint, RefreshCw, ShieldPlus, Share2, ShieldCheck, KeyRound } from "lucide-react";
import { api } from "@/lib/api";
import { useWorkspace } from "@/context/WorkspaceContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm, usePrompt } from "@/context/ConfirmProvider";
import { mtlsRolloutPeers } from "@/lib/mtls";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export function NodeSettingsMenu() {
  const { nodeId, node, mtlsState, nodePath, refreshMTLSState } =
    useWorkspace();
  const { hasPermission } = usePermissions();
  const handleError = useApiError();
  const confirm = useConfirm();
  const prompt = usePrompt();

  if (!node) return null;

  const canIdentity = hasPermission(nodePath("keys/identity"), "sudo");
  const canMtls =
    hasPermission(nodePath("keys/mtls"), "sudo") &&
    hasPermission(nodePath("keys/mtls"), "execute");
  const canToken = hasPermission(
    `control-tower/nodes/${nodeId}/token`,
    "sudo",
  );

  if (!canIdentity && !canMtls && !canToken) return null;

  async function rotateIdentity() {
    try {
      const state = await api.identityState(nodeId);
      if (state.restart_required) {
        toast.info(
          "Este node já possui uma nova identidade persistida e precisa ser reiniciado.",
        );
        return;
      }
      const current = state.active?.fingerprint || "";
      const confirmation = await prompt({
        title: "Rotacionar identidade",
        description: `Operação crítica. Digite a fingerprint atual para confirmar:\n${current}`,
        label: "Fingerprint atual",
      });
      if (confirmation === null || confirmation.trim() !== current) {
        if (confirmation !== null)
          toast.error("A fingerprint informada não corresponde à identidade atual.");
        return;
      }
      if (
        !(await confirm({
          title: "Rotacionar a identidade estável?",
          description:
            "A passagem de confiança assinada será enviada aos peers disponíveis e o node precisará ser reiniciado.",
          confirmText: "Rotacionar",
          destructive: true,
        }))
      )
        return;
      const result = await api.rotateIdentity(nodeId, confirmation.trim());
      const acknowledged = result.acknowledged_peer_node_ids?.length || 0;
      const pending = result.pending_peer_node_ids?.length || 0;
      const delivery = result.delivery_complete
        ? `Confiança entregue a ${acknowledged} peer(s)${pending ? `; ${pending} pendente(s)` : ""}.`
        : "A identidade foi rotacionada, mas a entrega aos peers precisa ser reconciliada.";
      toast.success(
        `Nova fingerprint: ${result.next_active?.fingerprint}. ${delivery} Reinicie o node para ativá-la.`,
      );
    } catch (error) {
      handleError(error);
    }
  }

  async function reconcileIdentity() {
    if (
      !(await confirm({
        title: `Redistribuir a cadeia de identidade de “${node!.name}”?`,
        description: "Aos peers disponíveis.",
        confirmText: "Reconciliar",
      }))
    )
      return;
    try {
      const result = await api.distributeIdentityHandovers(nodeId);
      const acknowledged = result.acknowledged_peer_node_ids?.length || 0;
      const pending = result.pending_peer_node_ids?.length || 0;
      toast.success(
        result.delivery_complete
          ? `Passagem de confiança confirmada por ${acknowledged} peer(s)${pending ? `; ${pending} ainda pendente(s).` : "."}`
          : "Não foi possível completar a descoberta dos peers. Tente novamente quando o node estiver disponível.",
      );
    } catch (error) {
      handleError(error);
    }
  }

  async function prepareMTLS() {
    if (
      !(await confirm({
        title: "Preparar um novo certificado mTLS?",
        description:
          "O certificado ficará inativo até ser distribuído e promovido.",
        confirmText: "Preparar",
      }))
    )
      return;
    try {
      await api.prepareMTLSRotation(nodeId, 365);
      await refreshMTLSState();
      toast.success(
        "Novo certificado preparado. Distribua-o aos peers antes de promover.",
      );
    } catch (error) {
      handleError(error);
    }
  }

  async function distributeMTLS() {
    try {
      const result = await api.distributeMTLSRotation(nodeId);
      await refreshMTLSState();
      const acknowledged = result.acknowledged_peer_node_ids?.length || 0;
      const pending = result.pending_peer_node_ids?.length || 0;
      toast.success(
        `Certificado confirmado por ${acknowledged} peer(s)${pending ? `; ${pending} pendente(s).` : "."}`,
      );
    } catch (error) {
      handleError(error);
    }
  }

  async function promoteMTLS() {
    const pending = mtlsRolloutPeers(mtlsState).filter(
      (p) => p.status !== "acknowledged",
    ).length;
    if (
      !(await confirm({
        title: "Promover certificado mTLS",
        description: pending
          ? `Ainda há ${pending} peer(s) sem confirmação. Promover mesmo assim com 24 horas de grace?`
          : "Promover o certificado preparado com 24 horas de grace para o certificado anterior?",
        confirmText: "Promover",
      }))
    )
      return;
    try {
      await api.promoteMTLSRotation(nodeId, 24);
      await refreshMTLSState();
      toast.success("Novo certificado mTLS promovido.");
    } catch (error) {
      handleError(error);
    }
  }

  async function rotateToken() {
    if (
      !(await confirm({
        title: `Rotacionar a credencial operacional de “${node!.name}”?`,
        description: "O token anterior será invalidado ao final do processo.",
        confirmText: "Rotacionar",
        destructive: true,
      }))
    )
      return;
    try {
      await api.rotateNodeToken(nodeId);
      toast.success(
        "Credencial operacional rotacionada e token anterior invalidado.",
      );
    } catch (error) {
      handleError(error);
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm">
          <Settings className="h-4 w-4" />
          Configurações
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        {canIdentity && (
          <>
            <DropdownMenuLabel>Identidade</DropdownMenuLabel>
            <DropdownMenuItem onClick={rotateIdentity}>
              <Fingerprint className="h-4 w-4" />
              Rotacionar identidade
            </DropdownMenuItem>
            <DropdownMenuItem onClick={reconcileIdentity}>
              <RefreshCw className="h-4 w-4" />
              Reconciliar confiança
            </DropdownMenuItem>
          </>
        )}
        {canMtls && (
          <>
            {canIdentity && <DropdownMenuSeparator />}
            <DropdownMenuLabel>mTLS</DropdownMenuLabel>
            {!mtlsState?.next && (
              <DropdownMenuItem onClick={prepareMTLS}>
                <ShieldPlus className="h-4 w-4" />
                Preparar mTLS
              </DropdownMenuItem>
            )}
            {mtlsState?.next && (
              <DropdownMenuItem onClick={distributeMTLS}>
                <Share2 className="h-4 w-4" />
                Distribuir mTLS
              </DropdownMenuItem>
            )}
            {mtlsState?.next && (
              <DropdownMenuItem onClick={promoteMTLS}>
                <ShieldCheck className="h-4 w-4" />
                Promover mTLS
              </DropdownMenuItem>
            )}
          </>
        )}
        {canToken && (
          <>
            {(canIdentity || canMtls) && <DropdownMenuSeparator />}
            <DropdownMenuLabel>Token</DropdownMenuLabel>
            <DropdownMenuItem onClick={rotateToken}>
              <KeyRound className="h-4 w-4" />
              Rotacionar token
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
