import { useWorkspace } from "@/context/WorkspaceContext";
import { Card } from "@/components/ui/card";
import { mtlsRolloutPeers } from "@/lib/mtls";

export function MtlsRolloutMetrics() {
  const { mtlsState } = useWorkspace();
  if (!mtlsState?.next) return null;

  const peers = mtlsRolloutPeers(mtlsState);
  const acknowledged = peers.filter((p) => p.status === "acknowledged");
  const pending = peers.filter((p) => p.status !== "acknowledged");

  return (
    <div className="grid gap-4 sm:grid-cols-3">
      <Card className="grid gap-1 p-6">
        <span className="text-sm text-muted-foreground">
          Rotação mTLS preparada
        </span>
        <strong className="text-lg">{mtlsState.next.key_id}</strong>
        <small className="text-muted-foreground">
          Serial {mtlsState.next.serial}
        </small>
      </Card>
      <Card className="grid gap-1 p-6">
        <span className="text-sm text-muted-foreground">Peers confirmados</span>
        <strong className="text-3xl font-semibold">
          {acknowledged.length}
        </strong>
        <small className="text-muted-foreground">
          de {peers.length} no rollout
        </small>
      </Card>
      <Card className="grid gap-1 p-6">
        <span className="text-sm text-muted-foreground">Pendências</span>
        <strong className="text-3xl font-semibold">{pending.length}</strong>
        <small className="text-muted-foreground">
          {pending.map((p) => p.node_id).join(", ") ||
            "Todos os peers confirmaram"}
        </small>
      </Card>
    </div>
  );
}
