import { Link } from "react-router-dom";
import { useNetworkDiagnostics } from "@/hooks/useNetworkDiagnostics";
import { peersNeedingAttention } from "@/lib/trust";
import { formatDate } from "@/lib/format";
import { summarizeNetworkJobs } from "@/lib/network-summary";
import { useState } from "react";
import { Plus } from "lucide-react";
import { useNodes } from "@/context/NodesContext";
import { usePermissions } from "@/context/PermissionsContext";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { AddNodeDialog } from "@/components/node/AddNodeDialog";

export default function NetworkOverviewPage() {
  const { nodes } = useNodes();
  const { diagnostics, error } = useNetworkDiagnostics();
  const activity = summarizeNetworkJobs(
    nodes.map((node) => diagnostics[node.node_id]?.jobs),
  );
  const { hasPermission } = usePermissions();
  const [addOpen, setAddOpen] = useState(false);

  const online = nodes.filter((n) => n.state === "online").length;
  const canAdd = hasPermission("control-tower/nodes", "sudo");

  const heading = nodes.length
    ? "Escolha um node para começar."
    : canAdd
      ? "Conecte seu primeiro node."
      : "Nenhum node autorizado.";

  return (
    <div className="grid gap-8">
      <Card className="flex min-h-[46vh] flex-col items-start justify-center gap-5 p-10 lg:p-16">
        <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
          Visão da rede
        </p>
        <h1 className="max-w-2xl text-4xl font-semibold tracking-tight lg:text-6xl">
          {heading}
        </h1>
        <p className="max-w-xl text-muted-foreground">
          A Control Tower coordena operações pelas APIs dos nodes. Seus arquivos
          continuam onde pertencem.
        </p>
        {canAdd && (
          <Button onClick={() => setAddOpen(true)}>
            {nodes.length ? "Adicionar outro node" : "Conectar node"} <Plus />
          </Button>
        )}
      </Card>

      <div className="grid gap-4 sm:grid-cols-3">
        <Metric label="Nodes conhecidos" value={nodes.length} />
        <Metric label="Disponíveis agora" value={online} />
        <Metric label="Operações ativas" value={activity.active ?? "—"} />
      </div>

      {activity.partial && (
        <p className="text-sm text-muted-foreground">
          Visão parcial: há dados indisponíveis, anteriores ou restritos por
          permissão.
        </p>
      )}
      {error && (
        <p role="status" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <section
        className="grid gap-4 md:grid-cols-2"
        aria-label="Diagnóstico dos nodes"
      >
        {nodes.map((node) => {
          const data = diagnostics[node.node_id];
          const counts = data?.jobs.value?.counts;
          const waiting = counts
            ? [
                "paused",
                "waiting_peer",
                "waiting_mount",
                "waiting_validation",
                "waiting_user_decision",
              ].reduce((sum, state) => sum + (counts[state] || 0), 0)
            : null;
          const unavailable = data?.mounts.value?.filter(
            (mount) =>
              !mount.enabled ||
              mount.state === "unavailable" ||
              mount.state === "degraded",
          ).length;
          const certificate = data?.mtls.value?.current as
            { not_after?: string; state?: string } | undefined;
          const certificateText = data?.mtls.value
            ? certificate?.not_after
              ? `${Date.parse(certificate.not_after) <= Date.now() ? "Expirado em" : "Válido até"} ${formatDate(certificate.not_after)}`
              : certificate?.state || "Sem certificado ativo informado"
            : undefined;
          return (
            <Card key={node.node_id} className="grid gap-4 p-5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <Link
                  className="font-semibold underline-offset-4 hover:underline"
                  to={`/nodes/${encodeURIComponent(node.node_id)}`}
                >
                  {node.name}
                </Link>
                <span className="text-xs text-muted-foreground">
                  {node.state === "online"
                    ? "Disponível"
                    : node.state === "offline"
                      ? "Offline"
                      : node.state === "untrusted"
                        ? "Credencial recusada"
                        : "Acesso limitado"}
                </span>
              </div>
              {node.last_seen_at && (
                <p className="text-xs text-muted-foreground">
                  Último contato: {formatDate(node.last_seen_at)}
                </p>
              )}
              <dl className="grid gap-3 text-sm">
                <Diagnostic
                  label="Jobs"
                  observation={data?.jobs}
                  value={
                    counts
                      ? `${(counts.running || 0) + (counts.pause_requested || 0) + (counts.cancel_requested || 0)} em execução · ${counts.queued || 0} na fila · ${waiting} aguardando`
                      : undefined
                  }
                />
                <Diagnostic
                  label="Volumes"
                  observation={data?.mounts}
                  value={
                    data?.mounts.value
                      ? `${unavailable} indisponíveis ou com acesso limitado`
                      : undefined
                  }
                />
                <Diagnostic
                  label="Confiança"
                  observation={data?.trust}
                  value={
                    data?.trust.value
                      ? `${peersNeedingAttention(data.trust.value.peers).length} conexões precisam de atenção`
                      : undefined
                  }
                />
                <Diagnostic
                  label="Certificados"
                  observation={data?.mtls}
                  value={certificateText}
                />
              </dl>
            </Card>
          );
        })}
      </section>
      <AddNodeDialog open={addOpen} onOpenChange={setAddOpen} />
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return (
    <Card className="grid gap-2 p-6">
      <span className="text-sm text-muted-foreground">{label}</span>
      <strong className="text-3xl font-semibold">{value}</strong>
    </Card>
  );
}

function Diagnostic({
  label,
  observation,
  value,
}: {
  label: string;
  observation?: { observedAt?: string; error?: string; restricted?: boolean };
  value?: string;
}) {
  return (
    <div className="grid gap-1">
      <dt className="text-muted-foreground">{label}</dt>
      <dd>
        {observation?.restricted
          ? "Restrito por permissão"
          : (value ?? (observation?.error ? "Indisponível" : "Carregando…"))}
      </dd>
      {observation?.observedAt && (
        <dd className="text-xs text-muted-foreground">
          {observation.error ? "Dados anteriores" : "Atualizado"}:{" "}
          {formatDate(observation.observedAt)}
        </dd>
      )}
      {observation?.error && value !== undefined && (
        <dd className="text-xs text-destructive">{observation.error}</dd>
      )}
    </div>
  );
}
