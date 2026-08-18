import { useWorkspace } from "@/context/WorkspaceContext";
import { formatDate } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { NodeActionsBar } from "@/components/workspace/NodeActionsBar";
import { NodeSettingsMenu } from "@/components/workspace/NodeSettingsMenu";
import { MtlsRolloutMetrics } from "@/components/workspace/MtlsRolloutMetrics";
import { MountStrip } from "@/components/workspace/MountStrip";
import { JobsPanel } from "@/components/workspace/JobsPanel";

export default function NodeWorkspacePage() {
  const { node } = useWorkspace();

  if (!node) {
    return (
      <p className="text-sm text-muted-foreground">Carregando node…</p>
    );
  }

  return (
    <div className="grid gap-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Node selecionado
          </p>
          <h1 className="text-3xl font-semibold tracking-tight">
            {node.name}
          </h1>
          <p className="text-sm text-muted-foreground">
            {node.endpoint} · visto {formatDate(node.last_seen_at)}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="secondary">{node.state}</Badge>
          <NodeSettingsMenu />
        </div>
      </div>

      <NodeActionsBar />
      <MtlsRolloutMetrics />
      <MountStrip />
      <JobsPanel />
    </div>
  );
}
