import { useSearchParams } from "react-router-dom";
import { useWorkspace } from "@/context/WorkspaceContext";
import { formatDate } from "@/lib/format";
import { peersNeedingAttention } from "@/lib/trust";
import { Badge } from "@/components/ui/badge";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { NodeActionsBar } from "@/components/workspace/NodeActionsBar";
import { NodeSettingsMenu } from "@/components/workspace/NodeSettingsMenu";
import { MtlsRolloutMetrics } from "@/components/workspace/MtlsRolloutMetrics";
import { MountStrip } from "@/components/workspace/MountStrip";
import { JobsPanel } from "@/components/workspace/JobsPanel";
import { TrustPanel } from "@/components/workspace/TrustPanel";

const tabs = ["overview", "trust", "jobs"] as const;
type NodeTab = (typeof tabs)[number];

export default function NodeWorkspacePage() {
  const { node, trustPeers, pairingRequests } = useWorkspace();
  // The tab lives in the URL so a reconciliation warning can be linked to.
  const [searchParams, setSearchParams] = useSearchParams();
  const requested = searchParams.get("tab");
  const currentTab: NodeTab = tabs.includes(requested as NodeTab)
    ? (requested as NodeTab)
    : "overview";

  if (!node) {
    return <p className="text-sm text-muted-foreground">Carregando node…</p>;
  }

  const needsAttention =
    peersNeedingAttention(trustPeers).length +
    pairingRequests.filter((request) => request.status === "pending_review")
      .length;

  return (
    <div className="grid gap-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Node selecionado
          </p>
          <h1 className="text-3xl font-semibold tracking-tight">{node.name}</h1>
          <p className="text-sm text-muted-foreground">
            {node.endpoint} · visto {formatDate(node.last_seen_at)}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="secondary">{node.state}</Badge>
          <NodeSettingsMenu />
        </div>
      </div>

      <Tabs
        value={currentTab}
        onValueChange={(value) => {
          if (typeof value !== "string") return;
          setSearchParams(
            (previous) => {
              const next = new URLSearchParams(previous);
              if (value === "overview") next.delete("tab");
              else next.set("tab", value);
              return next;
            },
            { replace: true },
          );
        }}
      >
        <TabsList>
          <TabsTrigger value="overview">Visão geral</TabsTrigger>
          <TabsTrigger value="trust">
            Confiança
            {needsAttention > 0 && (
              <Badge variant="destructive" className="ml-2">
                {needsAttention}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="jobs">Jobs</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="grid gap-8 pt-4">
          <NodeActionsBar />
          <MtlsRolloutMetrics />
          <MountStrip />
        </TabsContent>
        <TabsContent value="trust" className="pt-4">
          <TrustPanel />
        </TabsContent>
        <TabsContent value="jobs" className="pt-4">
          <JobsPanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}
