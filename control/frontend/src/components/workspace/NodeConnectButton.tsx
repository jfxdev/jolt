import { useMemo, useState } from "react";
import { Plus } from "lucide-react";
import { useWorkspace } from "@/context/WorkspaceContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useNodes } from "@/context/NodesContext";
import { Button } from "@/components/ui/button";
import { ConnectDialog } from "@/components/workspace/ConnectDialog";

export function NodeConnectButton() {
  const { nodeId, node, mounts, trustPeers, refreshTrust } = useWorkspace();
  const { hasPermission } = usePermissions();
  const { nodes } = useNodes();
  const [open, setOpen] = useState(false);

  // Peers already related to this node are not offered again.
  const connectedNodeIdsByIssuer = useMemo(
    () => ({
      [nodeId]: trustPeers
        .filter((peer) => peer.state !== "revoked")
        .map((peer) => peer.node_id),
    }),
    [nodeId, trustPeers],
  );

  if (!node || !hasPermission("control-tower/connections", "sudo")) return null;

  return (
    <>
      <Button
        size="sm"
        className="max-sm:size-10 max-sm:px-0"
        disabled={nodes.length < 2}
        onClick={() => setOpen(true)}
      >
        <Plus className="h-4 w-4 max-sm:size-5" />
        <span className="max-sm:sr-only">Conectar</span>
      </Button>
      <ConnectDialog
        open={open}
        onOpenChange={setOpen}
        issuerNodeId={nodeId}
        connectedNodeIdsByIssuer={connectedNodeIdsByIssuer}
        issuerMounts={mounts}
        onConnectionCreated={refreshTrust}
      />
    </>
  );
}
