import { useMemo, useState } from "react";
import { useWorkspace } from "@/context/WorkspaceContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useNodes } from "@/context/NodesContext";
import { Button } from "@/components/ui/button";
import { AddMountDialog } from "@/components/workspace/AddMountDialog";
import { ConnectDialog } from "@/components/workspace/ConnectDialog";
import { DeleteNodeDialog } from "@/components/workspace/DeleteNodeDialog";

export function NodeActionsBar() {
  const { nodeId, node, nodePath, mounts, trustPeers, refreshTrust } =
    useWorkspace();
  const { hasPermission } = usePermissions();
  const { nodes } = useNodes();

  const [connectOpen, setConnectOpen] = useState(false);
  const [mountOpen, setMountOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);

  // Peers already related to this node are not offered again.
  const connectedNodeIdsByIssuer = useMemo(
    () => ({
      [nodeId]: trustPeers
        .filter((peer) => peer.state !== "revoked")
        .map((peer) => peer.node_id),
    }),
    [nodeId, trustPeers],
  );

  if (!node) return null;

  return (
    <div className="flex flex-wrap items-center gap-2">
      {hasPermission("control-tower/connections", "sudo") && (
        <Button
          variant="secondary"
          size="sm"
          disabled={nodes.length < 2}
          onClick={() => setConnectOpen(true)}
        >
          Conectar
        </Button>
      )}
      {node.configuration?.mounts_mutable !== false && hasPermission(nodePath("mounts"), "create") && (
        <Button size="sm" onClick={() => setMountOpen(true)}>
          Novo mount
        </Button>
      )}
      {hasPermission("control-tower/nodes", "sudo") && (
        <Button
          variant="outline"
          size="sm"
          onClick={() => setDeleteOpen(true)}
        >
          Remover node
        </Button>
      )}

      <ConnectDialog
        open={connectOpen}
        onOpenChange={setConnectOpen}
        issuerNodeId={nodeId}
        connectedNodeIdsByIssuer={connectedNodeIdsByIssuer}
        issuerMounts={mounts}
        onConnectionCreated={refreshTrust}
      />
      <AddMountDialog open={mountOpen} onOpenChange={setMountOpen} />
      <DeleteNodeDialog open={deleteOpen} onOpenChange={setDeleteOpen} />
    </div>
  );
}
