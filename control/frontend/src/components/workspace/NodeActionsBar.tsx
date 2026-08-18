import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useWorkspace } from "@/context/WorkspaceContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useNodes } from "@/context/NodesContext";
import { remoteSourceNodes } from "@/lib/peers";
import { Button } from "@/components/ui/button";
import { AddMountDialog } from "@/components/workspace/AddMountDialog";
import { RemoteTransferDialog } from "@/components/workspace/RemoteTransferDialog";
import { DeleteNodeDialog } from "@/components/workspace/DeleteNodeDialog";

export function NodeActionsBar() {
  const { nodeId, node, grants, peers, nodePath } = useWorkspace();
  const { hasPermission } = usePermissions();
  const { nodes } = useNodes();
  const navigate = useNavigate();

  const [mountOpen, setMountOpen] = useState(false);
  const [transferOpen, setTransferOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);

  if (!node) return null;

  const sources = remoteSourceNodes(nodes, peers, nodeId);

  return (
    <div className="flex flex-wrap items-center gap-2">
      {hasPermission("control-tower/connections", "create") && (
        <Button
          variant="secondary"
          size="sm"
          disabled={nodes.length < 2}
          onClick={() => navigate("/relationships")}
        >
          Connect
        </Button>
      )}
      {hasPermission(nodePath("transfers"), "execute") && (
        <Button
          variant="secondary"
          size="sm"
          disabled={!sources.length || !grants.length}
          onClick={() => setTransferOpen(true)}
        >
          Transferir de peer
        </Button>
      )}
      {hasPermission(nodePath("mounts"), "create") && (
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

      <AddMountDialog open={mountOpen} onOpenChange={setMountOpen} />
      <RemoteTransferDialog open={transferOpen} onOpenChange={setTransferOpen} />
      <DeleteNodeDialog open={deleteOpen} onOpenChange={setDeleteOpen} />
    </div>
  );
}
