import { useState } from "react";
import { useWorkspace } from "@/context/WorkspaceContext";
import { usePermissions } from "@/context/PermissionsContext";
import { Button } from "@/components/ui/button";
import { AddMountDialog } from "@/components/workspace/AddMountDialog";

export function NodeActionsBar() {
  const { node, nodePath } = useWorkspace();
  const { hasPermission } = usePermissions();

  const [mountOpen, setMountOpen] = useState(false);

  if (
    !node ||
    node.configuration?.mounts_mutable === false ||
    !hasPermission(nodePath("mounts"), "create")
  )
    return null;

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button size="sm" onClick={() => setMountOpen(true)}>
        Novo mount
      </Button>
      <AddMountDialog open={mountOpen} onOpenChange={setMountOpen} />
    </div>
  );
}
