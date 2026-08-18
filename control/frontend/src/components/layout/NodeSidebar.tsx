import { useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { Link2, Plus } from "lucide-react";
import { useNodes } from "@/context/NodesContext";
import { usePermissions } from "@/context/PermissionsContext";
import { cn } from "@/lib/utils";
import { AddNodeDialog } from "@/components/node/AddNodeDialog";

const STATE_COLOR: Record<string, string> = {
  online: "bg-emerald-500",
  offline: "bg-destructive",
  untrusted: "bg-destructive",
  degraded: "bg-amber-500",
};

export function NodeSidebar() {
  const { nodes } = useNodes();
  const { hasPermission } = usePermissions();
  const { nodeId } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const [addOpen, setAddOpen] = useState(false);

  const canAdd = hasPermission("control-tower/nodes", "sudo");

  return (
    <aside className="flex min-h-[calc(100vh-4rem)] flex-col border-r p-3">
      <div className="flex items-center justify-between px-2 pb-3 font-mono text-xs uppercase tracking-widest text-muted-foreground">
        <span>Nodes</span>
        {canAdd && (
          <button
            aria-label="Adicionar node"
            className="grid h-7 w-7 place-content-center rounded-md border hover:bg-accent"
            onClick={() => setAddOpen(true)}
          >
            <Plus className="h-4 w-4" />
          </button>
        )}
      </div>

      <button
        className={cn(
          "mb-3 flex items-center gap-2 rounded-lg px-2 py-2 text-left text-sm font-medium hover:bg-accent",
          location.pathname === "/relationships" && "bg-accent",
        )}
        onClick={() => navigate("/relationships")}
      >
        <span className="grid h-9 w-9 place-content-center rounded-md bg-muted">
          <Link2 className="h-4 w-4" />
        </span>
        Connections
      </button>

      {nodes.map((node) => (
        <button
          key={node.node_id}
          className={cn(
            "grid grid-cols-[38px_1fr_10px] items-center gap-2 rounded-lg p-2 text-left hover:bg-accent",
            nodeId === node.node_id && "bg-accent",
          )}
          onClick={() => navigate(`/nodes/${node.node_id}`)}
        >
          <span className="grid h-9 w-9 place-content-center rounded-md bg-muted font-mono text-xs">
            {node.name.slice(0, 2).toUpperCase()}
          </span>
          <span className="min-w-0">
            <span className="block truncate text-sm font-semibold">
              {node.name}
            </span>
            <span className="block truncate text-xs text-muted-foreground">
              {node.endpoint}
            </span>
          </span>
          <span
            className={cn(
              "h-2 w-2 rounded-full",
              STATE_COLOR[node.state] || "bg-muted-foreground",
            )}
          />
        </button>
      ))}

      {!nodes.length && (
        <div className="px-2 py-5 text-xs text-muted-foreground">
          Nenhum node conectado.
        </div>
      )}

      <AddNodeDialog open={addOpen} onOpenChange={setAddOpen} />
    </aside>
  );
}
