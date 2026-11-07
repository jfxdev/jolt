import { cn } from "@/lib/utils";
import type { NodeInfo } from "@/lib/types";

export const STATE_COLOR: Record<string, string> = {
  online: "bg-emerald-500",
  offline: "bg-destructive",
  untrusted: "bg-destructive",
  degraded: "bg-amber-500",
};

/** Node name with its state dot, the same indicator the sidebar uses. */
export function NodeBadge({
  node,
  className,
}: {
  node: Pick<NodeInfo, "name" | "state">;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 rounded-md border bg-muted/40 px-2 py-1 text-sm font-medium",
        className,
      )}
      title={node.state}
      data-testid="node-badge"
    >
      <span
        aria-label={`Node ${node.state}`}
        className={cn(
          "block size-2 rounded-full",
          STATE_COLOR[node.state] || "bg-muted-foreground",
        )}
      />
      {node.name}
    </span>
  );
}
