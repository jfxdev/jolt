import { Link, useLocation } from "react-router-dom";
import { useNodes } from "@/context/NodesContext";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { NodeBadge } from "@/components/node/NodeBadge";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";

function pageTitle(pathname: string, nodes: ReturnType<typeof useNodes>["nodes"]) {
  if (pathname === "/") return "Visão da rede";
  if (pathname === "/relationships") return "Relacionamentos";
  if (pathname === "/jobs") return "Jobs";
  if (pathname === "/access") return "Access";
  if (pathname === "/identity") return "Identity";

  const match = pathname.match(/^\/nodes\/([^/]+)/);
  if (!match) return "Control Tower";

  const node = nodes.find((item) => item.node_id === match[1]);
  return pathname.includes("/mounts/")
    ? "Arquivos"
    : node?.name || "Node";
}

export function SiteHeader() {
  const { pathname } = useLocation();
  const { nodes } = useNodes();
  const online = nodes.filter((node) => node.state === "online").length;
  const title = pageTitle(pathname, nodes);
  // Files lives under a node, so the node is named in the trail instead of
  // being inferred from the sidebar highlight. The node ID comes from the
  // route, so the link survives a deep link while the inventory still loads.
  const filesNodeId = pathname.includes("/mounts/")
    ? pathname.match(/^\/nodes\/([^/]+)/)?.[1]
    : undefined;
  const filesNode = nodes.find((item) => item.node_id === filesNodeId);
  // `nodes` is empty until the first load, so only a non-empty inventory that
  // lacks the ID proves the node is gone.
  const filesNodeMissing = !!filesNodeId && !filesNode && nodes.length > 0;

  return (
    <header className="sticky top-0 z-20 flex h-12 shrink-0 items-center gap-2 border-b bg-background/95 px-3 backdrop-blur supports-backdrop-filter:bg-background/80 sm:px-4">
      <SidebarTrigger className="-ml-1" />
      <Separator orientation="vertical" className="mr-1 h-4" />
      <Breadcrumb>
        <BreadcrumbList>
          {filesNodeId && (
            <>
              <BreadcrumbItem>
                <Link to={`/nodes/${filesNodeId}`}>
                  {filesNode ? (
                    <NodeBadge node={filesNode} className="text-foreground" />
                  ) : (
                    <span className="inline-flex items-center rounded-md border bg-muted/40 px-2 py-1 text-sm font-medium text-muted-foreground">
                      {filesNodeMissing ? "Node indisponível" : "Node"}
                    </span>
                  )}
                </Link>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
            </>
          )}
          <BreadcrumbItem>
            <BreadcrumbPage>{title}</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>
      <div className="ml-auto flex items-center gap-2 font-mono text-xs uppercase tracking-wide text-muted-foreground">
        <span className="size-1.5 rounded-full bg-emerald-500" />
        <span className="hidden sm:inline">{online} nodes online</span>
        <span className="sm:hidden">{online}</span>
      </div>
    </header>
  );
}
