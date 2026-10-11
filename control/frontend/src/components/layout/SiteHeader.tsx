import { useLocation } from "react-router-dom";
import { useNodes } from "@/context/NodesContext";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";

function pageTitle(pathname: string, nodes: ReturnType<typeof useNodes>["nodes"]) {
  if (pathname === "/") return "Visão da rede";
  if (pathname === "/relationships") return "Relacionamentos";
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

  return (
    <header className="sticky top-0 z-20 flex h-12 shrink-0 items-center gap-2 border-b bg-background/95 px-3 backdrop-blur supports-backdrop-filter:bg-background/80 sm:px-4">
      <SidebarTrigger className="-ml-1" />
      <Separator orientation="vertical" className="mr-1 h-4" />
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem className="hidden md:block">
            <span className="text-muted-foreground">Jolt</span>
          </BreadcrumbItem>
          <BreadcrumbSeparator className="hidden md:block" />
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
