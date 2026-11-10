import { useState, type ComponentType, type SVGProps } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { Plus, ScrollText } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { useNodes } from "@/context/NodesContext";
import { usePermissions } from "@/context/PermissionsContext";
import { cn } from "@/lib/utils";
import { STATE_COLOR } from "@/components/node/NodeBadge";
import { AddNodeDialog } from "@/components/node/AddNodeDialog";
import { AuditDialog } from "@/components/admin/AuditDialog";
import { BuildVersion } from "@/components/layout/BuildVersion";
import { JoltMark } from "@/components/brand/JoltLogo";
import {
  AccessIcon,
  JobsIcon,
  NetworkIcon,
  TransferIcon,
  TrustIcon,
  VolumesIcon,
} from "@/components/brand/icons";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupAction,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

type AdminPanel = "audit";

type Icon = ComponentType<SVGProps<SVGSVGElement>>;

function SidebarLink({
  to,
  label,
  icon: IconComponent,
  active,
}: {
  to: string;
  label: string;
  icon: Icon;
  active: boolean;
}) {
  const { isMobile, setOpenMobile } = useSidebar();

  return (
    <SidebarMenuButton
      render={
        <NavLink
          to={to}
          onClick={() => {
            if (isMobile) setOpenMobile(false);
          }}
        />
      }
      isActive={active}
      tooltip={label}
      className="relative data-active:text-sidebar-accent-foreground data-active:[&_svg]:text-sidebar-primary before:absolute before:inset-y-2 before:left-0 before:w-0.5 before:rounded-full before:bg-sidebar-primary before:opacity-0 data-active:before:opacity-100"
    >
      <IconComponent />
      <span>{label}</span>
    </SidebarMenuButton>
  );
}

export function AppSidebar() {
  const { user, logout } = useAuth();
  const { nodes } = useNodes();
  const { hasPermission } = usePermissions();
  const { pathname } = useLocation();
  const [addOpen, setAddOpen] = useState(false);
  const [panel, setPanel] = useState<AdminPanel | null>(null);

  const canAdd = hasPermission("control-tower/nodes", "sudo");
  const canAccess =
    hasPermission("control-tower/access-groups", "sudo") ||
    hasPermission("control-tower/roles", "sudo") ||
    hasPermission("control-tower/policies", "sudo") ||
    hasPermission("control-tower/approvals", "list") ||
    hasPermission("control-tower/crypto", "sudo");
  const canIdentity =
    hasPermission("control-tower/users", "sudo") ||
    hasPermission("control-tower/service-accounts", "sudo");
  const canAudit = hasPermission("control-tower/audit", "sudo");

  return (
    <>
      <Sidebar variant="inset" collapsible="offcanvas">
        <SidebarHeader>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton
                size="lg"
                render={<NavLink to="/" aria-label="Jolt, visão da rede" />}
                className="hover:bg-transparent active:bg-transparent"
              >
                <JoltMark glow="neon" className="size-8!" />
                <span className="grid leading-tight">
                  <span className="text-base font-bold tracking-tight">Jolt</span>
                  <span className="font-mono text-[10px] uppercase tracking-widest text-sidebar-foreground/60">
                    Control Tower
                  </span>
                </span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarHeader>

        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>Control Tower</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarLink
                    to="/"
                    label="Visão da rede"
                    icon={NetworkIcon}
                    active={pathname === "/"}
                  />
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarLink
                    to="/relationships"
                    label="Relacionamentos"
                    icon={TransferIcon}
                    active={pathname === "/relationships"}
                  />
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarLink
                    to="/jobs"
                    label="Jobs"
                    icon={JobsIcon}
                    active={pathname === "/jobs"}
                  />
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>

          <SidebarGroup>
            <SidebarGroupLabel>Nodes</SidebarGroupLabel>
            {canAdd && (
              <SidebarGroupAction
                aria-label="Adicionar node"
                title="Adicionar node"
                onClick={() => setAddOpen(true)}
              >
                <Plus />
              </SidebarGroupAction>
            )}
            <SidebarGroupContent>
              <SidebarMenu>
                {nodes.map((node) => (
                  <SidebarMenuItem key={node.node_id}>
                    <SidebarLink
                      to={`/nodes/${node.node_id}`}
                      label={node.name}
                      icon={VolumesIcon}
                      active={pathname.startsWith(`/nodes/${node.node_id}`)}
                    />
                    <SidebarMenuBadge title={node.state}>
                      <span
                        aria-label={`Node ${node.state}`}
                        className={cn(
                          "block size-2 rounded-full",
                          STATE_COLOR[node.state] || "bg-muted-foreground",
                        )}
                      />
                    </SidebarMenuBadge>
                  </SidebarMenuItem>
                ))}
                {!nodes.length && (
                  <li className="px-2 py-2 text-xs text-sidebar-foreground/70">
                    Nenhum node conectado.
                  </li>
                )}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>

          {(canAccess || canIdentity || canAudit) && (
            <SidebarGroup className="mt-auto">
              <SidebarGroupLabel>Administração</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {canAccess && (
                    <SidebarMenuItem>
                      <SidebarLink
                        to="/access"
                        label="Access"
                        icon={TrustIcon}
                        active={pathname === "/access"}
                      />
                    </SidebarMenuItem>
                  )}
                  {canIdentity && (
                    <SidebarMenuItem>
                      <SidebarLink
                        to="/identity"
                        label="Identity"
                        icon={AccessIcon}
                        active={pathname === "/identity"}
                      />
                    </SidebarMenuItem>
                  )}
                  {canAudit && (
                    <SidebarMenuItem>
                      <SidebarMenuButton
                        onClick={() => setPanel("audit")}
                        tooltip="Auditoria"
                      >
                        <ScrollText />
                        <span>Auditoria</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  )}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          )}
        </SidebarContent>

        <SidebarFooter>
          <BuildVersion />
          <SidebarMenu>
            <SidebarMenuItem>
              <DropdownMenu>
                <DropdownMenuTrigger render={<SidebarMenuButton size="lg" />}>
                  <span className="grid size-7 place-content-center rounded-md bg-brand-gradient text-xs font-semibold text-sidebar-primary-foreground">
                    {user?.username.slice(0, 1).toUpperCase() || "J"}
                  </span>
                  <span>{user?.username || "Conta"}</span>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" side="right" className="w-52">
                  <DropdownMenuGroup>
                    <DropdownMenuLabel>
                      <p className="font-medium">{user?.username}</p>
                      <p className="text-xs font-normal text-muted-foreground">
                        {user?.role}
                      </p>
                    </DropdownMenuLabel>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onClick={() => void logout()}>
                      Sair
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                </DropdownMenuContent>
              </DropdownMenu>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
      </Sidebar>

      <AddNodeDialog open={addOpen} onOpenChange={setAddOpen} />
      <AuditDialog
        open={panel === "audit"}
        onOpenChange={(open) => setPanel(open ? "audit" : null)}
      />
    </>
  );
}
