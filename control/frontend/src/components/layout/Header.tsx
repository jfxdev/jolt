import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useNodes } from "@/context/NodesContext";
import { Button } from "@/components/ui/button";
import { UsersDialog } from "@/components/admin/UsersDialog";
import { ServiceAccountsDialog } from "@/components/admin/ServiceAccountsDialog";
import { RolesDialog } from "@/components/admin/RolesDialog";
import { PoliciesDialog } from "@/components/admin/PoliciesDialog";
import { AuditDialog } from "@/components/admin/AuditDialog";
import { AccessGroupsDialog } from "@/components/admin/AccessGroupsDialog";

type AdminPanel = "users" | "service-accounts" | "access-groups" | "roles" | "policies" | "audit";

export function Header() {
  const { user, logout } = useAuth();
  const { hasPermission } = usePermissions();
  const { nodes } = useNodes();
  const navigate = useNavigate();
  const [panel, setPanel] = useState<AdminPanel | null>(null);

  const online = nodes.filter((n) => n.state === "online").length;

  return (
    <header className="sticky top-0 z-10 col-span-2 flex h-16 items-center gap-6 border-b bg-background/95 px-6 backdrop-blur">
      <button
        className="flex items-center gap-2 text-lg font-semibold"
        onClick={() => navigate("/")}
      >
        <span className="grid h-8 w-8 place-content-center rounded-md bg-primary text-sm font-bold text-primary-foreground">
          J
        </span>
        Jolt
      </button>

      <div className="mx-auto flex items-center gap-2 font-mono text-xs uppercase tracking-wide text-muted-foreground">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
        {online} nodes online
      </div>

      <div className="flex items-center gap-1 text-sm">
        <span className="mr-2 text-muted-foreground">{user?.username}</span>
        {hasPermission("control-tower/users", "sudo") && (
          <Button variant="ghost" size="sm" onClick={() => setPanel("users")}>
            Usuários
          </Button>
        )}
        {hasPermission("control-tower/service-accounts", "sudo") && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setPanel("service-accounts")}
          >
            API Keys
          </Button>
        )}
        {hasPermission("control-tower/access-groups", "sudo") && (
          <Button variant="ghost" size="sm" onClick={() => setPanel("access-groups")}>Grupos</Button>
        )}
        {hasPermission("control-tower/roles", "sudo") && (
          <Button variant="ghost" size="sm" onClick={() => setPanel("roles")}>
            Roles
          </Button>
        )}
        {hasPermission("control-tower/policies", "sudo") && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setPanel("policies")}
          >
            Policies
          </Button>
        )}
        {hasPermission("control-tower/audit", "sudo") && (
          <Button variant="ghost" size="sm" onClick={() => setPanel("audit")}>
            Auditoria
          </Button>
        )}
        <Button variant="ghost" size="sm" onClick={() => logout()}>
          Sair
        </Button>
      </div>

      <UsersDialog
        open={panel === "users"}
        onOpenChange={(o) => setPanel(o ? "users" : null)}
      />
      <ServiceAccountsDialog
        open={panel === "service-accounts"}
        onOpenChange={(o) => setPanel(o ? "service-accounts" : null)}
      />
      <AccessGroupsDialog
        open={panel === "access-groups"}
        onOpenChange={(o) => setPanel(o ? "access-groups" : null)}
      />
      <RolesDialog
        open={panel === "roles"}
        onOpenChange={(o) => setPanel(o ? "roles" : null)}
      />
      <PoliciesDialog
        open={panel === "policies"}
        onOpenChange={(o) => setPanel(o ? "policies" : null)}
      />
      <AuditDialog
        open={panel === "audit"}
        onOpenChange={(o) => setPanel(o ? "audit" : null)}
      />
    </header>
  );
}
