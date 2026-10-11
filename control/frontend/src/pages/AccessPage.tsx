import { useState } from "react";
import { usePermissions } from "@/context/PermissionsContext";
import { AccessGroupsDialog } from "@/components/admin/AccessGroupsDialog";
import { PoliciesDialog } from "@/components/admin/PoliciesDialog";
import { RolesDialog } from "@/components/admin/RolesDialog";
import { SharesPanel } from "@/components/admin/SharesPanel";
import { Card } from "@/components/ui/card";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";

type AccessTab = "policies" | "roles" | "groups" | "shares";

export default function AccessPage() {
  const { hasPermission } = usePermissions();
  const [activeTab, setActiveTab] = useState<AccessTab | null>(null);
  const canManagePolicies = hasPermission("control-tower/policies", "sudo");
  const canManageRoles = hasPermission("control-tower/roles", "sudo");
  const canManageGroups = hasPermission(
    "control-tower/access-groups",
    "sudo",
  );
  // Listing links needs only the shares capability, so an operator who may
  // publish links can also audit and revoke their own.
  const canManageShares = hasPermission("control-tower/shares", "list");
  const firstTab = canManagePolicies
    ? "policies"
    : canManageRoles
      ? "roles"
      : canManageGroups
        ? "groups"
        : canManageShares
          ? "shares"
          : null;
  const currentTab =
    (activeTab === "policies" && canManagePolicies) ||
    (activeTab === "roles" && canManageRoles) ||
    (activeTab === "groups" && canManageGroups) ||
    (activeTab === "shares" && canManageShares)
      ? activeTab
      : firstTab;

  return (
    <div className="grid gap-8">
      <div className="grid max-w-3xl gap-3">
        <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
          Administração
        </p>
        <h1 className="text-3xl font-semibold tracking-tight">Access</h1>
        <p className="text-muted-foreground">
          Defina o que cada identidade pode acessar nos nodes e como essas
          permissões são reutilizadas.
        </p>
      </div>

      {firstTab ? (
        <Tabs
          value={currentTab}
          onValueChange={(value) => {
            if (typeof value === "string") setActiveTab(value as AccessTab);
          }}
        >
          <TabsList>
            {canManagePolicies && (
              <TabsTrigger value="policies">Policies</TabsTrigger>
            )}
            {canManageRoles && <TabsTrigger value="roles">Roles</TabsTrigger>}
            {canManageGroups && <TabsTrigger value="groups">Grupos</TabsTrigger>}
            {canManageShares && (
              <TabsTrigger value="shares">Links públicos</TabsTrigger>
            )}
          </TabsList>

          {canManagePolicies && (
            <TabsContent value="policies" className="pt-2">
              <PoliciesDialog
                open={currentTab === "policies"}
                inline
                onOpenChange={() => undefined}
              />
            </TabsContent>
          )}
          {canManageRoles && (
            <TabsContent value="roles" className="pt-2">
              <RolesDialog
                open={currentTab === "roles"}
                inline
                onOpenChange={() => undefined}
              />
            </TabsContent>
          )}
          {canManageGroups && (
            <TabsContent value="groups" className="pt-2">
              <AccessGroupsDialog
                open={currentTab === "groups"}
                inline
                onOpenChange={() => undefined}
              />
            </TabsContent>
          )}
          {canManageShares && (
            <TabsContent value="shares" className="pt-2">
              <SharesPanel />
            </TabsContent>
          )}
        </Tabs>
      ) : (
        <Card className="p-6 text-sm text-muted-foreground">
          Você não tem permissão para administrar o acesso.
        </Card>
      )}
    </div>
  );
}
