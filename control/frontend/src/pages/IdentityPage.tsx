import { useState } from "react";
import { usePermissions } from "@/context/PermissionsContext";
import { ServiceAccountsDialog } from "@/components/admin/ServiceAccountsDialog";
import { UsersDialog } from "@/components/admin/UsersDialog";
import { Card } from "@/components/ui/card";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";

type IdentityTab = "users" | "api-keys";

export default function IdentityPage() {
  const { hasPermission } = usePermissions();
  const [activeTab, setActiveTab] = useState<IdentityTab | null>(null);
  const canManageUsers = hasPermission("control-tower/users", "sudo");
  const canManageServiceAccounts = hasPermission(
    "control-tower/service-accounts",
    "sudo",
  );
  const firstTab = canManageUsers
    ? "users"
    : canManageServiceAccounts
      ? "api-keys"
      : null;
  const currentTab =
    (activeTab === "users" && canManageUsers) ||
    (activeTab === "api-keys" && canManageServiceAccounts)
      ? activeTab
      : firstTab;

  return (
    <div className="grid gap-8">
      <div className="grid max-w-3xl gap-3">
        <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
          Administração
        </p>
        <h1 className="text-3xl font-semibold tracking-tight">Identity</h1>
        <p className="text-muted-foreground">
          Gerencie identidades humanas e credenciais usadas por integrações.
        </p>
      </div>

      {firstTab ? (
        <Tabs
          value={currentTab}
          onValueChange={(value) => {
            if (typeof value === "string") setActiveTab(value as IdentityTab);
          }}
        >
          <TabsList>
            {canManageUsers && <TabsTrigger value="users">Usuários</TabsTrigger>}
            {canManageServiceAccounts && (
              <TabsTrigger value="api-keys">API Keys</TabsTrigger>
            )}
          </TabsList>

          {canManageUsers && (
            <TabsContent value="users" className="pt-2">
              <UsersDialog
                open={currentTab === "users"}
                inline
                onOpenChange={() => undefined}
              />
            </TabsContent>
          )}
          {canManageServiceAccounts && (
            <TabsContent value="api-keys" className="pt-2">
              <ServiceAccountsDialog
                open={currentTab === "api-keys"}
                inline
                onOpenChange={() => undefined}
              />
            </TabsContent>
          )}
        </Tabs>
      ) : (
        <Card className="p-6 text-sm text-muted-foreground">
          Você não tem permissão para administrar identidades.
        </Card>
      )}
    </div>
  );
}
