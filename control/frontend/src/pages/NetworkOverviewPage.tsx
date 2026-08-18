import { useState } from "react";
import { Plus } from "lucide-react";
import { useNodes } from "@/context/NodesContext";
import { usePermissions } from "@/context/PermissionsContext";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { AddNodeDialog } from "@/components/node/AddNodeDialog";

export default function NetworkOverviewPage() {
  const { nodes } = useNodes();
  const { hasPermission } = usePermissions();
  const [addOpen, setAddOpen] = useState(false);

  const online = nodes.filter((n) => n.state === "online").length;
  const canAdd = hasPermission("control-tower/nodes", "sudo");

  const heading = nodes.length
    ? "Escolha um node para começar."
    : canAdd
      ? "Conecte seu primeiro node."
      : "Nenhum node autorizado.";

  return (
    <div className="grid gap-8">
      <Card className="flex min-h-[46vh] flex-col items-start justify-center gap-5 p-10 lg:p-16">
        <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
          Visão da rede
        </p>
        <h1 className="max-w-2xl text-4xl font-semibold tracking-tight lg:text-6xl">
          {heading}
        </h1>
        <p className="max-w-xl text-muted-foreground">
          A Control Tower coordena operações pelas APIs dos nodes. Seus arquivos
          continuam onde pertencem.
        </p>
        {canAdd && (
          <Button onClick={() => setAddOpen(true)}>
            {nodes.length ? "Adicionar outro node" : "Conectar node"} <Plus />
          </Button>
        )}
      </Card>

      <div className="grid gap-4 sm:grid-cols-3">
        <Metric label="Nodes conhecidos" value={nodes.length} />
        <Metric label="Disponíveis agora" value={online} />
        <Metric label="Operações ativas" value={0} />
      </div>

      <AddNodeDialog open={addOpen} onOpenChange={setAddOpen} />
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <Card className="grid gap-2 p-6">
      <span className="text-sm text-muted-foreground">{label}</span>
      <strong className="text-3xl font-semibold">{value}</strong>
    </Card>
  );
}
