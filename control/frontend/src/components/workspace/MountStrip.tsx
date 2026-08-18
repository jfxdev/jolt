import { useNavigate, useParams } from "react-router-dom";
import { FolderOpen, HardDrive, LockKeyhole, PencilLine } from "lucide-react";
import { useWorkspace } from "@/context/WorkspaceContext";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";

export function MountStrip() {
  const { nodeId, mounts } = useWorkspace();
  const { mountId } = useParams();
  const navigate = useNavigate();

  return (
    <section className="grid gap-4">
      <div>
        <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
          Volumes
        </p>
        <h2 className="text-lg font-semibold">Arquivos deste node</h2>
        <p className="text-sm text-muted-foreground">
          Selecione um volume para abrir seu explorador de arquivos.
        </p>
      </div>

      {mounts.length ? (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {mounts.map((mount) => (
            <Card
              key={mount.mount_id}
              className={cn(
                "group cursor-pointer p-0 transition-colors hover:border-primary hover:bg-accent/40",
                mountId === mount.mount_id && "border-primary bg-accent",
              )}
            >
              <button
                className="grid w-full gap-4 p-5 text-left"
                onClick={() =>
                  navigate(`/nodes/${nodeId}/mounts/${mount.mount_id}`)
                }
              >
                <div className="flex items-start justify-between gap-3">
                  <span className="grid h-10 w-10 place-content-center rounded-lg bg-muted text-muted-foreground group-hover:bg-primary group-hover:text-primary-foreground">
                    <HardDrive className="h-5 w-5" />
                  </span>
                  <Badge variant={mount.enabled === false ? "destructive" : "secondary"}>
                    {mount.enabled === false ? "indisponível" : "ativo"}
                  </Badge>
                </div>
                <div className="min-w-0">
                  <strong className="block truncate">{mount.name}</strong>
                  <span className="mt-1 block truncate font-mono text-xs text-muted-foreground">
                    {mount.local_path || mount.mount_id}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1">
                    {mount.mode === "read_write" ? <PencilLine className="h-3.5 w-3.5" /> : <LockKeyhole className="h-3.5 w-3.5" />}
                    {mount.mode === "read_write" ? "Leitura e escrita" : "Somente leitura"}
                  </span>
                  <span className="flex items-center gap-1 font-medium text-foreground">
                    Abrir <FolderOpen className="h-3.5 w-3.5" />
                  </span>
                </div>
              </button>
            </Card>
          ))}
        </div>
      ) : (
        <Card className="flex items-center gap-3 p-5 text-sm text-muted-foreground">
          <HardDrive className="h-5 w-5" />
          Nenhum volume publicado neste node.
        </Card>
      )}
    </section>
  );
}
