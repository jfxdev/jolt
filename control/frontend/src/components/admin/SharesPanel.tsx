import { useCallback, useEffect, useState } from "react";
import { Ban, Link2, RefreshCw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { Share } from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm } from "@/context/ConfirmProvider";
import { formatDate } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

/** shareState describes a link in one word, which is what an operator scans
 * for when auditing what is currently exposed. */
function shareState(share: Share): { label: string; tone: "active" | "ended" } {
  if (share.revoked_at) return { label: "Revogado", tone: "ended" };
  if (share.expires_at && new Date(share.expires_at) < new Date()) {
    return { label: "Expirado", tone: "ended" };
  }
  if (share.max_downloads > 0 && share.download_count >= share.max_downloads) {
    return { label: "Esgotado", tone: "ended" };
  }
  return { label: "Ativo", tone: "active" };
}

export function SharesPanel() {
  const handleError = useApiError();
  const confirm = useConfirm();
  const [shares, setShares] = useState<Share[]>([]);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.shares();
      setShares(response.shares || []);
    } catch (error) {
      handleError(error);
    } finally {
      setLoading(false);
    }
  }, [handleError]);

  useEffect(() => {
    void load();
  }, [load]);

  async function revoke(share: Share) {
    if (
      !(await confirm({
        title: `Revogar o link de “${share.name}”?`,
        description:
          "O link para de funcionar imediatamente para todos que o tenham.",
        confirmText: "Revogar",
        destructive: true,
      }))
    )
      return;
    try {
      await api.revokeShare(share.share_id);
      toast.success("Link revogado.");
      await load();
    } catch (error) {
      handleError(error);
    }
  }

  async function remove(share: Share) {
    if (
      !(await confirm({
        title: `Excluir o registro do link de “${share.name}”?`,
        description:
          "O histórico de auditoria do link é mantido, mas o registro sai desta lista.",
        confirmText: "Excluir",
        destructive: true,
      }))
    )
      return;
    try {
      await api.deleteShare(share.share_id);
      toast.success("Registro removido.");
      await load();
    } catch (error) {
      handleError(error);
    }
  }

  return (
    <div className="grid gap-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-medium">
            <Link2 className="size-4" /> Links públicos
          </h3>
          <p className="text-sm text-muted-foreground">
            Links somente de leitura. Revogar encerra o acesso na hora; o link
            também deixa de funcionar se quem o criou perder acesso ao caminho.
          </p>
        </div>
        <Button variant="secondary" size="sm" onClick={load} disabled={loading}>
          <RefreshCw /> Atualizar
        </Button>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Item</TableHead>
            <TableHead>Estado</TableHead>
            <TableHead>Downloads</TableHead>
            <TableHead>Expira</TableHead>
            <TableHead>Último acesso</TableHead>
            <TableHead className="w-28" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {shares.map((share) => {
            const state = shareState(share);
            return (
              <TableRow key={share.share_id}>
                <TableCell>
                  <div className="grid">
                    <span className="truncate font-medium">{share.name}</span>
                    <span className="truncate text-xs text-muted-foreground">
                      {share.kind === "directory" ? "Pasta" : "Arquivo"}
                      {share.has_password && " · protegido por senha"}
                    </span>
                  </div>
                </TableCell>
                <TableCell>
                  <Badge variant={state.tone === "active" ? "default" : "secondary"}>
                    {state.label}
                  </Badge>
                </TableCell>
                <TableCell>
                  {share.download_count}
                  {share.max_downloads > 0 && ` / ${share.max_downloads}`}
                </TableCell>
                <TableCell>
                  {share.expires_at ? formatDate(share.expires_at) : "Sem expiração"}
                </TableCell>
                <TableCell>
                  {share.last_access_at ? formatDate(share.last_access_at) : "—"}
                </TableCell>
                <TableCell className="flex gap-1">
                  {!share.revoked_at && (
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-label={`Revogar o link de ${share.name}`}
                      onClick={() => revoke(share)}
                    >
                      <Ban className="size-4" />
                    </Button>
                  )}
                  <Button
                    size="sm"
                    variant="ghost"
                    aria-label={`Excluir o registro do link de ${share.name}`}
                    onClick={() => remove(share)}
                  >
                    <Trash2 className="size-4" />
                  </Button>
                </TableCell>
              </TableRow>
            );
          })}
          {shares.length === 0 && !loading && (
            <TableRow>
              <TableCell colSpan={6} className="text-muted-foreground">
                Nenhum link público criado.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  );
}
