import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { AuditEvent } from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { AdminDialogProps } from "./types";

interface Filters {
  actor_type: string;
  result: string;
  action: string;
  correlation_id: string;
}

const EMPTY: Filters = {
  actor_type: "",
  result: "",
  action: "",
  correlation_id: "",
};

function policyLabel(event: AuditEvent) {
  return event.policy_ids?.length
    ? event.policy_ids.join(", ")
    : "sem policy aplicada";
}

export function AuditDialog({ open, onOpenChange }: AdminDialogProps) {
  const handleError = useApiError();
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [nextBeforeId, setNextBeforeId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async (append: boolean) => {
    setBusy(true);
    try {
      const result = await api.auditEvents({
        ...filters,
        limit: 100,
        before_id: append ? nextBeforeId : null,
      });
      setEvents((prev) =>
        append ? [...prev, ...(result.events || [])] : result.events || [],
      );
      setHasMore(Boolean(result.has_more));
      setNextBeforeId(result.next_before_id || null);
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (!open) return;
    setFilters(EMPTY);
    setEvents([]);
    setNextBeforeId(null);
    void load(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                Rastreabilidade
              </p>
              <DialogTitle>Auditoria</DialogTitle>
            </div>
            <Button
              variant="secondary"
              size="sm"
              disabled={busy}
              onClick={() => load(false)}
            >
              Atualizar
            </Button>
          </div>
        </DialogHeader>

        <form
          className="grid grid-cols-2 gap-3 md:grid-cols-4"
          onSubmit={(e) => {
            e.preventDefault();
            load(false);
          }}
        >
          <div className="grid gap-1">
            <Label className="text-xs">Ator</Label>
            <Select
              value={filters.actor_type || "all"}
              onValueChange={(v) =>
                setFilters({ ...filters, actor_type: v === "all" ? "" : v })
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Todos</SelectItem>
                <SelectItem value="user">Usuário</SelectItem>
                <SelectItem value="service_account">Conta de serviço</SelectItem>
                <SelectItem value="recovery">Recuperação offline</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1">
            <Label className="text-xs">Resultado</Label>
            <Select
              value={filters.result || "all"}
              onValueChange={(v) =>
                setFilters({ ...filters, result: v === "all" ? "" : v })
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Todos</SelectItem>
                <SelectItem value="allowed">Permitido</SelectItem>
                <SelectItem value="denied">Negado</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1">
            <Label className="text-xs">Ação</Label>
            <Input
              value={filters.action}
              placeholder="authorize"
              onChange={(e) =>
                setFilters({ ...filters, action: e.target.value.trim() })
              }
            />
          </div>
          <div className="grid gap-1">
            <Label className="text-xs">Correlação</Label>
            <Input
              value={filters.correlation_id}
              placeholder="cor_…"
              onChange={(e) =>
                setFilters({
                  ...filters,
                  correlation_id: e.target.value.trim(),
                })
              }
            />
          </div>
          <Button type="submit" size="sm" className="col-span-2 md:col-span-4">
            Filtrar
          </Button>
        </form>

        <div className="grid max-h-[50vh] gap-2 overflow-y-auto">
          {events.map((event) => (
            <article
              key={event.event_id}
              className="grid gap-1 rounded-md border p-3"
            >
              <header className="flex items-center gap-2">
                <Badge
                  variant={
                    event.result === "allowed" ? "success" : "destructive"
                  }
                >
                  {event.result === "allowed" ? "permitido" : "negado"}
                </Badge>
                <strong className="text-sm">{event.action}</strong>
                <time className="ml-auto text-xs text-muted-foreground">
                  {formatDate(event.created_at)}
                </time>
              </header>
              <code className="break-all text-xs text-muted-foreground">
                {event.evaluated_path || event.resource}
              </code>
              <p className="text-sm text-muted-foreground">
                {event.actor_type} · {event.actor_id || "anônimo"}
                {event.capability ? (
                  <>
                    {" "}
                    · capability <strong>{event.capability}</strong>
                  </>
                ) : null}
              </p>
              <small className="text-muted-foreground">
                Policies: {policyLabel(event)} · Correlação:{" "}
                {event.correlation_id}
              </small>
            </article>
          ))}
          {!events.length && (
            <div
              className={cn(
                "py-6 text-center text-sm text-muted-foreground",
              )}
            >
              Nenhum evento corresponde aos filtros.
            </div>
          )}
        </div>

        {hasMore && (
          <Button
            variant="secondary"
            size="sm"
            disabled={busy}
            onClick={() => load(true)}
          >
            Carregar eventos anteriores
          </Button>
        )}
      </DialogContent>
    </Dialog>
  );
}
