import { useEffect, useState } from "react";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import type { AccessGroup, NodeInfo, Policy } from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm } from "@/context/ConfirmProvider";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { AdminDialogProps } from "./types";
import {
  AdminEntityDialog,
  EntityDialogFormLayout,
} from "./AdminEntityDialog";

interface GroupForm {
  name: string;
  description: string;
  enabled: boolean;
  node_ids: string[];
  policy_ids: string[];
}

const EMPTY: GroupForm = {
  name: "",
  description: "",
  enabled: true,
  node_ids: [],
  policy_ids: [],
};

export function AccessGroupsDialog({
  open,
  onOpenChange,
  inline = false,
}: AdminDialogProps) {
  const handleError = useApiError();
  const confirm = useConfirm();
  const [groups, setGroups] = useState<AccessGroup[]>([]);
  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [editingId, setEditingId] = useState("");
  const [form, setForm] = useState<GroupForm>(EMPTY);
  const [busy, setBusy] = useState(false);
  const [search, setSearch] = useState("");
  const [formOpen, setFormOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    reset();
    setSearch("");
    (async () => {
      try {
        const [n, p] = await Promise.all([api.nodes(), api.policies()]);
        setNodes(n.items || []);
        setPolicies(p.items || []);
      } catch (error) {
        handleError(error);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    const timeout = window.setTimeout(() => {
      void api
        .accessGroups(search)
        .then((result) => {
          if (!cancelled) setGroups(result.items || []);
        })
        .catch((error) => {
          if (!cancelled) handleError(error);
        });
    }, search ? 250 : 0);
    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [handleError, open, search]);

  function reset() {
    setEditingId("");
    setForm({ ...EMPTY, node_ids: [], policy_ids: [] });
  }

  function openCreateForm() {
    reset();
    setFormOpen(true);
  }

  function closeForm(open: boolean) {
    setFormOpen(open);
    if (!open) reset();
  }

  function edit(group: AccessGroup) {
    setEditingId(group.group_id);
    setForm({
      name: group.name,
      description: group.description,
      enabled: group.enabled,
      node_ids: [...(group.node_ids || [])],
      policy_ids: [...(group.policy_ids || [])],
    });
    setFormOpen(true);
  }

  function toggle(field: "node_ids" | "policy_ids", id: string, checked: boolean) {
    setForm((current) => ({
      ...current,
      [field]: checked
        ? [...current[field], id]
        : current[field].filter((value) => value !== id),
    }));
  }

  async function reload(query = search) {
    const result = await api.accessGroups(query);
    setGroups(result.items || []);
  }

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      let id = editingId;
      const payload = {
        name: form.name,
        description: form.description,
        enabled: form.enabled,
      };
      if (id) {
        await api.updateAccessGroup(id, payload);
      } else {
        const group = await api.createAccessGroup(payload);
        id = group.group_id;
      }
      await Promise.all([
        api.setAccessGroupNodes(id, form.node_ids),
        api.setAccessGroupPolicies(id, form.policy_ids),
      ]);
      toast.success(editingId ? "Grupo atualizado." : "Grupo criado.");
      reset();
      setFormOpen(false);
      await reload();
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  async function remove(group: AccessGroup) {
    if (
      !(await confirm({
        title: `Remover o grupo “${group.name}”?`,
        description: "As API keys deixam de pertencer ao grupo e perdem suas policies herdadas.",
        confirmText: "Remover",
        destructive: true,
      }))
    ) return;
    setBusy(true);
    try {
      await api.deleteAccessGroup(group.group_id);
      reset();
      setFormOpen(false);
      await reload();
      toast.success("Grupo removido.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  if (inline && !open) return null;

  const searchInput = (
    <div className="grid gap-2">
      <Label htmlFor="groups-search">Buscar grupos</Label>
      <Input
        id="groups-search"
        type="search"
        value={search}
        placeholder="Nome ou descrição"
        onChange={(event) => setSearch(event.target.value)}
      />
    </div>
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        inline={inline}
        showCloseButton={!inline}
        className={
          inline ? "w-full max-w-none" : "sm:w-[calc(100vw-4rem)] sm:max-w-5xl"
        }
      >
        <DialogHeader>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Acesso de API</p>
              <DialogTitle>Grupos de acesso</DialogTitle>
            </div>
            <Button variant="secondary" size="sm" onClick={openCreateForm}>Novo grupo</Button>
          </div>
        </DialogHeader>
        <div
          className={cn(
            "grid gap-4",
            inline ? "" : "md:grid-cols-[220px_1fr]",
          )}
        >
          {inline ? (
            <div className="order-2 grid gap-2">
              {searchInput}
              <div className="overflow-hidden rounded-md border">
                <Table aria-label="Grupos de acesso cadastrados">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Grupo</TableHead>
                      <TableHead>Descrição</TableHead>
                      <TableHead>Nodes</TableHead>
                      <TableHead>Policies</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Ação</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {groups.map((group) => (
                      <TableRow
                        key={group.group_id}
                        data-state={
                          editingId === group.group_id ? "selected" : undefined
                        }
                      >
                        <TableCell className="font-medium">{group.name}</TableCell>
                        <TableCell className="max-w-sm truncate text-muted-foreground">
                          {group.description || "Sem descrição"}
                        </TableCell>
                        <TableCell>{group.node_ids?.length || 0}</TableCell>
                        <TableCell>{group.policy_ids?.length || 0}</TableCell>
                        <TableCell>
                          <span
                            className={
                              group.enabled ? "text-emerald-500" : "text-destructive"
                            }
                          >
                            {group.enabled ? "Ativo" : "Inativo"}
                          </span>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => edit(group)}
                            >
                              Editar
                            </Button>
                            <Button
                              type="button"
                              variant="destructive"
                              size="sm"
                              onClick={() => void remove(group)}
                            >
                              Remover
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                    {!groups.length && (
                      <TableRow>
                        <TableCell colSpan={6} className="text-muted-foreground">
                          {search
                            ? "Nenhum grupo encontrado."
                            : "Nenhum grupo cadastrado."}
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </div>
          ) : (
            <div className="grid max-h-[60vh] gap-1 overflow-y-auto">
              {searchInput}
              {groups.map((group) => (
                <button key={group.group_id} className={cn("flex items-center justify-between rounded-md border p-2 text-left text-sm hover:bg-accent", editingId === group.group_id && "bg-accent")} onClick={() => edit(group)}>
                  <span><strong className="block">{group.name}</strong><small className="text-muted-foreground">{group.node_ids?.length || 0} node(s) · {group.policy_ids?.length || 0} policy(s)</small></span>
                  <small className={group.enabled ? "text-emerald-500" : "text-destructive"}>{group.enabled ? "Ativo" : "Inativo"}</small>
                </button>
              ))}
              {!groups.length && <div className="p-2 text-xs text-muted-foreground">{search ? "Nenhum grupo encontrado." : "Nenhum grupo cadastrado."}</div>}
            </div>
          )}
          <AdminEntityDialog
            open={formOpen}
            onOpenChange={closeForm}
            title={editingId ? "Editar grupo" : "Criar grupo"}
          >
              <form className="grid gap-3" onSubmit={save}>
            <EntityDialogFormLayout
              summary={
                <>
                  <div className="grid gap-2"><Label htmlFor="ag-name">Nome</Label><Input id="ag-name" value={form.name} minLength={3} maxLength={64} pattern="[A-Za-z0-9._\-]+" required onChange={(event) => setForm({ ...form, name: event.target.value })} /></div>
                  <div className="grid gap-2"><Label htmlFor="ag-desc">Descrição</Label><Textarea id="ag-desc" value={form.description} maxLength={512} rows={2} onChange={(event) => setForm({ ...form, description: event.target.value })} /></div>
                </>
              }
            >
            <label className="flex items-center gap-2 text-sm"><Checkbox checked={form.enabled} onCheckedChange={(value) => setForm({ ...form, enabled: value === true })} />Grupo ativo</label>
            <fieldset className="grid gap-2 rounded-md border p-3"><legend className="px-1 text-sm font-medium">Nodes autorizados</legend>
              {nodes.map((node) => <label key={node.node_id} className="flex items-center gap-2 text-sm"><Checkbox checked={form.node_ids.includes(node.node_id)} onCheckedChange={(value) => toggle("node_ids", node.node_id, value === true)} /><span><strong>{node.name}</strong> <small className="text-muted-foreground">{node.node_id}</small></span></label>)}
              {!nodes.length && <small className="text-muted-foreground">Cadastre nodes antes de montar o grupo.</small>}
            </fieldset>
            <fieldset className="grid gap-2 rounded-md border p-3"><legend className="px-1 text-sm font-medium">Policies compartilhadas</legend>
              {policies.map((policy) => <label key={policy.policy_id} className="flex items-center gap-2 text-sm"><Checkbox checked={form.policy_ids.includes(policy.policy_id)} onCheckedChange={(value) => toggle("policy_ids", policy.policy_id, value === true)} /><span><strong>{policy.name}</strong> <small className="text-muted-foreground">{policy.description || `${policy.rules.length} regra(s)`}</small></span></label>)}
              {!policies.length && <small className="text-muted-foreground">Crie policies para permitir arquivos, jobs ou transferências.</small>}
            </fieldset>
            <div className="flex justify-end gap-2">
              <Button type="submit" disabled={busy}>{editingId ? "Salvar alterações" : "Criar grupo"} <ArrowRight /></Button>
            </div>
            </EntityDialogFormLayout>
              </form>
          </AdminEntityDialog>
        </div>
      </DialogContent>
    </Dialog>
  );
}
