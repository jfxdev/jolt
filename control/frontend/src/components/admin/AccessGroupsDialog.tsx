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
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { AdminDialogProps } from "./types";

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

export function AccessGroupsDialog({ open, onOpenChange }: AdminDialogProps) {
  const handleError = useApiError();
  const confirm = useConfirm();
  const [groups, setGroups] = useState<AccessGroup[]>([]);
  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [editingId, setEditingId] = useState("");
  const [form, setForm] = useState<GroupForm>(EMPTY);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    reset();
    (async () => {
      try {
        const [g, n, p] = await Promise.all([
          api.accessGroups(),
          api.nodes(),
          api.policies(),
        ]);
        setGroups(g.items || []);
        setNodes(n.items || []);
        setPolicies(p.items || []);
      } catch (error) {
        handleError(error);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  function reset() {
    setEditingId("");
    setForm({ ...EMPTY, node_ids: [], policy_ids: [] });
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
  }

  function toggle(field: "node_ids" | "policy_ids", id: string, checked: boolean) {
    setForm((current) => ({
      ...current,
      [field]: checked
        ? [...current[field], id]
        : current[field].filter((value) => value !== id),
    }));
  }

  async function reload() {
    const result = await api.accessGroups();
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
      await reload();
      toast.success("Grupo removido.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Acesso de API</p>
              <DialogTitle>Grupos de acesso</DialogTitle>
            </div>
            <Button variant="secondary" size="sm" onClick={reset}>Novo grupo</Button>
          </div>
        </DialogHeader>
        <div className="grid gap-4 md:grid-cols-[220px_1fr]">
          <div className="grid max-h-[60vh] gap-1 overflow-y-auto">
            {groups.map((group) => (
              <button key={group.group_id} className={cn("flex items-center justify-between rounded-md border p-2 text-left text-sm hover:bg-accent", editingId === group.group_id && "bg-accent")} onClick={() => edit(group)}>
                <span><strong className="block">{group.name}</strong><small className="text-muted-foreground">{group.node_ids?.length || 0} node(s) · {group.policy_ids?.length || 0} policy(s)</small></span>
                <small className={group.enabled ? "text-emerald-500" : "text-destructive"}>{group.enabled ? "Ativo" : "Inativo"}</small>
              </button>
            ))}
            {!groups.length && <div className="p-2 text-xs text-muted-foreground">Nenhum grupo cadastrado.</div>}
          </div>
          <form className="grid gap-3" onSubmit={save}>
            <h3 className="font-semibold">{editingId ? "Editar grupo" : "Criar grupo"}</h3>
            <div className="grid gap-2"><Label htmlFor="ag-name">Nome</Label><Input id="ag-name" value={form.name} minLength={3} maxLength={64} pattern="[A-Za-z0-9._-]+" required onChange={(event) => setForm({ ...form, name: event.target.value })} /></div>
            <div className="grid gap-2"><Label htmlFor="ag-desc">Descrição</Label><Textarea id="ag-desc" value={form.description} maxLength={512} rows={2} onChange={(event) => setForm({ ...form, description: event.target.value })} /></div>
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
              {editingId && <Button type="button" variant="destructive" onClick={() => { const group = groups.find((item) => item.group_id === editingId); if (group) void remove(group); }}>Remover</Button>}
              <Button type="submit" disabled={busy}>{editingId ? "Salvar alterações" : "Criar grupo"} <ArrowRight /></Button>
            </div>
          </form>
        </div>
      </DialogContent>
    </Dialog>
  );
}
