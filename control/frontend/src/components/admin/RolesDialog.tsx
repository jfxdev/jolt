import { useEffect, useState } from "react";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import type { Policy, Role } from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm } from "@/context/ConfirmProvider";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
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

interface RoleForm {
  name: string;
  description: string;
  policy_ids: string[];
}

const EMPTY: RoleForm = { name: "", description: "", policy_ids: [] };

export function RolesDialog({
  open,
  onOpenChange,
  inline = false,
}: AdminDialogProps) {
  const handleError = useApiError();
  const confirm = useConfirm();
  const [roles, setRoles] = useState<Role[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [editingId, setEditingId] = useState("");
  const [form, setForm] = useState<RoleForm>(EMPTY);
  const [busy, setBusy] = useState(false);
  const [search, setSearch] = useState("");
  const [formOpen, setFormOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    reset();
    setSearch("");
    (async () => {
      try {
        const p = await api.policies();
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
        .roles(search)
        .then((result) => {
          if (!cancelled) setRoles(result.items || []);
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
    setForm(EMPTY);
  }

  function openCreateForm() {
    reset();
    setFormOpen(true);
  }

  function closeForm(open: boolean) {
    setFormOpen(open);
    if (!open) reset();
  }

  async function reloadRoles(query = search) {
    const result = await api.roles(query);
    setRoles(result.items || []);
  }

  function edit(role: Role) {
    setEditingId(role.role_id);
    setForm({
      name: role.name,
      description: role.description,
      policy_ids: [...(role.policy_ids || [])],
    });
    setFormOpen(true);
  }

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      if (editingId) {
        await api.updateRole(editingId, form);
        toast.success("Role atualizada.");
      } else {
        await api.createRole(form);
        toast.success("Role criada.");
      }
      reset();
      setFormOpen(false);
      await reloadRoles();
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  async function remove(role: Role) {
    if (
      !(await confirm({
        title: `Remover a role “${role.name}”?`,
        description: "Os usuários perderão as policies herdadas por ela.",
        confirmText: "Remover",
        destructive: true,
      }))
    )
      return;
    setBusy(true);
    try {
      await api.deleteRole(role.role_id);
      reset();
      setFormOpen(false);
      await reloadRoles();
      toast.success("Role removida.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  if (inline && !open) return null;

  const searchInput = (
    <div className="grid gap-2">
      <Label htmlFor="roles-search">Buscar roles</Label>
      <Input
        id="roles-search"
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
              <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                Autorização
              </p>
              <DialogTitle>Roles</DialogTitle>
            </div>
            <Button variant="secondary" size="sm" onClick={openCreateForm}>
              Nova role
            </Button>
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
                <Table aria-label="Roles cadastradas">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Role</TableHead>
                      <TableHead>Descrição</TableHead>
                      <TableHead>Policies</TableHead>
                      <TableHead className="text-right">Ação</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {roles.map((role) => (
                      <TableRow
                        key={role.role_id}
                        data-state={
                          editingId === role.role_id ? "selected" : undefined
                        }
                      >
                        <TableCell className="font-medium">{role.name}</TableCell>
                        <TableCell className="max-w-sm truncate text-muted-foreground">
                          {role.description || "Sem descrição"}
                        </TableCell>
                        <TableCell>{role.policy_ids?.length || 0}</TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => edit(role)}
                            >
                              Editar
                            </Button>
                            <Button
                              type="button"
                              variant="destructive"
                              size="sm"
                              onClick={() => void remove(role)}
                            >
                              Remover
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                    {!roles.length && (
                      <TableRow>
                        <TableCell colSpan={4} className="text-muted-foreground">
                          {search
                            ? "Nenhuma role encontrada."
                            : "Nenhuma role cadastrada."}
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
              {roles.map((role) => (
                <button
                  key={role.role_id}
                  className={cn(
                    "rounded-md border p-2 text-left text-sm hover:bg-accent",
                    editingId === role.role_id && "bg-accent",
                  )}
                  onClick={() => edit(role)}
                >
                  <strong className="block">{role.name}</strong>
                  <small className="text-muted-foreground">
                    {role.policy_ids?.length || 0} policy(s)
                  </small>
                </button>
              ))}
              {!roles.length && (
                <div className="p-2 text-xs text-muted-foreground">
                  {search ? "Nenhuma role encontrada." : "Nenhuma role cadastrada."}
                </div>
              )}
            </div>
          )}

          <AdminEntityDialog
            open={formOpen}
            onOpenChange={closeForm}
            title={editingId ? "Editar role" : "Criar role"}
          >
              <form className="grid gap-3" onSubmit={save}>
            <EntityDialogFormLayout
              summary={
                <>
            <div className="grid gap-2">
              <Label htmlFor="r-name">Nome</Label>
              <Input
                id="r-name"
                value={form.name}
                minLength={3}
                maxLength={64}
                pattern="[A-Za-z0-9._\-]+"
                required
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="r-desc">Descrição</Label>
              <Textarea
                id="r-desc"
                value={form.description}
                maxLength={512}
                rows={2}
                onChange={(e) =>
                  setForm({ ...form, description: e.target.value })
                }
              />
            </div>
                </>
              }
            >
            <fieldset className="grid gap-2 rounded-md border p-3">
              <legend className="px-1 text-sm font-medium">
                Policies da role
              </legend>
              {policies.map((policy) => (
                <label
                  key={policy.policy_id}
                  className="flex items-center gap-2 text-sm"
                >
                  <Checkbox
                    checked={form.policy_ids.includes(policy.policy_id)}
                    onCheckedChange={(v) =>
                      setForm((prev) => ({
                        ...prev,
                        policy_ids:
                          v === true
                            ? [...prev.policy_ids, policy.policy_id]
                            : prev.policy_ids.filter(
                                (id) => id !== policy.policy_id,
                              ),
                      }))
                    }
                  />
                  <span>
                    <strong>{policy.name}</strong>{" "}
                    <small className="text-muted-foreground">
                      {policy.description || `${policy.rules.length} regra(s)`}
                    </small>
                  </span>
                </label>
              ))}
              {!policies.length && (
                <small className="text-muted-foreground">
                  Crie uma policy antes de configurar a role.
                </small>
              )}
            </fieldset>
            <div className="flex justify-end gap-2">
              <Button type="submit" disabled={busy}>
                Salvar role <ArrowRight />
              </Button>
            </div>
            </EntityDialogFormLayout>
              </form>
          </AdminEntityDialog>
        </div>
      </DialogContent>
    </Dialog>
  );
}
