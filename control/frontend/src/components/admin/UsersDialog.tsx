import { useEffect, useState } from "react";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import type { Policy, Role, User } from "@/lib/types";
import { useAuth } from "@/context/AuthContext";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm } from "@/context/ConfirmProvider";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { AdminEntityDialog } from "./AdminEntityDialog";

interface UserForm {
  username: string;
  password: string;
  role: string;
  enabled: boolean;
}

const EMPTY: UserForm = {
  username: "",
  password: "",
  role: "operator",
  enabled: true,
};

export function UsersDialog({
  open,
  onOpenChange,
  inline = false,
}: AdminDialogProps) {
  const { user, clearUser } = useAuth();
  const handleError = useApiError();
  const confirm = useConfirm();

  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [editingId, setEditingId] = useState("");
  const [form, setForm] = useState<UserForm>(EMPTY);
  const [roleIds, setRoleIds] = useState<string[]>([]);
  const [policyIds, setPolicyIds] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [search, setSearch] = useState("");
  const [formOpen, setFormOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    reset();
    setSearch("");
    (async () => {
      try {
        const [r, p] = await Promise.all([api.roles(), api.policies()]);
        setRoles(r.items || []);
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
        .users(search)
        .then((result) => {
          if (!cancelled) setUsers(result.items || []);
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

  async function reloadUsers(query = search) {
    const result = await api.users(query);
    setUsers(result.items || []);
  }

  function reset() {
    setEditingId("");
    setForm(EMPTY);
    setRoleIds([]);
    setPolicyIds([]);
  }

  function openCreateForm() {
    reset();
    setFormOpen(true);
  }

  function closeForm(open: boolean) {
    setFormOpen(open);
    if (!open) reset();
  }

  async function edit(target: User) {
    setEditingId(target.user_id);
    setForm({
      username: target.username,
      password: "",
      role: target.role,
      enabled: target.enabled,
    });
    setFormOpen(true);
    try {
      const [r, p] = await Promise.all([
        api.userRoles(target.user_id),
        api.userPolicies(target.user_id),
      ]);
      setRoleIds(r.role_ids || []);
      setPolicyIds(p.policy_ids || []);
    } catch (error) {
      handleError(error);
    }
  }

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      if (editingId) {
        const payload: Partial<User> & { password?: string } = {
          username: form.username,
          role: form.role,
          enabled: form.enabled,
        };
        if (form.password) payload.password = form.password;
        const changedOwnPassword =
          editingId === user?.user_id && Boolean(form.password);
        await api.updateUser(editingId, payload);
        await Promise.all([
          api.setUserRoles(editingId, roleIds),
          api.setUserPolicies(editingId, policyIds),
        ]);
        if (changedOwnPassword) {
          onOpenChange(false);
          clearUser();
          return;
        }
        toast.success(
          "Usuário atualizado; sessões incompatíveis foram revogadas.",
        );
      } else {
        const created = await api.createUser(form);
        if (roleIds.length) await api.setUserRoles(created.user_id, roleIds);
        toast.success("Usuário criado.");
      }
      reset();
      setFormOpen(false);
      await reloadUsers();
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  async function remove(target: User) {
    if (
      !(await confirm({
        title: `Remover o usuário “${target.username}”?`,
        description: "O histórico de auditoria será preservado.",
        confirmText: "Remover",
        destructive: true,
      }))
    )
      return;
    setBusy(true);
    try {
      await api.deleteUser(target.user_id);
      if (editingId === target.user_id) reset();
      setFormOpen(false);
      await reloadUsers();
      toast.success("Usuário removido; a auditoria foi preservada.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  if (inline && !open) return null;

  const searchInput = (
    <div className="grid gap-2">
      <Label htmlFor="users-search">Buscar usuários</Label>
      <Input
        id="users-search"
        type="search"
        value={search}
        placeholder="Nome ou nível administrativo"
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
                Administração
              </p>
              <DialogTitle>Usuários</DialogTitle>
            </div>
            <Button variant="secondary" size="sm" onClick={openCreateForm}>
              Novo usuário
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
                <Table aria-label="Usuários cadastrados">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Usuário</TableHead>
                      <TableHead>Nível administrativo</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Ação</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {users.map((target) => (
                      <TableRow
                        key={target.user_id}
                        data-state={
                          editingId === target.user_id ? "selected" : undefined
                        }
                      >
                        <TableCell className="font-medium">
                          {target.username}
                        </TableCell>
                        <TableCell>
                          {target.role === "admin" ? "Administrador" : "Operador"}
                        </TableCell>
                        <TableCell>
                          <span
                            className={
                              target.enabled ? "text-emerald-500" : "text-destructive"
                            }
                          >
                            {target.enabled ? "Ativo" : "Inativo"}
                          </span>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => edit(target)}
                            >
                              Editar
                            </Button>
                            {target.user_id !== user?.user_id && (
                              <Button
                                type="button"
                                variant="destructive"
                                size="sm"
                                onClick={() => void remove(target)}
                              >
                                Remover
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                    {!users.length && (
                      <TableRow>
                        <TableCell colSpan={4} className="text-muted-foreground">
                          {search
                            ? "Nenhum usuário encontrado."
                            : "Nenhum usuário cadastrado."}
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
              {users.map((target) => (
                <button
                  key={target.user_id}
                  className={cn(
                    "flex items-center justify-between rounded-md border p-2 text-left text-sm hover:bg-accent",
                    editingId === target.user_id && "bg-accent",
                  )}
                  onClick={() => edit(target)}
                >
                  <span>
                    <strong className="block">{target.username}</strong>
                    <small className="text-muted-foreground">
                      {target.role === "admin" ? "Administrador" : "Operador"}
                    </small>
                  </span>
                  <small
                    className={
                      target.enabled ? "text-emerald-500" : "text-destructive"
                    }
                  >
                    {target.enabled ? "Ativo" : "Inativo"}
                  </small>
                </button>
              ))}
              {!users.length && (
                <div className="p-2 text-xs text-muted-foreground">
                  {search ? "Nenhum usuário encontrado." : "Nenhum usuário cadastrado."}
                </div>
              )}
            </div>
          )}

          <AdminEntityDialog
            open={formOpen}
            onOpenChange={closeForm}
            title={editingId ? "Editar usuário" : "Criar usuário"}
          >
              <form className="grid gap-3" onSubmit={save}>
            <div className="grid gap-2">
              <Label htmlFor="u-name">Nome de usuário</Label>
              <Input
                id="u-name"
                value={form.username}
                minLength={3}
                maxLength={64}
                pattern="[A-Za-z0-9._\-]+"
                autoComplete="off"
                required
                onChange={(e) => setForm({ ...form, username: e.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="u-pass">
                {editingId
                  ? "Nova senha — deixe vazio para manter"
                  : "Senha"}
              </Label>
              <Input
                id="u-pass"
                type="password"
                value={form.password}
                minLength={12}
                required={!editingId}
                autoComplete="new-password"
                onChange={(e) => setForm({ ...form, password: e.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label>Nível administrativo</Label>
              <Select
                value={form.role}
                onValueChange={(v) => setForm({ ...form, role: v })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="operator">Operador</SelectItem>
                  <SelectItem value="admin">Administrador</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <fieldset className="grid gap-2 rounded-md border p-3">
              <legend className="px-1 text-sm font-medium">
                Roles atribuídas
              </legend>
              {roles.map((role) => (
                <label
                  key={role.role_id}
                  className="flex items-center gap-2 text-sm"
                >
                  <Checkbox
                    checked={roleIds.includes(role.role_id)}
                    onCheckedChange={(v) =>
                      setRoleIds((prev) =>
                        v === true
                          ? [...prev, role.role_id]
                          : prev.filter((id) => id !== role.role_id),
                      )
                    }
                  />
                  <span>
                    <strong>{role.name}</strong>{" "}
                    <small className="text-muted-foreground">
                      {role.description ||
                        `${role.policy_ids?.length || 0} policy(s)`}
                    </small>
                  </span>
                </label>
              ))}
              {form.role === "admin" && (
                <small className="text-muted-foreground">
                  Administradores também possuem acesso total implícito.
                </small>
              )}
              {!roles.length && (
                <small className="text-muted-foreground">
                  Nenhuma role cadastrada.
                </small>
              )}
            </fieldset>

            {editingId && (
              <fieldset className="grid gap-2 rounded-md border p-3">
                <legend className="px-1 text-sm font-medium">
                  Policies diretas — avançado
                </legend>
                {policies.map((policy) => (
                  <label
                    key={policy.policy_id}
                    className="flex items-center gap-2 text-sm"
                  >
                    <Checkbox
                      checked={policyIds.includes(policy.policy_id)}
                      onCheckedChange={(v) =>
                        setPolicyIds((prev) =>
                          v === true
                            ? [...prev, policy.policy_id]
                            : prev.filter((id) => id !== policy.policy_id),
                        )
                      }
                    />
                    <span>
                      <strong>{policy.name}</strong>{" "}
                      <small className="text-muted-foreground">
                        {policy.description || "Sem descrição"}
                      </small>
                    </span>
                  </label>
                ))}
                {!policies.length && (
                  <small className="text-muted-foreground">
                    Nenhuma policy cadastrada.
                  </small>
                )}
              </fieldset>
            )}

            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={form.enabled}
                disabled={editingId === user?.user_id}
                onCheckedChange={(v) =>
                  setForm({ ...form, enabled: v === true })
                }
              />
              Usuário ativo
            </label>

            <div className="flex justify-end gap-2">
              <Button type="submit" disabled={busy}>
                {editingId ? "Salvar alterações" : "Criar usuário"}{" "}
                <ArrowRight />
              </Button>
            </div>
              </form>
          </AdminEntityDialog>
        </div>
      </DialogContent>
    </Dialog>
  );
}
