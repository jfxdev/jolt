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

export function UsersDialog({ open, onOpenChange }: AdminDialogProps) {
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

  useEffect(() => {
    if (!open) return;
    reset();
    (async () => {
      try {
        const [u, r, p] = await Promise.all([
          api.users(),
          api.roles(),
          api.policies(),
        ]);
        setUsers(u.items || []);
        setRoles(r.items || []);
        setPolicies(p.items || []);
      } catch (error) {
        handleError(error);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  async function reloadUsers() {
    const result = await api.users();
    setUsers(result.items || []);
  }

  function reset() {
    setEditingId("");
    setForm(EMPTY);
    setRoleIds([]);
    setPolicyIds([]);
  }

  async function edit(target: User) {
    setEditingId(target.user_id);
    setForm({
      username: target.username,
      password: "",
      role: target.role,
      enabled: target.enabled,
    });
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
      await reloadUsers();
      toast.success("Usuário removido; a auditoria foi preservada.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                Administração
              </p>
              <DialogTitle>Usuários</DialogTitle>
            </div>
            <Button variant="secondary" size="sm" onClick={reset}>
              Novo usuário
            </Button>
          </div>
        </DialogHeader>

        <div className="grid gap-4 md:grid-cols-[220px_1fr]">
          <div className="grid max-h-[60vh] gap-1 overflow-y-auto">
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
          </div>

          <form className="grid gap-3" onSubmit={save}>
            <h3 className="font-semibold">
              {editingId ? "Editar usuário" : "Criar usuário"}
            </h3>
            <div className="grid gap-2">
              <Label htmlFor="u-name">Nome de usuário</Label>
              <Input
                id="u-name"
                value={form.username}
                minLength={3}
                maxLength={64}
                pattern="[A-Za-z0-9._-]+"
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
              {editingId && editingId !== user?.user_id && (
                <Button
                  type="button"
                  variant="destructive"
                  onClick={() => {
                    const target = users.find((u) => u.user_id === editingId);
                    if (target) remove(target);
                  }}
                >
                  Remover
                </Button>
              )}
              <Button type="submit" disabled={busy}>
                {editingId ? "Salvar alterações" : "Criar usuário"}{" "}
                <ArrowRight />
              </Button>
            </div>
          </form>
        </div>
      </DialogContent>
    </Dialog>
  );
}
