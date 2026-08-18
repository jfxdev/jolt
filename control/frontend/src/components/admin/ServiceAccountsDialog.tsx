import { useEffect, useState } from "react";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import type {
  AccessGroup,
  Policy,
  ServiceAccount,
  ServiceAccountToken,
  ServiceCredential,
} from "@/lib/types";
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
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { AdminDialogProps } from "./types";

interface ServiceAccountForm {
  name: string;
  description: string;
  group_ids: string[];
  enabled: boolean;
  token_name: string;
  expires_at: string;
}

function emptyForm(): ServiceAccountForm {
  return {
    name: "",
    description: "",
    group_ids: [],
    enabled: true,
    token_name: "initial",
    expires_at: "",
  };
}

function credentialExpiry(value: string) {
  return value ? new Date(value).toISOString() : null;
}

export function ServiceAccountsDialog({
  open,
  onOpenChange,
}: AdminDialogProps) {
  const handleError = useApiError();
  const confirm = useConfirm();
  const [accounts, setAccounts] = useState<ServiceAccount[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [groups, setGroups] = useState<AccessGroup[]>([]);
  const [editingId, setEditingId] = useState("");
  const [form, setForm] = useState<ServiceAccountForm>(emptyForm());
  const [policyIds, setPolicyIds] = useState<string[]>([]);
  const [tokens, setTokens] = useState<ServiceAccountToken[]>([]);
  const [credential, setCredential] = useState<ServiceCredential | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    reset();
    (async () => {
      try {
        const [a, p, g] = await Promise.all([
          api.serviceAccounts(),
          api.policies(),
          api.accessGroups(),
        ]);
        setAccounts(a.items || []);
        setPolicies(p.items || []);
        setGroups(g.items || []);
      } catch (error) {
        handleError(error);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  function reset() {
    setEditingId("");
    setForm(emptyForm());
    setPolicyIds([]);
    setTokens([]);
    setCredential(null);
  }

  async function reloadAccounts() {
    const result = await api.serviceAccounts();
    setAccounts(result.items || []);
  }

  async function edit(target: ServiceAccount) {
    setEditingId(target.service_account_id);
    setCredential(null);
    setForm({
      name: target.name,
      description: target.description,
      group_ids: [],
      enabled: target.enabled,
      token_name: "rotated",
      expires_at: "",
    });
    try {
      const [t, p, g] = await Promise.all([
        api.serviceAccountTokens(target.service_account_id),
        api.serviceAccountPolicies(target.service_account_id),
        api.serviceAccountGroups(target.service_account_id),
      ]);
      setTokens(t.items || []);
      setPolicyIds(p.policy_ids || []);
      setForm((current) => ({ ...current, group_ids: g.group_ids || [] }));
    } catch (error) {
      handleError(error);
    }
  }

  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (!form.group_ids.length) {
      toast.error("Selecione ao menos um grupo de acesso ativo.");
      return;
    }
    setBusy(true);
    try {
      if (editingId) {
        await api.updateServiceAccount(editingId, {
          name: form.name,
          description: form.description,
          enabled: form.enabled,
        });
        await Promise.all([
          api.setServiceAccountPolicies(editingId, policyIds),
          api.setServiceAccountGroups(editingId, form.group_ids),
        ]);
        toast.success("Conta de serviço atualizada.");
      } else {
        const result = await api.createServiceAccount({
          name: form.name,
          description: form.description,
          group_ids: form.group_ids,
          enabled: form.enabled,
          token_name: form.token_name,
          expires_at: credentialExpiry(form.expires_at),
        });
        setCredential(result.credential);
        setEditingId(result.service_account.service_account_id);
        setTokens([
          {
            token_id: result.credential.token_id,
            name: result.credential.name,
            expires_at: result.credential.expires_at,
            created_at: result.credential.created_at,
          },
        ]);
        toast.success("Conta criada. Copie a credencial agora.");
      }
      await reloadAccounts();
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  async function rotate() {
    setBusy(true);
    try {
      const result = await api.rotateServiceAccountToken(editingId, {
        name: form.token_name || "rotated",
        expires_at: credentialExpiry(form.expires_at),
        revoke_existing: true,
      });
      setCredential(result);
      const t = await api.serviceAccountTokens(editingId);
      setTokens(t.items || []);
      toast.success(
        "Credencial rotacionada. As credenciais anteriores foram revogadas.",
      );
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  async function revoke(token: ServiceAccountToken) {
    if (
      !(await confirm({
        title: `Revogar a credencial “${token.name}”?`,
        confirmText: "Revogar",
        destructive: true,
      }))
    )
      return;
    try {
      await api.revokeServiceAccountToken(editingId, token.token_id);
      const t = await api.serviceAccountTokens(editingId);
      setTokens(t.items || []);
      toast.success("Credencial revogada.");
    } catch (error) {
      handleError(error);
    }
  }

  async function remove(target: ServiceAccount) {
    if (
      !(await confirm({
        title: `Remover a conta de serviço “${target.name}”?`,
        description:
          "Suas credenciais serão revogadas e a auditoria será preservada.",
        confirmText: "Remover",
        destructive: true,
      }))
    )
      return;
    setBusy(true);
    try {
      await api.deleteServiceAccount(target.service_account_id);
      reset();
      await reloadAccounts();
      toast.success("Conta removida; a auditoria foi preservada.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  async function copyCredential() {
    if (!credential?.token) return;
    try {
      await navigator.clipboard.writeText(credential.token);
      toast.success("Credencial copiada.");
    } catch {
      toast.message("Selecione e copie a credencial manualmente.");
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
              <DialogTitle>API Keys</DialogTitle>
            </div>
            <Button variant="secondary" size="sm" onClick={reset}>
              Nova API key
            </Button>
          </div>
        </DialogHeader>

        <div className="grid gap-4 md:grid-cols-[220px_1fr]">
          <div className="grid max-h-[60vh] gap-1 overflow-y-auto">
            {accounts.map((target) => (
              <button
                key={target.service_account_id}
                className={cn(
                  "flex items-center justify-between rounded-md border p-2 text-left text-sm hover:bg-accent",
                  editingId === target.service_account_id && "bg-accent",
                )}
                onClick={() => edit(target)}
              >
                <span>
                  <strong className="block">{target.name}</strong>
                  <small className="text-muted-foreground">
                    {target.description || "Sem descrição"}
                  </small>
                </span>
                <small
                  className={
                    target.enabled ? "text-emerald-500" : "text-destructive"
                  }
                >
                  {target.enabled ? "Ativa" : "Inativa"}
                </small>
              </button>
            ))}
            {!accounts.length && (
              <div className="p-2 text-xs text-muted-foreground">
                Nenhuma conta de serviço.
              </div>
            )}
          </div>

          <form className="grid gap-3" onSubmit={save}>
            <h3 className="font-semibold">
              {editingId ? "Editar conta" : "Criar conta"}
            </h3>
            <div className="grid gap-2">
              <Label htmlFor="sa-name">Nome</Label>
              <Input
                id="sa-name"
                value={form.name}
                minLength={3}
                maxLength={64}
                pattern="[A-Za-z0-9._-]+"
                autoComplete="off"
                required
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="sa-desc">Descrição</Label>
              <Textarea
                id="sa-desc"
                value={form.description}
                maxLength={512}
                rows={2}
                onChange={(e) =>
                  setForm({ ...form, description: e.target.value })
                }
              />
            </div>
            <fieldset className="grid gap-2 rounded-md border p-3">
              <legend className="px-1 text-sm font-medium">Grupos de acesso</legend>
              {groups.map((group) => (
                <label key={group.group_id} className="flex items-center gap-2 text-sm">
                  <Checkbox checked={form.group_ids.includes(group.group_id)} disabled={!group.enabled && !form.group_ids.includes(group.group_id)} onCheckedChange={(value) => setForm((current) => ({ ...current, group_ids: value === true ? [...current.group_ids, group.group_id] : current.group_ids.filter((id) => id !== group.group_id) }))} />
                  <span><strong>{group.name}</strong>{!group.enabled && <small className="text-destructive"> (inativo)</small>}</span>
                </label>
              ))}
              <small className="text-muted-foreground">Selecione ao menos um grupo. A API key recebe a união dos nodes e policies dos grupos ativos.</small>
            </fieldset>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={form.enabled}
                onCheckedChange={(v) =>
                  setForm({ ...form, enabled: v === true })
                }
              />
              Conta ativa
            </label>

            {editingId && (
              <fieldset className="grid gap-2 rounded-md border p-3">
                <legend className="px-1 text-sm font-medium">
                  Policies extras da API key
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
                    Sem uma policy, a conta não acessa nodes.
                  </small>
                )}
              </fieldset>
            )}

            {!editingId && (
              <>
                <div className="grid gap-2">
                  <Label htmlFor="sa-token">Nome da credencial</Label>
                  <Input
                    id="sa-token"
                    value={form.token_name}
                    maxLength={64}
                    autoComplete="off"
                    required
                    onChange={(e) =>
                      setForm({ ...form, token_name: e.target.value })
                    }
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="sa-exp">Expiração opcional</Label>
                  <Input
                    id="sa-exp"
                    type="datetime-local"
                    value={form.expires_at}
                    onChange={(e) =>
                      setForm({ ...form, expires_at: e.target.value })
                    }
                  />
                </div>
              </>
            )}

            {credential && (
              <div className="grid gap-2 rounded-md border border-primary p-3">
                <strong className="text-sm">
                  Copie agora — este token não será exibido novamente.
                </strong>
                <code className="break-all text-xs">{credential.token}</code>
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  onClick={copyCredential}
                >
                  Copiar credencial
                </Button>
              </div>
            )}

            {editingId && (
              <div className="grid gap-2 rounded-md border p-3">
                <div className="flex items-baseline justify-between">
                  <h3 className="font-semibold">Credenciais</h3>
                  <small className="text-muted-foreground">
                    Rotação revoga todas as anteriores.
                  </small>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="sa-newtoken">Nome da nova credencial</Label>
                  <Input
                    id="sa-newtoken"
                    value={form.token_name}
                    maxLength={64}
                    autoComplete="off"
                    onChange={(e) =>
                      setForm({ ...form, token_name: e.target.value })
                    }
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="sa-newexp">Expiração opcional</Label>
                  <Input
                    id="sa-newexp"
                    type="datetime-local"
                    value={form.expires_at}
                    onChange={(e) =>
                      setForm({ ...form, expires_at: e.target.value })
                    }
                  />
                </div>
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  disabled={busy}
                  onClick={rotate}
                >
                  Rotacionar credencial
                </Button>
                <div className="grid gap-1">
                  {tokens.map((token) => (
                    <div
                      key={token.token_id}
                      className="flex items-center justify-between text-sm"
                    >
                      <span>
                        <strong>{token.name}</strong>{" "}
                        <small className="text-muted-foreground">
                          {token.revoked_at
                            ? "Revogada"
                            : token.expires_at
                              ? `Expira ${new Date(token.expires_at).toLocaleString()}`
                              : "Sem expiração"}
                        </small>
                      </span>
                      {!token.revoked_at && (
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          onClick={() => revoke(token)}
                        >
                          Revogar
                        </Button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex justify-end gap-2">
              {editingId && (
                <Button
                  type="button"
                  variant="destructive"
                  onClick={() => {
                    const target = accounts.find(
                      (a) => a.service_account_id === editingId,
                    );
                    if (target) remove(target);
                  }}
                >
                  Remover
                </Button>
              )}
              <Button type="submit" disabled={busy}>
                {editingId ? "Salvar alterações" : "Criar e emitir API key"}{" "}
                <ArrowRight />
              </Button>
            </div>
          </form>
        </div>
      </DialogContent>
    </Dialog>
  );
}
