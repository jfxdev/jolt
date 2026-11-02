import { useEffect, useState } from "react";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import type {
  AccessGroup,
  Policy,
  ServiceAccount,
  ServiceAccountToken,
  ServiceCredential,
  AgentLimits,
} from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm } from "@/context/ConfirmProvider";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
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
import { TemporaryPoliciesEditor } from "./TemporaryPoliciesEditor";
import {
  AdminEntityDialog,
  EntityDialogFormLayout,
} from "./AdminEntityDialog";

interface ServiceAccountForm {
  kind: "automation" | "agent";
  limits: AgentLimits;
  cidrs: string;
  mediaTypes: string;
  name: string;
  description: string;
  group_ids: string[];
  enabled: boolean;
  token_name: string;
  expires_at: string;
}

function emptyForm(): ServiceAccountForm {
  return {
    kind: "automation",
    limits: { requests_per_minute: 60, burst: 10, max_concurrent: 2, max_response_bytes: 16 * 1024 * 1024, daily_bytes: 1024 * 1024 * 1024, allowed_cidrs: [] },
    cidrs: "",
    mediaTypes: "",
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
  inline = false,
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
  const [search, setSearch] = useState("");
  const [formOpen, setFormOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    reset();
    setSearch("");
    (async () => {
      try {
        const [p, g] = await Promise.all([api.policies(), api.accessGroups()]);
        setPolicies(p.items || []);
        setGroups(g.items || []);
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
        .serviceAccounts(search)
        .then((result) => {
          if (!cancelled) setAccounts(result.items || []);
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
    setForm(emptyForm());
    setPolicyIds([]);
    setTokens([]);
    setCredential(null);
  }

  function openCreateForm() {
    reset();
    setFormOpen(true);
  }

  function closeForm(open: boolean) {
    setFormOpen(open);
    if (!open) reset();
  }

  async function reloadAccounts(query = search) {
    const result = await api.serviceAccounts(query);
    setAccounts(result.items || []);
  }

  async function edit(target: ServiceAccount) {
    setEditingId(target.service_account_id);
    setCredential(null);
    setForm({
      kind: target.kind || "automation",
      limits: emptyForm().limits,
      cidrs: "",
      mediaTypes: "",
      name: target.name,
      description: target.description,
      group_ids: [],
      enabled: target.enabled,
      token_name: "rotated",
      expires_at: "",
    });
    setFormOpen(true);
    try {
      const [t, p, g] = await Promise.all([
        api.serviceAccountTokens(target.service_account_id),
        api.serviceAccountPolicies(target.service_account_id),
        api.serviceAccountGroups(target.service_account_id),
      ]);
      setTokens(t.items || []);
      setPolicyIds(p.policy_ids || []);
      const limits = t.items?.find((token) => !token.revoked_at && token.agent_limits)?.agent_limits;
      setForm((current) => ({ ...current, group_ids: g.group_ids || [], limits: limits || current.limits, cidrs: limits?.allowed_cidrs?.join(", ") || "", mediaTypes: limits?.read_media_types?.join(", ") || "" }));
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
          kind: form.kind,
          ...(form.kind === "agent" ? { agent_limits: { ...form.limits, allowed_cidrs: form.cidrs.split(",").map((item) => item.trim()).filter(Boolean), read_media_types: form.mediaTypes.split(",").map((item) => item.trim()).filter(Boolean) } } : {}),
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
        ...(form.kind === "agent" ? { agent_limits: { ...form.limits, allowed_cidrs: form.cidrs.split(",").map((item) => item.trim()).filter(Boolean), read_media_types: form.mediaTypes.split(",").map((item) => item.trim()).filter(Boolean) } } : {}),
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

  async function updateLimits(token: ServiceAccountToken) {
    setBusy(true);
    try {
      await api.updateAgentTokenLimits(editingId, token.token_id, { ...form.limits, allowed_cidrs: form.cidrs.split(",").map((item) => item.trim()).filter(Boolean), read_media_types: form.mediaTypes.split(",").map((item) => item.trim()).filter(Boolean) });
      const result = await api.serviceAccountTokens(editingId);
      setTokens(result.items || []);
      toast.success("Limites atualizados; requisições em andamento foram interrompidas.");
    } catch (error) { handleError(error); } finally { setBusy(false); }
  }

  async function disableAgents() {
    if (!(await confirm({ title: "Desativar todos os agentes?", description: "As requisições em andamento serão interrompidas. Cada conta poderá ser reativada individualmente.", confirmText: "Desativar agentes", destructive: true }))) return;
    setBusy(true);
    try {
      const result = await api.disableAgentAccounts();
      await reloadAccounts();
      toast.success(`${result.disabled} conta(s) de agente desativada(s).`);
    } catch (error) { handleError(error); } finally { setBusy(false); }
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
      setFormOpen(false);
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

  if (inline && !open) return null;

  const searchInput = (
    <div className="grid gap-2">
      <Label htmlFor="api-keys-search">Buscar API keys</Label>
      <Input
        id="api-keys-search"
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
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                Administração
              </p>
              <DialogTitle>API Keys</DialogTitle>
            </div>
            <div className="flex flex-wrap gap-2">
            <Button variant="destructive" size="sm" disabled={busy} onClick={disableAgents}>Desativar agentes</Button>
            <Button variant="secondary" size="sm" onClick={openCreateForm}>
              Nova API key
            </Button>
            </div>
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
                <Table aria-label="API Keys cadastradas">
                  <TableHeader>
                    <TableRow>
                      <TableHead>API Key</TableHead>
                      <TableHead>Descrição</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Ação</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {accounts.map((target) => (
                      <TableRow
                        key={target.service_account_id}
                        data-state={
                          editingId === target.service_account_id
                            ? "selected"
                            : undefined
                        }
                      >
                        <TableCell className="font-medium">{target.name}</TableCell>
                        <TableCell className="max-w-sm truncate text-muted-foreground">
                          {target.description || "Sem descrição"}
                        </TableCell>
                        <TableCell>
                          <span
                            className={
                              target.enabled ? "text-emerald-500" : "text-destructive"
                            }
                          >
                            {target.enabled ? "Ativa" : "Inativa"}
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
                            <Button
                              type="button"
                              variant="destructive"
                              size="sm"
                              onClick={() => void remove(target)}
                            >
                              Remover
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                    {!accounts.length && (
                      <TableRow>
                        <TableCell colSpan={4} className="text-muted-foreground">
                          {search
                            ? "Nenhuma API key encontrada."
                            : "Nenhuma conta de serviço."}
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
                  {search ? "Nenhuma API key encontrada." : "Nenhuma conta de serviço."}
                </div>
              )}
            </div>
          )}

          <AdminEntityDialog
            open={formOpen}
            onOpenChange={closeForm}
            title={editingId ? "Editar conta" : "Criar conta"}
          >
              <form className="grid gap-3" onSubmit={save}>
            <EntityDialogFormLayout
              summary={
                <>
            <div className="grid gap-2">
              <Label htmlFor="sa-kind">Tipo de conta</Label>
              <Select value={form.kind} disabled={!!editingId} onValueChange={(value) => setForm({ ...form, kind: value as "automation" | "agent" })}>
                <SelectTrigger id="sa-kind"><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="automation">Automação</SelectItem><SelectItem value="agent">Agente de IA</SelectItem></SelectContent>
              </Select>
              {form.kind === "agent" && <small className="text-muted-foreground">O agente pode apenas listar e ler, dentro das policies e limites da credencial.</small>}
            </div>
            <div className="grid gap-2">
              <Label htmlFor="sa-name">Nome</Label>
              <Input
                id="sa-name"
                value={form.name}
                minLength={3}
                maxLength={64}
                pattern="[A-Za-z0-9._\-]+"
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
                </>
              }
            >
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

            {editingId && <TemporaryPoliciesEditor subject="service-accounts" subjectId={editingId} policies={policies} agent={form.kind === "agent"} />}

            {form.kind === "agent" && (
              <fieldset className="grid gap-3 rounded-md border p-3">
                <legend className="px-1 text-sm font-medium">Limites da credencial{editingId ? " selecionada ou nova" : ""}</legend>
                {([
                  ["requests_per_minute", "Requisições por minuto", 1, 60000],
                  ["burst", "Pico de requisições", 1, 10000],
                  ["max_concurrent", "Requisições simultâneas", 1, 32],
                  ["max_response_bytes", "Bytes por resposta", 1024, 1073741824],
                  ["daily_bytes", "Bytes por dia (UTC)", 1024, 1125899906842624],
                ] as const).map(([key, label, min, max]) => (
                  <div className="grid gap-1" key={key}>
                    <Label htmlFor={`agent-${key}`}>{label}</Label>
                    <Input id={`agent-${key}`} type="number" min={min} max={max} step={1} required value={form.limits[key]} onChange={(event) => setForm((current) => ({ ...current, limits: { ...current.limits, [key]: Number(event.target.value) } }))} />
                  </div>
                ))}
                <div className="grid gap-1"><Label htmlFor="agent-cidrs">Redes permitidas (CIDR, opcional)</Label><Input id="agent-cidrs" value={form.cidrs} placeholder="192.168.1.0/24, 10.0.0.0/8" onChange={(event) => setForm({ ...form, cidrs: event.target.value })} /></div>
                <div className="grid gap-1"><Label htmlFor="agent-media-types">Formatos de leitura (opcional)</Label><Input id="agent-media-types" value={form.mediaTypes} placeholder="text/plain, application/pdf" onChange={(event) => setForm({ ...form, mediaTypes: event.target.value })} /></div>
                <small className="text-muted-foreground">Em branco permite qualquer formato. Com restrição, downloads ZIP ficam indisponíveis.</small>
                <small className="text-muted-foreground">Deixe as redes em branco para permitir qualquer origem. A expiração padrão é de 30 dias.</small>
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
                  <Label htmlFor="sa-exp">{form.kind === "agent" ? "Expiração (padrão: 30 dias)" : "Expiração opcional"}</Label>
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
                  <Label htmlFor="sa-newexp">{form.kind === "agent" ? "Expiração (padrão: 30 dias)" : "Expiração opcional"}</Label>
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
                        <div className="flex flex-wrap gap-1">
                        {form.kind === "agent" && token.agent_limits && <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => setForm((current) => ({ ...current, limits: token.agent_limits!, cidrs: token.agent_limits?.allowed_cidrs?.join(", ") || "", mediaTypes: token.agent_limits?.read_media_types?.join(", ") || "" }))}>Carregar limites</Button>}
                        {form.kind === "agent" && <Button type="button" variant="secondary" size="sm" disabled={busy} onClick={() => void updateLimits(token)}>Aplicar limites</Button>}
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          onClick={() => revoke(token)}
                        >
                          Revogar
                        </Button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex justify-end gap-2">
              <Button type="submit" disabled={busy}>
                {editingId ? "Salvar alterações" : "Criar e emitir API key"}{" "}
                <ArrowRight />
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
