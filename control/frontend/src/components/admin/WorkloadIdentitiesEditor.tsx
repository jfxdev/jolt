import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { useConfirm } from "@/context/ConfirmProvider";
import { useApiError } from "@/hooks/useApiError";
import { api } from "@/lib/api";
import { safeDisplayName } from "@/lib/display-name";
import type { AgentLimits, WorkloadIdentity } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface Props {
  accountId: string;
  agentLimits?: AgentLimits;
  onLoadLimits?: (limits: AgentLimits) => void;
}

export function WorkloadIdentitiesEditor({ accountId, agentLimits, onLoadLimits }: Props) {
  const handleError = useApiError();
  const confirm = useConfirm();
  const [items, setItems] = useState<WorkloadIdentity[]>([]);
  const [provider, setProvider] = useState("");
  const [issuer, setIssuer] = useState("");
  const [subject, setSubject] = useState("");
  const [audience, setAudience] = useState("");
  const [busy, setBusy] = useState(false);
  const sequence = useRef(0);

  async function refresh() {
    const current = ++sequence.current;
    try {
      const result = await api.workloadIdentities(accountId);
      if (sequence.current === current) setItems(result.items || []);
    } catch (error) {
      if (sequence.current === current) handleError(error);
    }
  }

  useEffect(() => {
    void refresh();
    return () => { sequence.current++; };
    // A remount on account change resets the form and request sequence.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accountId]);

  async function create() {
    setBusy(true);
    try {
      await api.createWorkloadIdentity(accountId, {
        provider_id: provider.trim(), issuer: issuer.trim(), subject: subject.trim(), audience: audience.trim(),
        ...(agentLimits ? { agent_limits: agentLimits } : {}),
      });
      setSubject("");
      await refresh();
      toast.success("Identidade de workload cadastrada.");
    } catch (error) { handleError(error); } finally { setBusy(false); }
  }

  async function setEnabled(identity: WorkloadIdentity) {
    setBusy(true);
    try {
      await api.setWorkloadIdentityEnabled(accountId, identity.credential_id, !identity.enabled);
      await refresh();
      toast.success(identity.enabled ? "Identidade desativada." : "Identidade ativada.");
    } catch (error) { handleError(error); } finally { setBusy(false); }
  }

  async function revoke(identity: WorkloadIdentity) {
    if (!(await confirm({ title: "Revogar identidade de workload?", description: "Esta credencial não poderá ser reativada.", confirmText: "Revogar", destructive: true }))) return;
    setBusy(true);
    try {
      await api.revokeServiceAccountToken(accountId, identity.credential_id);
      await refresh();
      toast.success("Identidade revogada.");
    } catch (error) { handleError(error); } finally { setBusy(false); }
  }

  async function updateLimits(identity: WorkloadIdentity) {
    if (!agentLimits) return;
    setBusy(true);
    try {
      await api.updateAgentTokenLimits(accountId, identity.credential_id, agentLimits);
      await refresh();
      toast.success("Limites atualizados.");
    } catch (error) { handleError(error); } finally { setBusy(false); }
  }

  return <section className="grid gap-3 rounded-md border p-3" aria-label="Identidades de workload">
    <div>
      <h3 className="font-semibold">Identidades de workload</h3>
      <p className="text-xs text-muted-foreground">Cadastre o provedor e os claims configurados. A autenticação por workload ainda não está disponível.</p>
    </div>
    <div className="grid gap-2 sm:grid-cols-2">
      <div className="grid gap-1"><Label htmlFor="workload-provider">Provedor</Label><Input id="workload-provider" value={provider} onChange={e => setProvider(e.target.value)} /></div>
      <div className="grid gap-1"><Label htmlFor="workload-issuer">Emissor</Label><Input id="workload-issuer" value={issuer} onChange={e => setIssuer(e.target.value)} placeholder="Vazio para JWT-SVID" /></div>
      <div className="grid gap-1"><Label htmlFor="workload-subject">Sujeito</Label><Input id="workload-subject" value={subject} onChange={e => setSubject(e.target.value)} /></div>
      <div className="grid gap-1"><Label htmlFor="workload-audience">Audiência</Label><Input id="workload-audience" value={audience} onChange={e => setAudience(e.target.value)} /></div>
    </div>
    {agentLimits && <p className="text-xs text-muted-foreground">O novo vínculo usará os limites de agente exibidos acima.</p>}
    <Button type="button" variant="secondary" size="sm" disabled={busy || !provider.trim() || !subject.trim() || !audience.trim()} onClick={() => void create()}>Adicionar identidade</Button>
    <div className="grid gap-2">
      {items.map(item => <div key={item.credential_id} className="flex flex-wrap items-center justify-between gap-2 border-t pt-2 text-sm">
        <div className="min-w-0"><strong className="break-all">{safeDisplayName(item.subject)}</strong><p className="break-all text-xs text-muted-foreground">{safeDisplayName(item.provider_id)} · {safeDisplayName(item.audience)} · {item.revoked ? "Revogada" : item.enabled ? "Ativa" : "Desativada"}</p></div>
        {!item.revoked && <div className="flex flex-wrap gap-1">
          {agentLimits && item.agent_limits && onLoadLimits && <Button type="button" variant="ghost" size="sm" disabled={busy} aria-label={`Carregar limites da identidade ${safeDisplayName(item.subject)}`} onClick={() => onLoadLimits(item.agent_limits!)}>Carregar limites</Button>}
          {agentLimits && <Button type="button" variant="secondary" size="sm" disabled={busy} aria-label={`Aplicar limites à identidade ${safeDisplayName(item.subject)}`} onClick={() => void updateLimits(item)}>Aplicar limites</Button>}
          <Button type="button" variant="outline" size="sm" disabled={busy} aria-label={`${item.enabled ? "Desativar" : "Ativar"} identidade ${safeDisplayName(item.subject)}`} onClick={() => void setEnabled(item)}>{item.enabled ? "Desativar" : "Ativar"}</Button>
          <Button type="button" variant="ghost" size="sm" disabled={busy} aria-label={`Revogar identidade ${safeDisplayName(item.subject)}`} onClick={() => void revoke(item)}>Revogar</Button>
        </div>}
      </div>)}
    </div>
  </section>;
}
