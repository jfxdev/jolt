import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { Policy, TemporaryPolicyAssignment } from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function TemporaryPoliciesEditor({ subject, subjectId, policies, agent = false }: {
  subject: "users" | "service-accounts";
  subjectId: string;
  policies: Policy[];
  agent?: boolean;
}) {
  const handleError = useApiError();
  const [items, setItems] = useState<TemporaryPolicyAssignment[]>([]);
  const [policyId, setPolicyId] = useState("");
  const [minutes, setMinutes] = useState(15);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setItems([]);
    api.temporaryPolicies(subject, subjectId).then((result) => {
      if (!cancelled) setItems(result.items || []);
    }).catch((error) => { if (!cancelled) handleError(error); });
    return () => { cancelled = true; };
    // The error handler is stable for the lifetime of the dialog.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subject, subjectId]);

  async function grant() {
    if (!policyId || !Number.isInteger(minutes) || minutes < 1 || minutes > 60) return;
    setBusy(true);
    try {
      const assignment = await api.grantTemporaryPolicy(subject, subjectId, policyId, minutes * 60);
      setItems((current) => [...current.filter((item) => item.policy_id !== policyId), assignment]);
      toast.success("Policy temporária concedida.");
    } catch (error) { handleError(error); } finally { setBusy(false); }
  }

  async function revoke(id: string) {
    setBusy(true);
    try {
      await api.revokeTemporaryPolicy(subject, subjectId, id);
      setItems((current) => current.filter((item) => item.policy_id !== id));
      toast.success("Policy temporária removida.");
    } catch (error) { handleError(error); } finally { setBusy(false); }
  }

  return (
    <fieldset className="grid gap-3 rounded-md border p-3">
      <legend className="px-1 text-sm font-medium">Policies temporárias</legend>
      <p className="text-sm text-muted-foreground">A concessão é aplicada imediatamente e expira automaticamente. {agent && "Agentes continuam limitados a leitura."}</p>
      {items.map((item) => (
        <div key={item.policy_id} className="flex flex-wrap items-center justify-between gap-2 text-sm">
          <span>{policies.find((policy) => policy.policy_id === item.policy_id)?.name || item.policy_id} · até {new Date(item.expires_at).toLocaleString()}</span>
          <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => void revoke(item.policy_id)}>Remover</Button>
        </div>
      ))}
      <div className="grid gap-2 sm:grid-cols-[1fr_8rem_auto] sm:items-end">
        <div className="grid gap-1"><Label htmlFor={`temporary-policy-${subjectId}`}>Policy</Label><select id={`temporary-policy-${subjectId}`} value={policyId} onChange={(event) => setPolicyId(event.target.value)} className="h-9 rounded-md border bg-background px-2 text-sm"><option value="">Selecione</option>{policies.map((policy) => <option key={policy.policy_id} value={policy.policy_id}>{policy.name}</option>)}</select></div>
        <div className="grid gap-1"><Label htmlFor={`temporary-minutes-${subjectId}`}>Minutos</Label><Input id={`temporary-minutes-${subjectId}`} type="number" min={1} max={60} step={1} value={minutes} onChange={(event) => setMinutes(Number(event.target.value))} /></div>
        <Button type="button" disabled={busy || !policyId || !Number.isInteger(minutes) || minutes < 1 || minutes > 60} onClick={() => void grant()}>Conceder</Button>
      </div>
    </fieldset>
  );
}
