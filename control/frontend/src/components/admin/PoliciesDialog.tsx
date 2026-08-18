import { useEffect, useState } from "react";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import type { Capability, Policy, PolicyRule } from "@/lib/types";
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

const CAPABILITIES: Capability[] = [
  "read",
  "list",
  "create",
  "update",
  "delete",
  "write",
  "execute",
  "sudo",
  "deny",
];

interface PolicyForm {
  name: string;
  description: string;
  rules: PolicyRule[];
}

function emptyForm(): PolicyForm {
  return {
    name: "",
    description: "",
    rules: [{ path: "nodes/*", capabilities: ["list"] }],
  };
}

function normalize(rule: PolicyRule, changed: Capability): Capability[] {
  if (changed === "deny" && rule.capabilities.includes("deny")) return ["deny"];
  if (changed !== "deny" && rule.capabilities.includes(changed))
    return rule.capabilities.filter((c) => c !== "deny");
  return rule.capabilities;
}

export function PoliciesDialog({ open, onOpenChange }: AdminDialogProps) {
  const handleError = useApiError();
  const confirm = useConfirm();
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [editingId, setEditingId] = useState("");
  const [form, setForm] = useState<PolicyForm>(emptyForm());
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    reset();
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  async function reload() {
    try {
      const result = await api.policies();
      setPolicies(result.items || []);
    } catch (error) {
      handleError(error);
    }
  }

  function reset() {
    setEditingId("");
    setForm(emptyForm());
  }

  function edit(policy: Policy) {
    setEditingId(policy.policy_id);
    setForm({
      name: policy.name,
      description: policy.description,
      rules: policy.rules.map((r) => ({
        path: r.path,
        capabilities: [...r.capabilities],
      })),
    });
  }

  function toggleCapability(index: number, capability: Capability) {
    setForm((prev) => {
      const rules = prev.rules.map((rule, i) => {
        if (i !== index) return rule;
        const has = rule.capabilities.includes(capability);
        const capabilities = has
          ? rule.capabilities.filter((c) => c !== capability)
          : [...rule.capabilities, capability];
        const next = { ...rule, capabilities };
        return { ...next, capabilities: normalize(next, capability) };
      });
      return { ...prev, rules };
    });
  }

  function setRulePath(index: number, path: string) {
    setForm((prev) => ({
      ...prev,
      rules: prev.rules.map((rule, i) =>
        i === index ? { ...rule, path } : rule,
      ),
    }));
  }

  function addRule() {
    setForm((prev) => ({
      ...prev,
      rules: [...prev.rules, { path: "nodes/*", capabilities: ["read"] }],
    }));
  }

  function removeRule(index: number) {
    setForm((prev) =>
      prev.rules.length > 1
        ? { ...prev, rules: prev.rules.filter((_, i) => i !== index) }
        : prev,
    );
  }

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      if (editingId) {
        await api.updatePolicy(editingId, form);
        toast.success("Policy atualizada.");
      } else {
        await api.createPolicy(form);
        toast.success("Policy criada.");
      }
      reset();
      await reload();
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  async function remove(policy: Policy) {
    if (
      !(await confirm({
        title: `Remover a policy “${policy.name}”?`,
        description: "As atribuições relacionadas também serão removidas.",
        confirmText: "Remover",
        destructive: true,
      }))
    )
      return;
    setBusy(true);
    try {
      await api.deletePolicy(policy.policy_id);
      reset();
      await reload();
      toast.success("Policy removida.");
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
                Autorização
              </p>
              <DialogTitle>Node Path policies</DialogTitle>
            </div>
            <Button variant="secondary" size="sm" onClick={reset}>
              Nova policy
            </Button>
          </div>
        </DialogHeader>

        <div className="grid gap-4 md:grid-cols-[220px_1fr]">
          <div className="grid max-h-[60vh] gap-1 overflow-y-auto">
            {policies.map((policy) => (
              <button
                key={policy.policy_id}
                className={cn(
                  "rounded-md border p-2 text-left text-sm hover:bg-accent",
                  editingId === policy.policy_id && "bg-accent",
                )}
                onClick={() => edit(policy)}
              >
                <strong className="block">{policy.name}</strong>
                <small className="text-muted-foreground">
                  {policy.rules.length} regra(s)
                </small>
              </button>
            ))}
            {!policies.length && (
              <div className="p-2 text-xs text-muted-foreground">
                Nenhuma policy cadastrada.
              </div>
            )}
          </div>

          <form className="grid gap-3" onSubmit={save}>
            <h3 className="font-semibold">
              {editingId ? "Editar policy" : "Criar policy"}
            </h3>
            <div className="grid gap-2">
              <Label htmlFor="p-name">Nome</Label>
              <Input
                id="p-name"
                value={form.name}
                minLength={3}
                maxLength={64}
                pattern="[A-Za-z0-9._-]+"
                required
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="p-desc">Descrição</Label>
              <Textarea
                id="p-desc"
                value={form.description}
                maxLength={512}
                rows={2}
                onChange={(e) =>
                  setForm({ ...form, description: e.target.value })
                }
              />
            </div>

            <div className="grid gap-3">
              {form.rules.map((rule, index) => (
                <article key={index} className="grid gap-2 rounded-md border p-3">
                  <div className="flex items-center justify-between">
                    <strong className="text-sm">Regra {index + 1}</strong>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      disabled={form.rules.length === 1}
                      onClick={() => removeRule(index)}
                    >
                      Remover
                    </Button>
                  </div>
                  <div className="grid gap-2">
                    <Label className="text-xs">Node Path</Label>
                    <Input
                      value={rule.path}
                      placeholder="nodes/*/files/mounts/media"
                      required
                      onChange={(e) => setRulePath(index, e.target.value)}
                    />
                  </div>
                  <div className="grid grid-cols-3 gap-1">
                    {CAPABILITIES.map((capability) => (
                      <label
                        key={capability}
                        className={cn(
                          "flex items-center gap-1.5 text-sm",
                          capability === "deny" && "text-destructive",
                        )}
                      >
                        <Checkbox
                          checked={rule.capabilities.includes(capability)}
                          onCheckedChange={() =>
                            toggleCapability(index, capability)
                          }
                        />
                        {capability}
                      </label>
                    ))}
                  </div>
                </article>
              ))}
            </div>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={addRule}
            >
              Adicionar regra
            </Button>

            <div className="flex justify-end gap-2">
              {editingId && (
                <Button
                  type="button"
                  variant="destructive"
                  onClick={() => {
                    const policy = policies.find(
                      (p) => p.policy_id === editingId,
                    );
                    if (policy) remove(policy);
                  }}
                >
                  Remover policy
                </Button>
              )}
              <Button type="submit" disabled={busy}>
                Salvar policy <ArrowRight />
              </Button>
            </div>
          </form>
        </div>
      </DialogContent>
    </Dialog>
  );
}
