import { useEffect, useMemo, useState } from "react";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import type { Capability, Mount, Policy, PolicyRule } from "@/lib/types";
import { useApiError } from "@/hooks/useApiError";
import { useConfirm } from "@/context/ConfirmProvider";
import { useNodes } from "@/context/NodesContext";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Toggle } from "@/components/ui/toggle";
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
import {
  AdminEntityDialog,
  EntityDialogFormLayout,
} from "./AdminEntityDialog";

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

interface MountOption {
  mount: Mount;
  availableOn: number;
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

function segments(path: string): string[] {
  return path.trim().replace(/^\/+|\/+$/g, "").split("/").filter(Boolean);
}

function nodeSegment(path: string): string {
  const values = segments(path);
  return values[0] === "nodes" ? (values[1] ?? "") : "";
}

function mountSegment(path: string): string {
  const values = segments(path);
  if (values[0] !== "nodes") return "";
  const mountIndex = values.indexOf("mounts");
  return mountIndex >= 0 ? (values[mountIndex + 1] ?? "") : "";
}

function isDirectNodePath(path: string): boolean {
  const values = segments(path);
  return values[0] === "nodes" && values.length === 2;
}

function withNodeSegment(path: string, nodeID: string): string {
  const values = segments(path);
  if (values[0] !== "nodes") return `nodes/${nodeID}`;
  values[1] = nodeID;
  return values.join("/");
}

function withMountSegment(path: string, nodeID: string, mountID: string): string {
  const values = segments(path);
  if (values[0] === "nodes") {
    const selectedNode = values[1] || nodeID || "*";
    const mountIndex = values.indexOf("mounts");
    if (mountIndex >= 0) {
      values[mountIndex + 1] = mountID;
      return values.join("/");
    }
    return `nodes/${selectedNode}/files/mounts/${mountID}`;
  }
  return `nodes/${nodeID || "*"}/files/mounts/${mountID}`;
}

export function PoliciesDialog({
  open,
  onOpenChange,
  inline = false,
}: AdminDialogProps) {
  const handleError = useApiError();
  const confirm = useConfirm();
  const { nodes } = useNodes();
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [editingId, setEditingId] = useState("");
  const [form, setForm] = useState<PolicyForm>(emptyForm());
  const [busy, setBusy] = useState(false);
  const [mountsByNode, setMountsByNode] = useState<Record<string, Mount[]>>(
    {},
  );
  const [mountsLoading, setMountsLoading] = useState(false);
  const [mountLoadFailures, setMountLoadFailures] = useState(0);
  const [directNodeModes, setDirectNodeModes] = useState([true]);
  const [search, setSearch] = useState("");
  const [formOpen, setFormOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    reset();
    setSearch("");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  useEffect(() => {
    if (!open) {
      setMountsByNode({});
      setMountsLoading(false);
      setMountLoadFailures(0);
      return;
    }

    let cancelled = false;
    setMountsLoading(true);
    setMountLoadFailures(0);

    void Promise.allSettled(
      nodes.map(async (node) => ({
        nodeID: node.node_id,
        mounts: (await api.mounts(node.node_id)).items || [],
      })),
    ).then((results) => {
      if (cancelled) return;

      const next: Record<string, Mount[]> = {};
      let failures = 0;
      for (const result of results) {
        if (result.status === "fulfilled") {
          next[result.value.nodeID] = result.value.mounts;
        } else {
          failures += 1;
        }
      }
      setMountsByNode(next);
      setMountLoadFailures(failures);
      setMountsLoading(false);
    });

    return () => {
      cancelled = true;
    };
  }, [nodes, open]);

  const allMounts = useMemo<MountOption[]>(() => {
    const options = new Map<string, MountOption>();
    for (const node of nodes) {
      for (const mount of mountsByNode[node.node_id] || []) {
        const current = options.get(mount.mount_id);
        options.set(mount.mount_id, {
          mount: current?.mount || mount,
          availableOn: (current?.availableOn || 0) + 1,
        });
      }
    }
    return [...options.values()].sort(
      (left, right) =>
        left.mount.name.localeCompare(right.mount.name) ||
        left.mount.mount_id.localeCompare(right.mount.mount_id),
    );
  }, [mountsByNode, nodes]);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    const timeout = window.setTimeout(() => {
      void api
        .policies(search)
        .then((result) => {
          if (!cancelled) setPolicies(result.items || []);
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

  async function reload(query = search) {
    const result = await api.policies(query);
    setPolicies(result.items || []);
  }

  function reset() {
    setEditingId("");
    setForm(emptyForm());
    setDirectNodeModes([true]);
  }

  function openCreateForm() {
    reset();
    setFormOpen(true);
  }

  function closeForm(open: boolean) {
    setFormOpen(open);
    if (!open) reset();
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
    setDirectNodeModes(policy.rules.map((rule) => isDirectNodePath(rule.path)));
    setFormOpen(true);
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
    setDirectNodeModes((prev) =>
      prev.map((mode, i) => (i === index ? isDirectNodePath(path) : mode)),
    );
  }

  function setRuleNode(index: number, nodeID: string) {
    setForm((prev) => ({
      ...prev,
      rules: prev.rules.map((rule, i) =>
        i === index ? { ...rule, path: withNodeSegment(rule.path, nodeID) } : rule,
      ),
    }));
  }

  function setRuleMount(index: number, nodeID: string, mountID: string) {
    setForm((prev) => ({
      ...prev,
      rules: prev.rules.map((rule, i) =>
        i === index
          ? { ...rule, path: withMountSegment(rule.path, nodeID, mountID) }
          : rule,
      ),
    }));
    setDirectNodeModes((prev) =>
      prev.map((mode, i) => (i === index ? false : mode)),
    );
  }

  function setDirectNodeMode(index: number, direct: boolean) {
    setDirectNodeModes((prev) =>
      prev.map((mode, i) => (i === index ? direct : mode)),
    );
    if (!direct) return;
    setForm((prev) => ({
      ...prev,
      rules: prev.rules.map((rule, i) =>
        i === index
          ? { ...rule, path: `nodes/${nodeSegment(rule.path) || "*"}` }
          : rule,
      ),
    }));
  }

  function addRule() {
    setForm((prev) => ({
      ...prev,
      rules: [...prev.rules, { path: "nodes/*", capabilities: ["read"] }],
    }));
    setDirectNodeModes((prev) => [...prev, true]);
  }

  function removeRule(index: number) {
    setForm((prev) =>
      prev.rules.length > 1
        ? { ...prev, rules: prev.rules.filter((_, i) => i !== index) }
        : prev,
    );
    setDirectNodeModes((prev) =>
      prev.length > 1 ? prev.filter((_, i) => i !== index) : prev,
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
      setFormOpen(false);
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
      setFormOpen(false);
      await reload();
      toast.success("Policy removida.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  if (inline && !open) return null;

  const searchInput = (
    <div className="grid gap-2">
      <Label htmlFor="policies-search">Buscar policies</Label>
      <Input
        id="policies-search"
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
              <DialogTitle>Node Path policies</DialogTitle>
            </div>
            <Button variant="secondary" size="sm" onClick={openCreateForm}>
              Nova policy
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
                <Table aria-label="Policies cadastradas">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Policy</TableHead>
                      <TableHead>Descrição</TableHead>
                      <TableHead>Regras</TableHead>
                      <TableHead className="text-right">Ação</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {policies.map((policy) => (
                      <TableRow
                        key={policy.policy_id}
                        data-state={
                          editingId === policy.policy_id ? "selected" : undefined
                        }
                      >
                        <TableCell className="font-medium">{policy.name}</TableCell>
                        <TableCell className="max-w-sm truncate text-muted-foreground">
                          {policy.description || "Sem descrição"}
                        </TableCell>
                        <TableCell>{policy.rules.length}</TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => edit(policy)}
                            >
                              Editar
                            </Button>
                            <Button
                              type="button"
                              variant="destructive"
                              size="sm"
                              onClick={() => void remove(policy)}
                            >
                              Remover
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                    {!policies.length && (
                      <TableRow>
                        <TableCell colSpan={4} className="text-muted-foreground">
                          {search
                            ? "Nenhuma policy encontrada."
                            : "Nenhuma policy cadastrada."}
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
                  {search ? "Nenhuma policy encontrada." : "Nenhuma policy cadastrada."}
                </div>
              )}
            </div>
          )}

          <AdminEntityDialog
            open={formOpen}
            onOpenChange={closeForm}
            title={editingId ? "Editar policy" : "Criar policy"}
          >
              <form className="grid gap-3" onSubmit={save}>
            <EntityDialogFormLayout
              summary={
                <>
            <div className="grid gap-2">
              <Label htmlFor="p-name">Nome</Label>
              <Input
                id="p-name"
                value={form.name}
                minLength={3}
                maxLength={64}
                pattern="[A-Za-z0-9._\-]+"
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
                </>
              }
            >

            <div className="grid gap-3">
              {form.rules.map((rule, index) => {
                const selectedNode = nodeSegment(rule.path);
                const selectedMount = mountSegment(rule.path);
                const directNode =
                  directNodeModes[index] ?? isDirectNodePath(rule.path);
                const mountOptions =
                  selectedNode && selectedNode !== "*"
                    ? (mountsByNode[selectedNode] || []).map((mount) => ({
                        mount,
                        availableOn: 1,
                      }))
                    : allMounts;
                const unknownNode =
                  selectedNode &&
                  selectedNode !== "*" &&
                  !nodes.some((node) => node.node_id === selectedNode);
                const unknownMount =
                  selectedMount &&
                  selectedMount !== "*" &&
                  !mountOptions.some(
                    (option) => option.mount.mount_id === selectedMount,
                  );

                return (
                  <article
                    key={index}
                    className="grid gap-2 rounded-md border p-3"
                  >
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
                    <div className="grid gap-2 sm:grid-cols-2">
                      <div className="grid gap-2">
                        <Label className="text-xs">Node</Label>
                        <Select
                          value={selectedNode}
                          onValueChange={(nodeID) => setRuleNode(index, nodeID)}
                        >
                          <SelectTrigger className="w-full" aria-label="Node">
                            <SelectValue placeholder="Selecione um node" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="*">Todos os nodes (*)</SelectItem>
                            {unknownNode && (
                              <SelectItem value={selectedNode}>
                                Node atual · {selectedNode}
                              </SelectItem>
                            )}
                            {nodes.map((node) => (
                              <SelectItem key={node.node_id} value={node.node_id}>
                                {node.name} · {node.node_id}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid gap-2">
                        <div className="flex items-center justify-between gap-2">
                          <Label className="text-xs">Mount</Label>
                          <Toggle
                            type="button"
                            variant="outline"
                            size="sm"
                            pressed={directNode}
                            onPressedChange={(pressed) =>
                              setDirectNodeMode(index, pressed)
                            }
                            aria-label="Permissão direta no node"
                          >
                            Direto no node
                          </Toggle>
                        </div>
                        <Select
                          value={selectedMount}
                          onValueChange={(mountID) =>
                            setRuleMount(index, selectedNode || "*", mountID)
                          }
                          disabled={mountsLoading || directNode}
                        >
                          <SelectTrigger className="w-full" aria-label="Mount">
                            <SelectValue
                              placeholder={
                                directNode
                                  ? "Permissão direta ativa"
                                  : mountsLoading
                                  ? "Carregando mounts…"
                                  : "Selecione um mount"
                              }
                            />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="*">Todos os mounts (*)</SelectItem>
                            {unknownMount && (
                              <SelectItem value={selectedMount}>
                                Mount atual · {selectedMount}
                              </SelectItem>
                            )}
                            {mountOptions.map(({ mount, availableOn }) => (
                              <SelectItem key={mount.mount_id} value={mount.mount_id}>
                                {mount.name} · {mount.mount_id}
                                {selectedNode === "*" && availableOn > 1
                                  ? ` · ${availableOn} nodes`
                                  : ""}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                    <div className="grid gap-2">
                      <Label className="text-xs">Node Path</Label>
                      <Input
                        value={rule.path}
                        placeholder="nodes/*/files/mounts/media"
                        required
                        onChange={(e) => setRulePath(index, e.target.value)}
                      />
                      <small className="text-muted-foreground">
                        {directNode
                          ? "As capabilities desta regra se aplicam apenas ao node selecionado."
                          : "Selecionar um mount cria acesso a arquivos quando o path ainda não contém um segmento de mount."}
                      </small>
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
                );
              })}
            </div>
            {mountLoadFailures > 0 && (
              <p className="text-xs text-muted-foreground" role="status">
                Não foi possível carregar os mounts de {mountLoadFailures}{" "}
                {mountLoadFailures === 1 ? "node" : "nodes"}. Você ainda pode
                editar o Node Path manualmente.
              </p>
            )}
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={addRule}
            >
              Adicionar regra
            </Button>

            <div className="flex justify-end gap-2">
              <Button type="submit" disabled={busy}>
                Salvar policy <ArrowRight />
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
