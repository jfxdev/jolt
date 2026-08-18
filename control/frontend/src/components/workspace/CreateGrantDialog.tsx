import { useEffect, useState, type FormEvent } from "react";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import type { GrantDirection, GrantPermissions } from "@/lib/types";
import { useWorkspace } from "@/context/WorkspaceContext";
import { useApiError } from "@/hooks/useApiError";
import { activePeers } from "@/lib/peers";
import { toast } from "sonner";
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
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface GrantForm {
  peer_node_id: string;
  mount_id: string;
  path: string;
  direction: GrantDirection;
  permissions: GrantPermissions;
  conflict_policies: string[];
  visible_to_peer: boolean;
  enabled: boolean;
}

const CONFLICT_OPTIONS = [
  { value: "fail", label: "Falhar" },
  { value: "skip", label: "Pular" },
  { value: "overwrite", label: "Sobrescrever" },
  { value: "rename", label: "Renomear" },
  { value: "ask", label: "Perguntar" },
  { value: "checksum", label: "Checksum" },
];

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function CreateGrantDialog({ open, onOpenChange }: Props) {
  const { nodeId, mounts, peers, refreshPairing } = useWorkspace();
  const handleError = useApiError();
  const trusted = activePeers(peers);
  const [form, setForm] = useState<GrantForm>(defaultForm());
  const [saving, setSaving] = useState(false);

  function defaultForm(): GrantForm {
    return {
      peer_node_id: "",
      mount_id: "",
      path: "",
      direction: "receive",
      permissions: { read: true, write: true, delete: false, rename: true },
      conflict_policies: ["fail"],
      visible_to_peer: true,
      enabled: true,
    };
  }

  useEffect(() => {
    if (!open) return;
    setForm({
      ...defaultForm(),
      peer_node_id: trusted[0]?.node_id || "",
      mount_id: mounts[0]?.mount_id || "",
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  function changeDirection(direction: GrantDirection) {
    setForm((prev) => {
      if (direction === "send")
        return {
          ...prev,
          direction,
          permissions: {
            read: true,
            write: false,
            delete: false,
            rename: false,
          },
          conflict_policies: [],
        };
      if (direction === "receive")
        return {
          ...prev,
          direction,
          permissions: { ...prev.permissions, write: true },
          conflict_policies: ["fail"],
        };
      return {
        ...prev,
        direction,
        permissions: { ...prev.permissions, read: true, write: true },
        conflict_policies: ["fail"],
      };
    });
  }

  function setPermission(key: keyof GrantPermissions, value: boolean) {
    setForm((prev) => ({
      ...prev,
      permissions: { ...prev.permissions, [key]: value },
    }));
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    try {
      await api.createGrant(nodeId, form);
      onOpenChange(false);
      await refreshPairing();
      toast.success("Grant criado no node proprietário do mount.");
    } catch (error) {
      handleError(error);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Autorização explícita
          </p>
          <DialogTitle>Novo Transfer Path Grant</DialogTitle>
          <DialogDescription>
            O grant pertence a este node e só pode referenciar um peer confiável
            e um mount já cadastrado.
          </DialogDescription>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={handleSubmit}>
          <div className="grid gap-2">
            <Label>Peer</Label>
            <Select
              value={form.peer_node_id}
              onValueChange={(v) => setForm({ ...form, peer_node_id: v })}
            >
              <SelectTrigger>
                <SelectValue placeholder="Selecione um peer" />
              </SelectTrigger>
              <SelectContent>
                {trusted.map((peer) => (
                  <SelectItem key={peer.node_id} value={peer.node_id}>
                    {peer.name} · {peer.fingerprint}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label>Mount</Label>
            <Select
              value={form.mount_id}
              onValueChange={(v) => setForm({ ...form, mount_id: v })}
            >
              <SelectTrigger>
                <SelectValue placeholder="Selecione um mount" />
              </SelectTrigger>
              <SelectContent>
                {mounts.map((mount) => (
                  <SelectItem key={mount.mount_id} value={mount.mount_id}>
                    {mount.name} · {mount.mode}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="grant-path">Subdiretório relativo</Label>
            <Input
              id="grant-path"
              value={form.path}
              placeholder="Vazio para todo o mount"
              onChange={(e) => setForm({ ...form, path: e.target.value })}
            />
          </div>
          <div className="grid gap-2">
            <Label>Direção</Label>
            <Select
              value={form.direction}
              onValueChange={(v) => changeDirection(v as GrantDirection)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="send">Enviar</SelectItem>
                <SelectItem value="receive">Receber</SelectItem>
                <SelectItem value="send_receive">Enviar e receber</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="grid grid-cols-2 gap-2">
            {(
              [
                ["read", "Leitura"],
                ["write", "Escrita"],
                ["rename", "Renomear"],
                ["delete", "Remover"],
              ] as [keyof GrantPermissions, string][]
            ).map(([key, label]) => (
              <label key={key} className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={form.permissions[key]}
                  onCheckedChange={(v) => setPermission(key, v === true)}
                />
                {label}
              </label>
            ))}
          </div>
          {form.direction !== "send" && (
            <div className="grid gap-2">
              <Label>Política de conflito permitida</Label>
              <Select
                value={form.conflict_policies[0] || ""}
                onValueChange={(v) =>
                  setForm({ ...form, conflict_policies: [v] })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CONFLICT_OPTIONS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          <label className="flex items-center gap-2 text-sm">
            <Checkbox
              checked={form.visible_to_peer}
              onCheckedChange={(v) =>
                setForm({ ...form, visible_to_peer: v === true })
              }
            />
            Visível para o peer
          </label>
          <Button type="submit" disabled={saving}>
            Criar grant <ArrowRight />
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
}
