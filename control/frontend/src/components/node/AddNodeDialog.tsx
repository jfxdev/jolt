import { useState, type FormEvent } from "react";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import { useNodes } from "@/context/NodesContext";
import { useApiError } from "@/hooks/useApiError";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const EMPTY = { name: "", endpoint: "http://jolt-node:8080", token: "" };

export function AddNodeDialog({ open, onOpenChange }: Props) {
  const { loadNodes } = useNodes();
  const handleError = useApiError();
  const [form, setForm] = useState(EMPTY);
  const [saving, setSaving] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    try {
      await api.addNode(form);
      setForm(EMPTY);
      onOpenChange(false);
      await loadNodes();
      toast.success("Node conectado com sucesso.");
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
            Novo node
          </p>
          <DialogTitle>Conectar um node</DialogTitle>
          <DialogDescription>
            O token será criptografado antes de ser persistido.
          </DialogDescription>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={handleSubmit}>
          <div className="grid gap-2">
            <Label htmlFor="node-name">Nome amigável</Label>
            <Input
              id="node-name"
              value={form.name}
              placeholder="NAS da sala"
              required
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="node-endpoint">Endpoint</Label>
            <Input
              id="node-endpoint"
              type="url"
              value={form.endpoint}
              placeholder="http://192.168.1.10:8080"
              required
              onChange={(e) => setForm({ ...form, endpoint: e.target.value })}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="node-token">Token operacional</Label>
            <Input
              id="node-token"
              type="password"
              value={form.token}
              autoComplete="off"
              required
              onChange={(e) => setForm({ ...form, token: e.target.value })}
            />
          </div>
          <Button type="submit" disabled={saving}>
            Validar e conectar <ArrowRight />
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
}
