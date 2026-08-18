import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Job, JobItem } from "@/lib/types";
import { useWorkspace } from "@/context/WorkspaceContext";
import { useApiError } from "@/hooks/useApiError";
import { toast } from "sonner";
import { ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
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

const ACTIONS = [
  { value: "overwrite", label: "Sobrescrever" },
  { value: "skip", label: "Pular" },
  { value: "rename", label: "Renomear a cópia" },
  { value: "fail", label: "Marcar como falha" },
];

interface Props {
  job: Job | null;
  onClose: () => void;
}

export function ConflictDecisionDialog({ job, onClose }: Props) {
  const { nodeId, refreshJobs } = useWorkspace();
  const handleError = useApiError();
  const [items, setItems] = useState<JobItem[]>([]);
  const [action, setAction] = useState("overwrite");
  const [applyToFollowing, setApplyToFollowing] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!job) {
      setItems([]);
      return;
    }
    let active = true;
    setAction("overwrite");
    setApplyToFollowing(false);
    (async () => {
      try {
        const result = await api.jobItems(nodeId, job.job_id);
        if (active)
          setItems((result.items || []).filter((i) => i.action === "conflict"));
      } catch (error) {
        if (active) handleError(error);
      }
    })();
    return () => {
      active = false;
    };
  }, [job, nodeId, handleError]);

  async function apply() {
    const item = items[0];
    if (!job || !item) return;
    setBusy(true);
    try {
      const updated = await api.overrideJobItem(nodeId, job.job_id, item.ordinal, {
        action,
        apply_to_following: applyToFollowing,
      });
      if (updated.state === "waiting_user_decision") {
        const result = await api.jobItems(nodeId, updated.job_id);
        setItems((result.items || []).filter((i) => i.action === "conflict"));
      } else {
        onClose();
      }
      await refreshJobs();
      toast.success(
        updated.state === "queued"
          ? "Decisão aplicada; job retomado."
          : "Decisão aplicada ao item.",
      );
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={job !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Decisão necessária
          </p>
          <DialogTitle>Resolver conflito</DialogTitle>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            apply();
          }}
        >
          {items[0] ? (
            <p className="text-sm text-muted-foreground">
              O destino <strong>{items[0].destination_path}</strong> já existe.
              Restam {items.length} conflito(s) sem decisão.
            </p>
          ) : null}
          <div className="grid gap-2">
            <Label>Ação</Label>
            <Select value={action} onValueChange={setAction}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ACTIONS.map((a) => (
                  <SelectItem key={a.value} value={a.value}>
                    {a.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <Checkbox
              checked={applyToFollowing}
              onCheckedChange={(v) => setApplyToFollowing(v === true)}
            />
            Aplicar aos conflitos seguintes deste job
          </label>
          <Button type="submit" disabled={busy || !items.length}>
            Aplicar decisão <ArrowRight />
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
}
