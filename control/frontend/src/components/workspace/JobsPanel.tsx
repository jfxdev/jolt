import { useState } from "react";
import { api } from "@/lib/api";
import type { Job } from "@/lib/types";
import { useWorkspace } from "@/context/WorkspaceContext";
import { usePermissions } from "@/context/PermissionsContext";
import { useApiError } from "@/hooks/useApiError";
import { formatBytes, formatETA } from "@/lib/format";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { ConflictDecisionDialog } from "@/components/workspace/ConflictDecisionDialog";

const CONTROL_LABELS: Record<string, string> = {
  pause: "Pausa solicitada.",
  resume: "Job retomado.",
  cancel: "Cancelamento solicitado.",
  retry: "Nova tentativa enfileirada.",
};

const ACTIVE_STATES = new Set([
  "queued",
  "running",
  "paused",
  "interrupted",
  "waiting_validation",
  "waiting_mount",
  "waiting_peer",
  "pause_requested",
]);

function jobIcon(type: string) {
  if (type.includes("upload")) return "↑";
  if (type.includes("delete")) return "×";
  return "→";
}

function stateVariant(
  state: string,
): "default" | "secondary" | "destructive" | "success" | "warning" {
  if (["completed"].includes(state)) return "success";
  if (["failed", "canceled"].includes(state)) return "destructive";
  if (["completed_with_warnings", "waiting_user_decision"].includes(state))
    return "warning";
  if (["running", "queued"].includes(state)) return "default";
  return "secondary";
}

function isRemoteTransfer(job: Job) {
  return job.type === "transfer_pull" || job.type === "transfer_pull_directory";
}

function progressPercent(job: Job) {
  if (!job.bytes_total || job.bytes_total <= 0) return null;
  return Math.min(100, Math.max(0, ((job.bytes_completed || 0) / job.bytes_total) * 100));
}

export function JobsPanel() {
  const { nodeId, jobs, nodePath, refreshJobs } = useWorkspace();
  const { hasPermission } = usePermissions();
  const handleError = useApiError();
  const [decisionJob, setDecisionJob] = useState<Job | null>(null);

  const canControl = (job: Job) =>
    hasPermission(nodePath(`jobs/${job.job_id}`), "execute");

  async function control(job: Job, action: string) {
    try {
      await api.controlJob(nodeId, job.job_id, action);
      await refreshJobs();
      toast.success(CONTROL_LABELS[action]);
    } catch (error) {
      handleError(error);
    }
  }

  return (
    <section className="grid gap-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Atividade
          </p>
          <h2 className="text-lg font-semibold">Jobs recentes</h2>
        </div>
        <Button variant="ghost" size="sm" onClick={() => refreshJobs()}>
          Atualizar
        </Button>
      </div>

      <div className="grid gap-2">
        {jobs.slice(0, 8).map((job) => (
          <Card
            key={job.job_id}
            className="flex flex-wrap items-center gap-4 p-4"
          >
            <span className="grid h-8 w-8 place-content-center rounded-md bg-muted">
              {jobIcon(job.type)}
            </span>
            <div className="min-w-0 flex-1">
              <strong className="block text-sm">
                {job.type.replaceAll("_", " ")}
              </strong>
              <small className="block truncate text-muted-foreground">
                {job.destination_path || job.source_path || job.mount_id}
              </small>
              {job.error ? (
                <small className="block text-destructive">{job.error}</small>
              ) : null}
              {isRemoteTransfer(job) && (
                <div className="mt-3 grid gap-1.5">
                  <div className="flex justify-between gap-3 text-xs text-muted-foreground">
                    <span>Progresso da transferência</span>
                    <span>
                      {progressPercent(job) == null
                        ? "Preparando…"
                        : `${Math.round(progressPercent(job)!)}%`}
                    </span>
                  </div>
                  <Progress value={progressPercent(job) ?? 0} />
                </div>
              )}
            </div>
            <span className="text-right text-xs text-muted-foreground">
              {formatBytes(job.bytes_completed)}
              {job.bytes_total ? ` / ${formatBytes(job.bytes_total)}` : ""}
              {job.bytes_per_second ? (
                <small className="block">
                  {formatBytes(job.bytes_per_second)}/s
                </small>
              ) : null}
              {job.eta_seconds != null ? (
                <small className="block">
                  ETA {formatETA(job.eta_seconds)} · {job.eta_confidence}
                </small>
              ) : null}
              {job.files_total ? (
                <small className="block">
                  {job.files_completed}/{job.files_total} arquivos
                  {job.files_failed ? ` · ${job.files_failed} falharam` : ""}
                </small>
              ) : null}
            </span>
            <Badge variant={stateVariant(job.state)}>{job.state}</Badge>
            <div className="flex flex-wrap gap-1">
              {canControl(job) &&
                ["queued", "running"].includes(job.state) && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => control(job, "pause")}
                  >
                    Pausar
                  </Button>
                )}
              {canControl(job) &&
                ["paused", "interrupted", "waiting_validation"].includes(
                  job.state,
                ) && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => control(job, "resume")}
                  >
                    Validar e retomar
                  </Button>
                )}
              {canControl(job) && ACTIVE_STATES.has(job.state) && (
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => control(job, "cancel")}
                >
                  Cancelar
                </Button>
              )}
              {canControl(job) &&
                ["failed", "completed_with_warnings"].includes(job.state) && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => control(job, "retry")}
                  >
                    Tentar novamente
                  </Button>
                )}
              {hasPermission(nodePath(`jobs/${job.job_id}`), "update") &&
                job.state === "waiting_user_decision" && (
                  <Button size="sm" onClick={() => setDecisionJob(job)}>
                    Resolver conflito
                  </Button>
                )}
            </div>
          </Card>
        ))}
        {!jobs.length && (
          <p className="py-6 text-sm text-muted-foreground">
            Nenhum job registrado.
          </p>
        )}
      </div>

      <ConflictDecisionDialog
        job={decisionJob}
        onClose={() => setDecisionJob(null)}
      />
    </section>
  );
}
