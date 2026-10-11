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
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="min-w-72">Job</TableHead>
              <TableHead className="min-w-48">Progresso</TableHead>
              <TableHead className="min-w-44">Transferência</TableHead>
              <TableHead>Estado</TableHead>
              <TableHead className="min-w-44">Ações</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {jobs.slice(0, 8).map((job) => (
              <TableRow key={job.job_id}>
                <TableCell className="whitespace-normal">
                  <div className="flex min-w-64 items-start gap-3">
                    <span className="grid size-8 shrink-0 place-content-center rounded-md bg-muted">
                      {jobIcon(job.type)}
                    </span>
                    <div className="min-w-0">
                      <strong className="block text-sm">
                        {job.type.replaceAll("_", " ")}
                      </strong>
                      <small className="block truncate text-muted-foreground">
                        {job.destination_path || job.source_path || job.mount_id}
                      </small>
                      {job.error ? (
                        <small className="block text-destructive">{job.error}</small>
                      ) : null}
                    </div>
                  </div>
                </TableCell>
                <TableCell className="whitespace-normal">
                  {progressPercent(job) == null ? (
                    <span className="text-xs text-muted-foreground">—</span>
                  ) : (
                    <div className="grid min-w-40 gap-1.5 text-xs text-muted-foreground">
                      <div className="flex justify-between gap-3">
                        <span>{isRemoteTransfer(job) ? "Transferência" : "Operação"}</span>
                        <span>{Math.round(progressPercent(job)!)}%</span>
                      </div>
                      <Progress value={progressPercent(job)} />
                    </div>
                  )}
                </TableCell>
                <TableCell className="whitespace-normal">
                  <div className="grid min-w-36 gap-1 text-xs text-muted-foreground">
                    <span>
                      {formatBytes(job.bytes_completed)}
                      {job.bytes_total ? ` / ${formatBytes(job.bytes_total)}` : ""}
                    </span>
                    {job.bytes_per_second ? (
                      <span>{formatBytes(job.bytes_per_second)}/s</span>
                    ) : null}
                    {job.eta_seconds != null ? (
                      <span>ETA {formatETA(job.eta_seconds)} · {job.eta_confidence}</span>
                    ) : null}
                    {job.files_total ? (
                      <span>
                        {job.files_completed}/{job.files_total} arquivos
                        {job.files_failed ? ` · ${job.files_failed} falharam` : ""}
                      </span>
                    ) : null}
                  </div>
                </TableCell>
                <TableCell>
                  <Badge variant={stateVariant(job.state)}>{job.state}</Badge>
                </TableCell>
                <TableCell className="whitespace-normal">
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
                </TableCell>
              </TableRow>
            ))}
            {!jobs.length && (
              <TableRow>
                <TableCell
                  colSpan={5}
                  className="py-8 text-center text-sm text-muted-foreground"
                >
                  Nenhum job registrado.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      <ConflictDecisionDialog
        job={decisionJob}
        onClose={() => setDecisionJob(null)}
      />
    </section>
  );
}
