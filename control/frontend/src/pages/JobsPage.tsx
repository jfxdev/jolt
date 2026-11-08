import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronLeft, ChevronRight, RefreshCw } from "lucide-react";
import { api } from "@/lib/api";
import { formatBytes, formatDate } from "@/lib/format";
import {
  mergeNetworkJobs,
  pageCount,
  pageSlice,
  type NodeJobs,
} from "@/lib/jobs-list";
import { useNodes } from "@/context/NodesContext";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const PAGE_SIZE = 20;
// The node returns at most 500 jobs per request, newest first.
const NODE_JOB_LIMIT = 500;
// A node that accepts the connection but never answers must not hold back the
// jobs of the others: its request is aborted and reported as unavailable.
const NODE_REQUEST_TIMEOUT_MS = 15_000;

function stateVariant(
  state: string,
): "default" | "secondary" | "destructive" | "success" | "warning" {
  if (state === "completed") return "success";
  if (["failed", "canceled"].includes(state)) return "destructive";
  if (["completed_with_warnings", "waiting_user_decision"].includes(state))
    return "warning";
  if (["running", "queued"].includes(state)) return "default";
  return "secondary";
}

function progressPercent(bytesCompleted = 0, bytesTotal = 0) {
  if (bytesTotal <= 0) return null;
  return Math.min(100, Math.max(0, (bytesCompleted / bytesTotal) * 100));
}

export default function JobsPage() {
  const { nodes } = useNodes();
  const [results, setResults] = useState<NodeJobs[]>([]);
  const [failed, setFailed] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [page, setPage] = useState(1);

  // Only the latest load may write state: a slower, superseded load must not
  // overwrite newer results or clear the loading flag early.
  const latestLoad = useRef(0);

  const load = useCallback(async () => {
    const id = ++latestLoad.current;
    setLoading(true);
    const settled = await Promise.allSettled(
      nodes.map((node) =>
        api.jobs(
          node.node_id,
          NODE_JOB_LIMIT,
          AbortSignal.timeout(NODE_REQUEST_TIMEOUT_MS),
        ),
      ),
    );
    if (id !== latestLoad.current) return;
    const next: NodeJobs[] = [];
    const unavailable: string[] = [];
    settled.forEach((outcome, index) => {
      if (outcome.status === "fulfilled")
        next.push({ node: nodes[index], jobs: outcome.value.items || [] });
      else unavailable.push(nodes[index].name);
    });
    setResults(next);
    setFailed(unavailable);
    setLoaded(true);
    setLoading(false);
  }, [nodes]);

  useEffect(() => {
    if (nodes.length) void load();
  }, [nodes.length, load]);

  const jobs = useMemo(() => mergeNetworkJobs(results), [results]);
  const pages = pageCount(jobs.length, PAGE_SIZE);
  const current = Math.min(page, pages);
  // Keep the clamped page: if the list shrinks (a node failed) and grows back on
  // a later refresh, the view must not jump back to the old page.
  useEffect(() => {
    if (page > pages) setPage(pages);
  }, [page, pages]);
  const visible = pageSlice(jobs, current, PAGE_SIZE);
  const first = jobs.length ? (current - 1) * PAGE_SIZE + 1 : 0;

  return (
    <section className="grid gap-4 p-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Atividade
          </p>
          <h1 className="text-xl font-semibold">Jobs</h1>
          <p className="text-sm text-muted-foreground">
            Jobs de todos os nodes, do mais recente para o mais antigo.
          </p>
        </div>
        <Button
          variant="ghost"
          size="sm"
          disabled={loading}
          onClick={() => void load()}
        >
          <RefreshCw className={loading ? "animate-spin" : undefined} />
          Atualizar
        </Button>
      </div>

      {failed.length > 0 && (
        <Alert variant="destructive">
          <AlertDescription>
            Não foi possível carregar os jobs de: {failed.join(", ")}.
          </AlertDescription>
        </Alert>
      )}

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="min-w-64">Job</TableHead>
              <TableHead>Node</TableHead>
              <TableHead className="min-w-44">Progresso</TableHead>
              <TableHead>Estado</TableHead>
              <TableHead className="min-w-36">Criado em</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {visible.map(({ node, job }) => {
              const percent = progressPercent(
                job.bytes_completed,
                job.bytes_total,
              );
              return (
                <TableRow key={`${node.node_id}:${job.job_id}`}>
                  <TableCell className="whitespace-normal">
                    <div className="min-w-0">
                      <strong className="block text-sm">
                        {job.type.replaceAll("_", " ")}
                      </strong>
                      <small className="block max-w-96 truncate text-muted-foreground">
                        {job.destination_path ||
                          job.source_path ||
                          job.mount_id}
                      </small>
                      {job.error ? (
                        <small className="block text-destructive">
                          {job.error}
                        </small>
                      ) : null}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Link
                      to={`/nodes/${node.node_id}`}
                      className="text-sm hover:underline"
                    >
                      {node.name}
                    </Link>
                  </TableCell>
                  <TableCell className="whitespace-normal">
                    {percent == null ? (
                      <span className="text-xs text-muted-foreground">—</span>
                    ) : (
                      <div className="grid min-w-40 gap-1.5 text-xs text-muted-foreground">
                        <div className="flex justify-between gap-3">
                          <span>
                            {formatBytes(job.bytes_completed)} /{" "}
                            {formatBytes(job.bytes_total)}
                          </span>
                          <span>{Math.round(percent)}%</span>
                        </div>
                        <Progress value={percent} />
                      </div>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge variant={stateVariant(job.state)}>{job.state}</Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {job.created_at ? formatDate(job.created_at) : "—"}
                  </TableCell>
                </TableRow>
              );
            })}
            {!visible.length && (
              <TableRow>
                <TableCell
                  colSpan={5}
                  className="py-8 text-center text-sm text-muted-foreground"
                >
                  {loaded ? "Nenhum job registrado." : "Carregando jobs…"}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-between gap-3 text-sm text-muted-foreground">
        <span>
          {jobs.length
            ? `${first}–${first + visible.length - 1} de ${jobs.length}`
            : "0 jobs"}
        </span>
        <div className="flex items-center gap-2">
          <span>
            Página {current} de {pages}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={current <= 1}
            onClick={() => setPage(current - 1)}
          >
            <ChevronLeft />
            Anterior
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={current >= pages}
            onClick={() => setPage(current + 1)}
          >
            Próxima
            <ChevronRight />
          </Button>
        </div>
      </div>
    </section>
  );
}
