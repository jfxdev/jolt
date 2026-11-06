import { formatBytes } from "./format.ts";
import type { PendingApprovalNotice, PendingOperation, PendingState } from "./types.ts";

/** Recognises the 202 a file operation answers when a policy wants an approval. */
export function asPendingApproval(value: unknown): PendingApprovalNotice | null {
  if (!value || typeof value !== "object") return null;
  const candidate = value as Partial<PendingApprovalNotice>;
  return candidate.state === "pending_approval" && typeof candidate.pending_operation_id === "string"
    ? (candidate as PendingApprovalNotice)
    : null;
}

const OPERATIONS: Record<string, string> = { delete: "Apagar", move: "Mover", copy: "Copiar" };

/** True when the person's software, not a person, asked. */
export function askedByAgent(op: Pick<PendingOperation, "summary">): boolean {
  return op.summary.requester_kind === "agent";
}

export function operationLabel(operation: string | undefined): string {
  return (operation && OPERATIONS[operation]) || "Operação";
}

/** One line that says what is being asked, with the names the approver must see. */
export function describePending(op: Pick<PendingOperation, "summary">): string {
  const paths = op.summary.paths ?? [];
  const label = operationLabel(op.summary.operation);
  const mount = op.summary.mount_id ? ` no mount ${op.summary.mount_id}` : "";
  const tree = op.summary.tree ? ` — ${treeSize(op.summary)}` : op.summary.destination ? ` — ${transferSize(op.summary)}` : "";
  if (op.summary.destination) {
    const from = op.summary.source_node ? `${op.summary.source_node}:${op.summary.mount_id ?? ""}` : (op.summary.mount_id ?? "");
    return `${label} ${paths.join(", ")} de ${from} para ${op.summary.destination}${tree}`;
  }
  if (!paths.length) return `${label}${mount}${tree}`;
  if (op.summary.operation === "move" || op.summary.operation === "copy") {
    const [source, destination] = [paths.find((p) => p) ?? "", paths[paths.length - 1]];
    return `${label} ${source} para ${destination}${mount}${tree}`;
  }
  return `${label} ${paths.join(", ")}${mount}${tree}`;
}

/** What a transfer between nodes would move, in words. */
export function transferSize(summary: Pick<PendingOperation["summary"], "files" | "bytes">): string {
  const files = summary.files ?? 0;
  return `${files} ${files === 1 ? "arquivo" : "arquivos"} (${formatBytes(summary.bytes ?? 0)})`;
}

/** The size of a folder the approver is asked about, in words. */
export function treeSize(summary: Pick<PendingOperation["summary"], "files" | "directories" | "bytes">): string {
  const count = (value: number, one: string, many: string) => `${value} ${value === 1 ? one : many}`;
  return `${count(summary.files ?? 0, "arquivo", "arquivos")} em ${count(summary.directories ?? 0, "pasta", "pastas")} (${formatBytes(summary.bytes ?? 0)})`;
}

const STATES: Record<PendingState, string> = {
  pending: "Aguardando",
  executing: "Executando",
  executed: "Executado",
  failed: "Falhou",
  rejected: "Rejeitado",
  expired: "Expirado",
  indeterminate: "Indeterminado",
};

export function stateLabel(state: PendingState): string {
  return STATES[state] ?? state;
}

/** Time left to decide, as "4 min 10 s", or "expirado". */
export function remainingLabel(expiresAt: string, now: number): string {
  const seconds = Math.floor((Date.parse(expiresAt) - now) / 1000);
  if (!Number.isFinite(seconds) || seconds <= 0) return "expirado";
  return seconds >= 60 ? `${Math.floor(seconds / 60)} min ${String(seconds % 60).padStart(2, "0")} s` : `${seconds} s`;
}

/** The toast a requester sees after asking for something that needs approval. */
export function pendingToast(notice: PendingApprovalNotice, now = Date.now()): string {
  // A folder plan counts directories too; a transfer between nodes does not.
  const size = notice.directories === undefined ? transferSize : treeSize;
  const tree = notice.files === undefined ? "" : ` ${size(notice)}`;
  return `${operationLabel(notice.operation)}${tree} aguardando aprovação de uma pessoa (${remainingLabel(notice.expires_at, now)} para decidir).`;
}

/** What an approver is told about the outcome of the replay. */
export function decisionMessage(status: number, replayed: boolean | undefined): string {
  if (replayed) return "Este pedido já tinha sido decidido; o resultado não foi executado de novo.";
  if (status >= 200 && status < 300) return "Aprovado e executado.";
  if (status === 403) return "Aprovado, mas você não tem permissão para executar esta operação. Nada foi alterado.";
  return `Aprovado, mas a operação respondeu ${status}. Confira antes de pedir de novo.`;
}
