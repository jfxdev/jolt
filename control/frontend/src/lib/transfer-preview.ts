import type { FileEntry, LogicalTransferRequest, TransferPlan } from "./types";

export interface TransferPreviewEntry {
  key: string;
  name: string;
  originalName: string;
  path: string;
  type: FileEntry["type"];
  size?: number;
  action?: string;
}

function basename(path: string): string {
  return path.replaceAll("\\", "/").split("/").filter(Boolean).pop() || "";
}

export function transferDestinationFolder(value: string): string | null {
  const parts: string[] = [];
  const destination = value.trim().replaceAll("\\", "/");
  if (destination.startsWith("/")) return null;
  for (const part of destination.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") {
      if (!parts.length) return null;
      parts.pop();
    } else parts.push(part);
  }
  return parts.join("/");
}

/** An estimate before planning; server paths and actions are authoritative afterward. */
export function transferPreviewEntries(entries: FileEntry[], destinationPath: string, plan: TransferPlan | null): TransferPreviewEntry[] {
  if (plan) return (plan.items || []).map((item) => {
    const path = item.destination_path || "";
    const name = basename(path);
    return {
      key: `plan-${item.ordinal}`,
      name,
      originalName: basename(item.source_path || "") || name,
      path,
      type: item.type === "directory" ? "directory" : "file",
      size: typeof item.size === "number" ? item.size : undefined,
      action: item.action,
    };
  });

  const folder = transferDestinationFolder(destinationPath);
  if (folder === null) return [];
  return entries.map((entry) => {
    const name = basename(entry.path) || entry.name;
    return {
      key: `selection-${entry.path}`,
      name,
      originalName: entry.name || name,
      path: [folder, name].filter(Boolean).join("/"),
      type: entry.type,
      size: entry.size,
    };
  });
}

/** A line telling the operator that some source entries will not be copied. */
export function omittedSourcesNotice(plan: TransferPlan | null): string {
  const omitted = plan?.sources_omitted ?? 0;
  if (!Number.isInteger(omitted) || omitted <= 0) return "";
  const noun = omitted === 1 ? "entrada da origem não está acessível" : "entradas da origem não estão acessíveis";
  return `${omitted} ${noun} para você e ${omitted === 1 ? "não será copiada" : "não serão copiadas"}.`;
}

/** A move deletes its source once the copy is verified, so say it before confirming. */
export function moveNotice(operation: "copy" | "move", plan: TransferPlan | null): string {
  if (operation !== "move" || !plan) return "";
  return "Os itens de origem serão apagados depois que a cópia for verificada. Esta confirmação vale por 5 minutos.";
}

/** The creation request of a previewed transfer; a move carries its one-use confirmation. */
export function withMovePlan(request: LogicalTransferRequest, plan: TransferPlan | null): LogicalTransferRequest | null {
  if (request.operation !== "move") return request;
  if (!plan?.move_plan?.plan_id || !plan.move_plan.token) return null;
  return { ...request, move_plan: { plan_id: plan.move_plan.plan_id, token: plan.move_plan.token } };
}
