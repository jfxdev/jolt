import { formatBytes } from "./format.ts";

// What the node reports for a delete or move of a directory tree, and what the
// operator confirms before it runs.
export interface DestructivePlan {
  plan_id: string;
  token: string;
  expires_at: string;
  operation: "delete" | "move";
  mount_id: string;
  source_path: string;
  destination_path?: string;
  overwrite?: boolean;
  files: number;
  directories: number;
  bytes: number;
  destination_exists?: boolean;
  destination_files?: number;
  destination_bytes?: number;
}

function plural(count: number, singular: string, many: string): string {
  return `${count} ${count === 1 ? singular : many}`;
}

// destructivePlanDescription spells out exactly what will be lost, so the
// confirmation is about this tree and not a generic "are you sure".
export function destructivePlanDescription(plan: DestructivePlan): string {
  const tree = `${plural(plan.files, "arquivo", "arquivos")} em ${plural(plan.directories, "pasta", "pastas")} (${formatBytes(plan.bytes)})`;
  const parts =
    plan.operation === "delete"
      ? [`Serão removidos permanentemente ${tree}.`]
      : [`Serão movidos ${tree}.`];
  if (plan.operation === "move" && plan.destination_exists) {
    parts.push(
      `O destino existente, com ${plural(plan.destination_files ?? 0, "arquivo", "arquivos")} (${formatBytes(plan.destination_bytes ?? 0)}), será substituído e não poderá ser recuperado.`,
    );
  }
  parts.push("Se algo mudar nessa pasta antes da execução, a operação é cancelada e nada é alterado.");
  return parts.join(" ");
}

// planUnavailable is true when the Control Tower does not offer destructive
// plans (the feature is off), so the direct route still applies.
export function planUnavailable(error: { code?: string; status?: number } | null | undefined): boolean {
  return error?.code === "resource_not_found" && error?.status === 404;
}

// planRequired is true when the direct route refused a directory.
export function planRequired(error: { code?: string } | null | undefined): boolean {
  return error?.code === "plan_required";
}
