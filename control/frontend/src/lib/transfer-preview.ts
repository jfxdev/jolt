import type { FileEntry, TransferPlan } from "./types";

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
