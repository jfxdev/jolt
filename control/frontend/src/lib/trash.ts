import type { Mount, TrashEntry } from "./types.ts";

/** Days a deleted entry is kept on this mount, or 0 when deleting is permanent. */
export function trashDays(mount: Pick<Mount, "trash"> | null | undefined): number {
  return mount?.trash?.enabled ? mount.trash.retention_days : 0;
}

/** What the confirmation says before a delete, so nobody assumes it is permanent or recoverable. */
export function removeDescription(mount: Pick<Mount, "trash"> | null | undefined): string | undefined {
  const days = trashDays(mount);
  return days
    ? `Vai para a lixeira e pode ser restaurado por ${days} ${days === 1 ? "dia" : "dias"}.`
    : "Esta ação não pode ser desfeita.";
}

/** The toast after a delete was accepted. */
export function removedNotice(mount: Pick<Mount, "trash"> | null | undefined): string {
  return trashDays(mount) ? "Item enviado para a lixeira." : "Item removido.";
}

/** Time left before the node purges an entry, as "29 dias", "5 h" or "expirando". */
export function remainingRetention(expiresAt: string, now: number): string {
  const ms = Date.parse(expiresAt) - now;
  if (!Number.isFinite(ms) || ms <= 0) return "expirando";
  const hours = Math.floor(ms / 3_600_000);
  if (hours >= 48) return `${Math.floor(hours / 24)} dias`;
  if (hours >= 1) return `${hours} h`;
  return "menos de 1 h";
}

export function entryName(entry: Pick<TrashEntry, "path">): string {
  const index = entry.path.lastIndexOf("/");
  return index < 0 ? entry.path : entry.path.slice(index + 1);
}

export function entryFolder(entry: Pick<TrashEntry, "path">): string {
  const index = entry.path.lastIndexOf("/");
  return index < 0 ? "/" : `/${entry.path.slice(0, index)}`;
}

const RESTORE_ERRORS: Record<string, string> = {
  conflict: "Já existe algo com o nome original. Renomeie ou remova antes de restaurar.",
  trash_not_found: "A entrada não existe mais, ou a pasta onde ela estava foi removida. Recrie a pasta e tente de novo.",
  hidden_name: "O nome original agora é oculto por configuração do mount.",
  mount_read_only: "O mount não permite alterações.",
  node_upgrade_required: "Atualize o node para usar a lixeira.",
};

/** A sentence for a failed restore, or undefined to fall back to the server's message. */
export function restoreErrorMessage(code: string | undefined): string | undefined {
  return code ? RESTORE_ERRORS[code] : undefined;
}
