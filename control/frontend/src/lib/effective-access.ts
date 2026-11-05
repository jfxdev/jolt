import type { EffectiveCapability, EffectiveOutcome } from "./types.ts";

// The order columns appear in, the same as the server answers.
export const EFFECTIVE_CAPABILITIES = ["read", "list", "create", "update", "delete", "write", "execute", "sudo"] as const;

const LABELS: Record<EffectiveOutcome, string> = {
  allowed: "Permitido",
  denied: "Negado",
  hidden: "Oculto",
  blocked: "Bloqueado",
};

const MEANINGS: Record<EffectiveOutcome, string> = {
  allowed: "A operação é permitida.",
  denied: "Nenhuma regra concede a operação, ou uma regra por caminho a nega.",
  hidden: "Uma regra por tipo nega a operação e o arquivo some da listagem; o acesso direto responde 404.",
  blocked: "Uma regra por tipo nega a operação; o arquivo aparece, mas não pode ser usado (403).",
};

export function outcomeLabel(outcome: EffectiveOutcome): string {
  return LABELS[outcome];
}

/** The glyph shown in a cell; the label travels separately for screen readers. */
export function outcomeSymbol(outcome: EffectiveOutcome): string {
  return { allowed: "✓", denied: "✗", hidden: "◌", blocked: "🔒" }[outcome];
}

/**
 * explainCell is the tooltip of a cell: what the outcome means and which
 * policies decided it, by name when the name is known.
 */
export function explainCell(cell: EffectiveCapability, policyNames: Record<string, string>): string {
  const via = cell.policy_ids.map((id) => policyNames[id] ?? id);
  const origin = via.length ? ` Policies envolvidas: ${via.join(", ")}.` : "";
  const typed = cell.typed ? " Decidido por regra por tipo." : "";
  return `${LABELS[cell.outcome]}. ${MEANINGS[cell.outcome]}${typed}${origin}`;
}

/** A path with a node and mount filled in, for the first row of a new query. */
export function suggestPath(nodeId: string | undefined, mountId: string | undefined): string {
  if (!nodeId) return "nodes/*";
  return mountId ? `nodes/${nodeId}/files/mounts/${mountId}` : `nodes/${nodeId}`;
}

const REASONS: Record<string, string> = {
  node_not_in_group: "O node não pertence a nenhum grupo de acesso ativo desta conta.",
};

export function describeReason(reason: string | undefined): string {
  return reason ? (REASONS[reason] ?? reason) : "";
}
