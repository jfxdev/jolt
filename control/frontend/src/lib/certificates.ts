import type { CertificateItem, CertificateKind, NodeCertificate, RootRotation } from "./types.ts";

const DAY = 24 * 60 * 60 * 1000;

const KINDS: Record<CertificateKind, string> = {
  root: "Raiz",
  intermediate: "Intermediária",
  https: "Certificado HTTPS",
  client: "Certificado de cliente",
  signing_key: "Chave de assinatura",
};

const STATES: Record<CertificateItem["state"], string> = {
  active: "Em uso",
  pending: "Publicada, ainda não assina",
  retired: "Em despedida",
  next: "Raiz nova, ainda não assina",
};

export function kindLabel(kind: CertificateKind): string {
  return KINDS[kind] ?? kind;
}

export function stateLabel(state: CertificateItem["state"]): string {
  return STATES[state] ?? state;
}

/** Whole days left, never negative; "0" means it ends today or has ended. */
export function daysLeft(notAfter: string, now: number): number {
  const left = Date.parse(notAfter) - now;
  return Number.isFinite(left) ? Math.max(0, Math.floor(left / DAY)) : 0;
}

export type Tone = "ok" | "warning" | "critical" | "neutral";

// How early each kind should draw attention. A root or an intermediate is
// renewed rarely and by a person if its key was taken out, so it warns early.
const WARN_DAYS: Record<CertificateKind, number> = { root: 365, intermediate: 60, https: 14, client: 14, signing_key: 14 };
const CRITICAL_DAYS: Record<CertificateKind, number> = { root: 90, intermediate: 14, https: 2, client: 2, signing_key: 2 };

/** What an entry's date should look like. Only what is in use matters: a retired one is meant to end. */
export function expiryTone(item: CertificateItem, now: number): Tone {
  if (item.state !== "active") return "neutral";
  const left = Date.parse(item.not_after) - now;
  if (!Number.isFinite(left) || left <= 0) return "critical";
  const days = left / DAY;
  if (days <= CRITICAL_DAYS[item.kind]) return "critical";
  if (days <= WARN_DAYS[item.kind]) return "warning";
  return "ok";
}

export function expiryLabel(item: CertificateItem, now: number): string {
  const left = Date.parse(item.not_after) - now;
  if (!Number.isFinite(left) || left <= 0) return "Expirado";
  const days = daysLeft(item.not_after, now);
  if (days >= 1) return days === 1 ? "1 dia" : `${days} dias`;
  const hours = Math.max(1, Math.floor(left / (60 * 60 * 1000)));
  return hours === 1 ? "1 hora" : `${hours} horas`;
}

const ORDER: Record<CertificateKind, number> = { root: 0, intermediate: 1, https: 2, client: 3, signing_key: 4 };
const STATE_ORDER: Record<CertificateItem["state"], number> = { active: 0, next: 1, pending: 2, retired: 3 };

/** Root first, then the issuers, then what they issued; what is in use before what is leaving. */
export function sortCertificates(items: CertificateItem[]): CertificateItem[] {
  return [...items].sort(
    (a, b) => ORDER[a.kind] - ORDER[b.kind] || STATE_ORDER[a.state] - STATE_ORDER[b.state] || a.not_before.localeCompare(b.not_before),
  );
}

/** The start of a fingerprint, enough to recognise it in a list. */
export function shortFingerprint(fingerprint: string): string {
  return fingerprint.length > 16 ? `${fingerprint.slice(0, 16)}…` : fingerprint;
}

/** True when anything in use needs attention, so the tab can say so. */
export function needsAttention(items: CertificateItem[], now: number): boolean {
  return items.some((item) => {
    const tone = expiryTone(item, now);
    return tone === "warning" || tone === "critical";
  });
}

export function authModeLabel(mode: NodeCertificate["auth_mode"]): string {
  if (mode === "certificate") return "Certificado";
  if (mode === "token") return "Token compartilhado";
  return "Ainda não informado";
}

/** How many enrolled nodes still take the shared token, which managed-only would refuse. */
export function nodesOnToken(nodes: NodeCertificate[]): number {
  return nodes.filter((node) => node.auth_mode === "token").length;
}

/** What a node's row should say besides its name: the first thing wrong, or that nothing is. */
export function nodeStatus(node: NodeCertificate, now: number): { tone: Tone; label: string } {
  if (node.last_error) return { tone: "critical", label: node.last_error };
  if (node.bundle_behind > 0) return { tone: "warning", label: `Pacote atrasado em ${node.bundle_behind} ${node.bundle_behind === 1 ? "versão" : "versões"}` };
  const left = Date.parse(node.cert_not_after) - now;
  if (!Number.isFinite(left) || left <= 0) return { tone: "critical", label: "Certificado expirado" };
  if (left / DAY <= 14) {
    const days = Math.max(1, Math.floor(left / DAY));
    return { tone: "warning", label: `Certificado vence em ${days} ${days === 1 ? "dia" : "dias"}` };
  }
  return { tone: "ok", label: "Em dia" };
}

export function rotationSummary(rotation: RootRotation | undefined): { title: string; detail: string } | undefined {
  if (rotation?.phase === "prepared") {
    return {
      title: "Raiz nova publicada",
      detail:
        "Os nodes já recebem a raiz nova no pacote e ela está em /ca para instalar nos dispositivos. Quando todos tiverem confirmado, promova-a: o Control Tower passa a assinar com ela.",
    };
  }
  if (rotation?.phase === "promoted") {
    return {
      title: "Raiz nova em uso",
      detail: "A raiz antiga sai do pacote sozinha quando todos os nodes tiverem o pacote e um certificado da cadeia nova.",
    };
  }
  return undefined;
}
