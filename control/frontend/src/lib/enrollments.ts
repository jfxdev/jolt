import type { Enrollment, JoinToken } from "./types.ts";

export type TokenStatus = "waiting" | "used" | "expired";

/** Where a token stands: unused and valid, spent, or past its time without being used. */
export function tokenStatus(token: Pick<JoinToken, "used_at" | "expires_at">, now: number): TokenStatus {
  if (token.used_at) return "used";
  const end = Date.parse(token.expires_at);
  return Number.isFinite(end) && end > now ? "waiting" : "expired";
}

const TOKEN_LABELS: Record<TokenStatus, string> = {
  waiting: "Aguardando o node",
  used: "Usado",
  expired: "Expirado",
};

export function tokenStatusLabel(status: TokenStatus): string {
  return TOKEN_LABELS[status];
}

const STATE_LABELS: Record<Enrollment["state"], string> = {
  pending: "Aguardando aprovação",
  issued: "Aprovado",
  rejected: "Rejeitado",
  expired: "Expirado",
};

export function enrollmentStateLabel(state: Enrollment["state"]): string {
  return STATE_LABELS[state] ?? state;
}

/** A token is shown once; this is the line to put in the node's environment. */
export function environmentLine(token: string): string {
  return `JOLT_JOIN_TOKEN=${token}`;
}

/** The part of node.yaml a node needs before it can join. */
export const NODE_YAML_SNIPPET = "tls_mode: managed\napi_public_endpoint: https://ENDEREÇO-DESTE-NODE:8080\n";

/** Group a fingerprint in pairs so two people can read it to each other. */
export function groupFingerprint(value: string): string {
  const clean = value.replace(/[^0-9a-fA-F]/g, "");
  if (clean.length < 16 || clean.length % 2) return value;
  return clean.toUpperCase().match(/.{2}/g)!.join(":");
}

/** Minutes a person asked for, kept inside what the server accepts. */
export function clampMinutes(value: number): number {
  if (!Number.isFinite(value)) return 15;
  return Math.min(1440, Math.max(1, Math.round(value)));
}
