export function joinPath(base: string, relative: string): string {
  return [base, relative].filter(Boolean).join("/");
}

/**
 * Returns the path relative to a grant's base, or null when the path lies
 * outside the grant. An empty base means the value is already relative.
 */
export function relativeToGrant(
  value: string,
  base: string,
): string | null {
  if (!base) return value || "";
  if (value === base) return "";
  return value.startsWith(`${base}/`) ? value.slice(base.length + 1) : null;
}
