/** Presentation only. Never use the result as a filesystem path or API argument. */
export function safeDisplayName(name: string, maxCodePoints = 255): string {
  let result = "";
  let count = 0;
  for (const character of name) {
    if (count++ === maxCodePoints) return result + "…";
    const code = character.codePointAt(0)!;
    const control = code < 0x20 || (code >= 0x7f && code <= 0x9f) ||
      code === 0x061c || code === 0x200e || code === 0x200f ||
      code === 0x2028 || code === 0x2029 || (code >= 0x202a && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x206f);
    result += control ? `⟦U+${code.toString(16).toUpperCase().padStart(4, "0")}⟧` : character;
  }
  return result;
}

export function fileEntryDisplayName(entry: { name: string; display_name?: string }): string {
  // The server's 255-code-point input may expand when controls are rendered
  // as U+ labels; retain that presentation while still bounding a bad response.
  return entry.display_name === undefined
    ? safeDisplayName(entry.name)
    : safeDisplayName(entry.display_name, 2550);
}

export function safeDisplayPath(path: string): string {
  return path.split("/").map((part) => safeDisplayName(part)).join("/");
}
