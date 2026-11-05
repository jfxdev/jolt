import type { Capability, FileTypeSelector, PolicyRule } from "./types.ts";

// The classes the server knows, with the label an operator reads.
export const FILE_TYPE_CLASSES: { id: string; label: string }[] = [
  { id: "video", label: "Vídeo" },
  { id: "audio", label: "Áudio" },
  { id: "image", label: "Imagem" },
  { id: "document", label: "Documento" },
  { id: "archive", label: "Arquivo compactado" },
  { id: "executable", label: "Executável" },
  { id: "secret", label: "Segredo (.env, .pem, .key…)" },
];

const MAX_SELECTORS = 64;

/** Splits a comma, space or line separated list into trimmed, de-duplicated tokens. */
export function parseTokens(text: string): string[] {
  const seen = new Set<string>();
  const tokens: string[] = [];
  for (const raw of text.split(/[\s,;]+/)) {
    const token = raw.trim();
    const key = token.toLowerCase();
    if (!token || seen.has(key)) continue;
    seen.add(key);
    tokens.push(token);
  }
  return tokens;
}

/** An extension is typed without its dot: ".PEM" and "pem" are the same. */
export function normalizeExtension(value: string): string {
  return value.trim().replace(/^\.+/, "");
}

export function emptySelector(): FileTypeSelector {
  return { classes: [], extensions: [], names: [] };
}

/** The selector as the server expects it: only the lists that have entries. */
export function cleanSelector(selector: FileTypeSelector | undefined): FileTypeSelector | undefined {
  if (!selector) return undefined;
  const result: FileTypeSelector = {};
  if (selector.classes?.length) result.classes = [...selector.classes];
  const extensions = (selector.extensions ?? []).map(normalizeExtension).filter(Boolean);
  if (extensions.length) result.extensions = extensions;
  if (selector.names?.length) result.names = [...selector.names];
  return result;
}

function selectorCount(selector: FileTypeSelector): number {
  return (selector.classes?.length ?? 0) + (selector.extensions?.length ?? 0) + (selector.names?.length ?? 0);
}

/**
 * validateTypedRule mirrors what the server will refuse, so the form can say so
 * before saving. It returns an empty string when the rule is acceptable.
 */
export function validateTypedRule(rule: PolicyRule): string {
  if (!rule.file_types) return rule.visibility ? "A visibilidade só vale para regras por tipo." : "";
  const selector = cleanSelector(rule.file_types) ?? {};
  const count = selectorCount(selector);
  if (count === 0) return "Escolha ao menos uma classe, extensão ou nome.";
  if (count > MAX_SELECTORS) return `Use no máximo ${MAX_SELECTORS} tipos por regra.`;
  const known = new Set(FILE_TYPE_CLASSES.map((entry) => entry.id));
  if ((selector.classes ?? []).some((value) => !known.has(value))) return "Há uma classe desconhecida.";
  const extensions = (selector.extensions ?? []).map((value) => value.toLowerCase());
  if (new Set(extensions).size !== extensions.length) return "Há extensões repetidas.";
  if (extensions.some((value) => !/^[\p{L}\p{N}_+-]+$/u.test(value) || [...value].length > 128)) {
    return "Extensões usam só letras, números, hífen, sublinhado e +, sem ponto.";
  }
  const names = (selector.names ?? []).map((value) => value.toLowerCase());
  if (new Set(names).size !== names.length) return "Há nomes repetidos.";
  if (names.some((value) => value === "." || value === ".." || /[/\\\0]/.test(value) || [...value].length > 255)) {
    return "Nomes são nomes exatos de arquivo, sem barras.";
  }
  if (rule.visibility && rule.visibility !== "hidden" && rule.visibility !== "visible") return "Visibilidade inválida.";
  return "";
}

/**
 * normalizeCapabilities keeps a rule coherent after a checkbox changed. A path
 * denial stands alone. A typed denial lists the capabilities it takes away from
 * the files it matches, so it may be combined with others.
 */
export function normalizeCapabilities(capabilities: Capability[], changed: Capability, typed: boolean): Capability[] {
  if (typed) return capabilities;
  if (changed === "deny" && capabilities.includes("deny")) return ["deny"];
  if (changed !== "deny" && capabilities.includes(changed)) return capabilities.filter((value) => value !== "deny");
  return capabilities;
}

const VERBS: Record<string, string> = {
  read: "ler o conteúdo de",
  list: "listar",
  create: "criar",
  update: "alterar",
  delete: "apagar",
  write: "gravar",
  execute: "executar",
  sudo: "administrar",
};

/** Names what a typed selector matches, in words. */
export function describeSelector(selector: FileTypeSelector | undefined): string {
  const cleaned = cleanSelector(selector);
  if (!cleaned) return "";
  const parts: string[] = [];
  const labels = (cleaned.classes ?? []).map((id) => FILE_TYPE_CLASSES.find((entry) => entry.id === id)?.label.split(" (")[0].toLowerCase() ?? id);
  if (labels.length) parts.push(`da classe ${labels.join(", ")}`);
  if (cleaned.extensions?.length) parts.push(`com extensão ${cleaned.extensions.map((value) => `.${value}`).join(", ")}`);
  if (cleaned.names?.length) parts.push(`chamados ${cleaned.names.join(", ")}`);
  return parts.join(" ou ");
}

/** A sentence that says what a rule does, so a typed rule is not left to be decoded. */
export function describeRule(rule: PolicyRule): string {
  const deny = rule.capabilities.includes("deny");
  const actions = rule.capabilities.filter((value) => value !== "deny");
  if (!rule.file_types) {
    if (deny) return "Nega todas as operações neste caminho.";
    return actions.length ? `Permite ${actions.map((value) => VERBS[value] ?? value).join(", ")}.` : "";
  }
  const kind = describeSelector(rule.file_types);
  const what = actions.map((value) => VERBS[value] ?? value).join(", ");
  const visibility = rule.visibility === "visible" ? " Os arquivos aparecem na listagem, mas ficam bloqueados." : " Os arquivos ficam ocultos: não aparecem nem existem para quem não pode.";
  if (deny) {
    return `Nega ${what || "todas as operações em"} arquivos ${kind}.${visibility} Pastas não são afetadas.`;
  }
  return `Permite ${what} somente arquivos ${kind}; pastas continuam navegáveis.${visibility}`;
}
