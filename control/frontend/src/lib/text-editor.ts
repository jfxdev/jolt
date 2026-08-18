export const TEXT_EDITOR_MAX_BYTES = 512 * 1024;

const textExtensions = new Set([
  "bash", "c", "cc", "cfg", "conf", "cpp", "css", "csv", "env", "go",
  "h", "html", "ini", "java", "js", "json", "jsx", "log", "md", "mjs",
  "py", "rb", "rs", "sh", "sql", "svg", "text", "toml", "ts", "tsx", "txt",
  "xml", "yaml", "yml", "zsh",
]);

export function isEditableTextFilename(filename: string): boolean {
  const extension = filename.split(".").pop()?.toLowerCase();
  return extension ? textExtensions.has(extension) : false;
}

export function isWithinTextEditorLimit(size: number | undefined): boolean {
  return size !== undefined && size <= TEXT_EDITOR_MAX_BYTES;
}
