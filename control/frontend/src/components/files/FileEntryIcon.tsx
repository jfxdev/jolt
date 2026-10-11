import {
  Container,
  File,
  FileArchive,
  FileAudio,
  FileCode2,
  FileCog,
  FileImage,
  FileJson2,
  FileSpreadsheet,
  FileSymlink,
  FileTerminal,
  FileText,
  FileVideo,
  Folder,
  type LucideIcon,
} from "lucide-react";
import type { FileEntry } from "@/lib/types";
import { cn } from "@/lib/utils";

interface IconStyle {
  icon: LucideIcon;
  className: string;
}

const docker: IconStyle = {
  icon: Container,
  className: "text-sky-600 dark:text-sky-400",
};
const configuration: IconStyle = {
  icon: FileCog,
  className: "text-slate-500 dark:text-slate-400",
};
const shell: IconStyle = {
  icon: FileTerminal,
  className: "text-emerald-600 dark:text-emerald-400",
};
const go: IconStyle = {
  icon: FileCode2,
  className: "text-cyan-600 dark:text-cyan-400",
};

const extensionGroups: (IconStyle & { extensions: string[] })[] = [
  {
    extensions: ["png", "jpg", "jpeg", "gif", "webp", "svg", "avif", "bmp", "ico", "tif", "tiff", "heic", "heif"],
    icon: FileImage,
    className: "text-fuchsia-600 dark:text-fuchsia-400",
  },
  {
    extensions: ["json", "jsonc", "json5", "ndjson"],
    icon: FileJson2,
    className: "text-amber-600 dark:text-amber-400",
  },
  {
    extensions: ["yaml", "yml"],
    icon: FileCode2,
    className: "text-orange-600 dark:text-orange-400",
  },
  { extensions: ["sh", "bash", "zsh", "fish", "ps1", "bat", "cmd"], ...shell },
  { extensions: ["conf", "config", "cfg", "cnf", "ini", "toml", "env", "properties", "service", "socket"], ...configuration },
  { extensions: ["go"], ...go },
  {
    extensions: ["ts", "tsx", "mts", "cts", "py", "pyi"],
    icon: FileCode2,
    className: "text-blue-600 dark:text-blue-400",
  },
  {
    extensions: ["js", "jsx", "mjs", "cjs"],
    icon: FileCode2,
    className: "text-yellow-600 dark:text-yellow-400",
  },
  {
    extensions: ["html", "htm", "xml", "rs", "java", "c", "h", "cpp", "hpp", "cs", "php", "rb", "swift", "kt", "vue", "svelte", "sql"],
    icon: FileCode2,
    className: "text-orange-600 dark:text-orange-400",
  },
  {
    extensions: ["css", "scss", "sass", "less"],
    icon: FileCode2,
    className: "text-violet-600 dark:text-violet-400",
  },
  {
    extensions: ["zip", "tar", "gz", "bz2", "xz", "zst", "7z", "rar", "tgz"],
    icon: FileArchive,
    className: "text-amber-600 dark:text-amber-400",
  },
  {
    extensions: ["mp4", "mkv", "webm", "mov", "avi", "m4v", "mpeg", "mpg"],
    icon: FileVideo,
    className: "text-violet-600 dark:text-violet-400",
  },
  {
    extensions: ["mp3", "wav", "ogg", "flac", "aac", "m4a", "opus"],
    icon: FileAudio,
    className: "text-pink-600 dark:text-pink-400",
  },
  {
    extensions: ["csv", "tsv", "xls", "xlsx", "ods"],
    icon: FileSpreadsheet,
    className: "text-green-600 dark:text-green-400",
  },
  {
    extensions: ["pdf"],
    icon: FileText,
    className: "text-red-600 dark:text-red-400",
  },
  {
    extensions: ["txt", "md", "mdx", "rst", "log", "doc", "docx", "odt", "rtf"],
    icon: FileText,
    className: "text-muted-foreground",
  },
];

const stylesByExtension = new Map(
  extensionGroups.flatMap(({ extensions, ...style }) =>
    extensions.map((extension) => [extension, style] as const),
  ),
);

function styleForEntry(entry: Pick<FileEntry, "name" | "type">): IconStyle {
  if (entry.type === "directory") {
    return { icon: Folder, className: "fill-yellow-500/15 text-yellow-600 dark:text-yellow-400" };
  }
  if (entry.type === "symlink") {
    return { icon: FileSymlink, className: "text-violet-600 dark:text-violet-400" };
  }

  const name = entry.name.toLowerCase();
  if (/^(dockerfile|containerfile)(\.|$)/.test(name) || /\.(dockerfile|containerfile)$/.test(name) ||
      /^(docker-compose|compose)(\.[^.]+)*\.ya?ml$/.test(name) || name === ".dockerignore") {
    return docker;
  }
  if (name === "go.mod" || name === "go.sum" || name === "go.work" || name === "go.work.sum") return go;
  if (/^\.env(\.|$)/.test(name) || [".gitignore", ".gitattributes", ".gitconfig", ".editorconfig", ".npmrc", ".yarnrc", ".bashrc", ".zshrc", ".profile", ".htaccess"].includes(name)) {
    return configuration;
  }
  if (["makefile", "gnumakefile", "justfile"].includes(name)) return shell;

  const extension = name.includes(".") ? name.split(".").pop()! : "";
  return stylesByExtension.get(extension) || { icon: File, className: "text-muted-foreground" };
}

interface Props {
  entry: Pick<FileEntry, "name" | "type">;
  className?: string;
}

/** Decorative file-type marker; the adjacent filename remains its accessible label. */
export function FileEntryIcon({ entry, className }: Props) {
  const { icon: Icon, className: color } = styleForEntry(entry);
  return <Icon aria-hidden="true" focusable="false" className={cn("size-4 shrink-0", color, className)} />;
}
