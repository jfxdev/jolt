export type MediaKind = "audio" | "video" | "image";

export interface MediaInfo {
  kind: MediaKind;
}

const mediaExtensions: Record<string, MediaInfo> = {
  aac: { kind: "audio" },
  flac: { kind: "audio" },
  m4a: { kind: "audio" },
  mp3: { kind: "audio" },
  oga: { kind: "audio" },
  ogg: { kind: "audio" },
  opus: { kind: "audio" },
  wav: { kind: "audio" },
  weba: { kind: "audio" },
  m4v: { kind: "video" },
  mov: { kind: "video" },
  mp4: { kind: "video" },
  ogv: { kind: "video" },
  webm: { kind: "video" },
  avif: { kind: "image" },
  gif: { kind: "image" },
  jpeg: { kind: "image" },
  jpg: { kind: "image" },
  png: { kind: "image" },
  svg: { kind: "image" },
  webp: { kind: "image" },
};

export function mediaInfoForFilename(filename: string): MediaInfo | null {
  const extension = filename.split(".").pop()?.toLowerCase();
  return extension ? mediaExtensions[extension] || null : null;
}
