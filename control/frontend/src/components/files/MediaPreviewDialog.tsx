import type { FileEntry } from "@/lib/types";
import { mediaInfoForFilename } from "@/lib/media";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface Props {
  entry: FileEntry | null;
  url: string | null;
  onClose: () => void;
}

export function MediaPreviewDialog({ entry, url, onClose }: Props) {
  const media = entry ? mediaInfoForFilename(entry.name) : null;

  return (
    <Dialog open={entry !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>{entry?.name}</DialogTitle>
          <DialogDescription>Visualização do arquivo</DialogDescription>
        </DialogHeader>
        {url && media?.kind === "audio" && <audio className="w-full" controls src={url} />}
        {url && media?.kind === "video" && (
          <video className="max-h-[65vh] w-full rounded-md bg-black" controls src={url} />
        )}
        {url && media?.kind === "image" && (
          <img className="max-h-[65vh] w-full object-contain" src={url} alt={entry?.name} />
        )}
      </DialogContent>
    </Dialog>
  );
}
