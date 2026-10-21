import { useCallback, useRef, useState } from "react";
import { api } from "@/lib/api";
import type { UploadSession } from "@/lib/types";
import {
  UploadAbortedError,
  uploadResumable,
  type UploadTransport,
} from "@/lib/resumable-upload";
import type { UploadItem } from "@/components/files/UploadQueue";

interface Options {
  nodeId: string;
  mountId: string | undefined;
  onFinished: () => void | Promise<void>;
  onError: (error: unknown) => void;
}

interface Pending {
  file: File;
  path: string;
  controller: AbortController;
  session?: UploadSession;
  /** overwrite stays false until the user explicitly chooses to replace the
   * file already at the destination. */
  overwrite: boolean;
}

/** isConflict recognises the responses that mean "something is already at this
 * destination": a conflicting session, or an existing file refused at
 * completion. */
function isConflict(error: unknown) {
  const status = (error as { status?: number })?.status;
  const code = (error as { code?: string })?.code;
  return status === 409 && code !== "upload_offset_mismatch";
}

/**
 * useResumableUploads drives chunked uploads with progress, cancellation and
 * resume. State lives in a ref keyed by upload id so a cancel or a retry
 * reaches the right transfer even while several run at once.
 */
export function useResumableUploads({ nodeId, mountId, onFinished, onError }: Options) {
  const [uploads, setUploads] = useState<UploadItem[]>([]);
  const pending = useRef(new Map<string, Pending>());

  const patch = useCallback((id: string, changes: Partial<UploadItem>) => {
    setUploads((current) =>
      current.map((item) => (item.id === id ? { ...item, ...changes } : item)),
    );
  }, []);

  const run = useCallback(
    async (id: string, entry: Pending) => {
      if (!mountId) return;
      const transport: UploadTransport = {
        create: (input) => api.createUpload(nodeId, mountId, input),
        append: (uploadId, chunk, offset, total) =>
          api.appendUploadChunk(nodeId, mountId, uploadId, chunk, offset, total),
        complete: (uploadId) => api.completeUpload(nodeId, mountId, uploadId),
        abort: (uploadId) => api.abortUpload(nodeId, mountId, uploadId),
        session: (uploadId) => api.uploadSession(nodeId, mountId, uploadId),
      };
      try {
        const session = await uploadResumable(
          {
            ...transport,
            // Capture the session as soon as it exists so a cancelled or
            // failed upload can still be resumed or cleaned up.
            create: async (input) => {
              const created = await transport.create(input);
              entry.session = created;
              return created;
            },
          },
          entry.file,
          entry.path,
          entry.overwrite,
          {
            signal: entry.controller.signal,
            resumeFrom: entry.session,
            onProgress: ({ uploaded, attempt }) =>
              patch(id, {
                uploaded,
                status: attempt > 1 ? "retrying" : "uploading",
              }),
          },
        );
        entry.session = session;
        patch(id, { uploaded: entry.file.size, status: "done", error: undefined });
        await onFinished();
      } catch (error) {
        if (error instanceof UploadAbortedError) {
          // The partial stays on the node, so the same file can continue.
          patch(id, { status: "cancelled", resumable: true });
          return;
        }
        if (isConflict(error)) {
          // Replacing a file is the user's decision, so the upload stops here
          // and waits rather than silently overwriting.
          patch(id, {
            status: "conflict",
            resumable: entry.session !== undefined,
            error:
              error instanceof Error
                ? error.message
                : "Já existe um arquivo com este nome.",
          });
          return;
        }
        patch(id, {
          status: "failed",
          resumable: entry.session !== undefined,
          error: error instanceof Error ? error.message : "Falha no envio.",
        });
        onError(error);
      }
    },
    [mountId, nodeId, onError, onFinished, patch],
  );

  const start = useCallback(
    (file: File, path: string, overwrite = false) => {
      if (!mountId) return;
      const id = `${path}:${file.size}:${file.lastModified}`;
      const entry: Pending = {
        file,
        path,
        overwrite,
        controller: new AbortController(),
      };
      pending.current.set(id, entry);
      setUploads((current) => [
        ...current.filter((item) => item.id !== id),
        { id, name: file.name, uploaded: 0, total: file.size, status: "uploading" },
      ]);
      void run(id, entry);
    },
    [mountId, run],
  );

  const cancel = useCallback((id: string) => {
    pending.current.get(id)?.controller.abort();
  }, []);

  const retry = useCallback(
    async (id: string, overwrite?: boolean) => {
      const entry = pending.current.get(id);
      if (!entry) return;
      // A fresh controller is required: the previous one is already aborted.
      const resumed: Pending = {
        ...entry,
        controller: new AbortController(),
        overwrite: overwrite ?? entry.overwrite,
      };
      // Cancel and dismiss must reach this attempt while the old session is
      // being removed, rather than the previous controller.
      pending.current.set(id, resumed);
      // A session created without overwrite carries that flag on the node, so
      // replacing requires a new session rather than completing the old one.
      if (overwrite && entry.session) {
        try {
          await api.abortUpload(nodeId, mountId!, entry.session.upload_id);
        } catch (error) {
          onError(error);
          return;
        }
        resumed.session = undefined;
      }
      if (pending.current.get(id) !== resumed) return;
      if (resumed.controller.signal.aborted) {
        patch(id, {
          status: "cancelled",
          error: undefined,
          resumable: resumed.session !== undefined,
        });
        return;
      }
      patch(id, { status: "uploading", error: undefined, resumable: false });
      void run(id, resumed);
    },
    [mountId, nodeId, onError, patch, run],
  );

  const replace = useCallback((id: string) => retry(id, true), [retry]);

  const dismiss = useCallback(
    (id: string) => {
      const entry = pending.current.get(id);
      // Discarding an unfinished upload releases its partial on the node so a
      // cancelled transfer does not occupy the destination indefinitely.
      if (entry?.session && mountId) {
        void api
          .abortUpload(nodeId, mountId, entry.session.upload_id)
          .catch(() => undefined);
      }
      pending.current.delete(id);
      setUploads((current) => current.filter((item) => item.id !== id));
    },
    [mountId, nodeId],
  );

  return { uploads, start, cancel, retry, replace, dismiss };
}
