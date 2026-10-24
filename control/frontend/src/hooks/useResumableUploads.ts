import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import type { UploadSession } from "@/lib/types";
import {
  UploadAbortedError,
  uploadResumable,
  type UploadTransport,
} from "@/lib/resumable-upload";
import { verifyUploadSource } from "@/lib/upload-verification";
import type { UploadItem } from "@/components/files/UploadQueue";

interface Options {
  nodeId: string;
  mountId: string | undefined;
  destinationLabel?: string;
  onFinished: () => void | Promise<void>;
  onError: (error: unknown) => void;
}
interface Pending {
  nodeId: string;
  mountId: string;
  path: string;
  file?: File;
  controller: AbortController;
  session?: UploadSession;
  overwrite: boolean;
}
function isConflict(error: unknown) {
  const value = error as { status?: number; code?: string };
  return value?.status === 409 && value.code !== "upload_offset_mismatch";
}

export function useResumableUploads({
  nodeId,
  mountId,
  destinationLabel,
  onFinished,
  onError,
}: Options) {
  const [uploads, setUploads] = useState<UploadItem[]>([]);
  const [recoveryError, setRecoveryError] = useState<string>();
  const pending = useRef(new Map<string, Pending>());
  const target = `${nodeId}:${mountId ?? ""}`;
  const targetRef = useRef(target);
  targetRef.current = target;
  const patch = useCallback((id: string, changes: Partial<UploadItem>) => {
    setUploads((current) =>
      current.map((item) => (item.id === id ? { ...item, ...changes } : item)),
    );
  }, []);

  const refreshSessions = useCallback(async () => {
    if (!mountId) return;
    const requestedTarget = `${nodeId}:${mountId}`;
    try {
      const { sessions } = await api.uploadSessions(nodeId, mountId);
      if (targetRef.current !== requestedTarget) return;
      setRecoveryError(undefined);
      const recovered: UploadItem[] = [];
      for (const session of sessions) {
        if (
          session.state === "completed" ||
          [...pending.current.values()].some(
            (entry) =>
              entry.nodeId === nodeId &&
              entry.mountId === mountId &&
              entry.session?.upload_id === session.upload_id,
          )
        )
          continue;
        const id = `${nodeId}:${mountId}:${session.upload_id}`;
        pending.current.set(id, {
          nodeId,
          mountId,
          path: session.destination_path,
          session,
          overwrite: session.overwrite,
          controller: new AbortController(),
        });
        recovered.push({
          id,
          name:
            session.destination_path.split("/").pop() ||
            session.destination_path,
          destination: [destinationLabel, session.destination_path].filter(Boolean).join(" / "),
          uploaded: session.offset,
          total: session.size,
          status: "cancelled",
          resumable: true,
          needsFile: true,
        });
      }
      if (recovered.length)
        setUploads((current) => [
          ...current,
          ...recovered.filter(
            (item) => !current.some((old) => old.id === item.id),
          ),
        ]);
    } catch (error) {
      if (targetRef.current === requestedTarget)
        setRecoveryError(
          error instanceof Error
            ? error.message
            : "Não foi possível recuperar os envios pendentes.",
        );
    }
  }, [nodeId, mountId, destinationLabel]);
  useEffect(() => {
    void refreshSessions();
  }, [refreshSessions]);
  useEffect(
    () => () => {
      for (const entry of pending.current.values()) entry.controller.abort();
    },
    [],
  );

  const run = useCallback(
    async (id: string, entry: Pending) => {
      if (!entry.file) return;
      const transport: UploadTransport = {
        create: (input) => api.createUpload(entry.nodeId, entry.mountId, input),
        append: (uploadId, chunk, offset, total) =>
          api.appendUploadChunk(
            entry.nodeId,
            entry.mountId,
            uploadId,
            chunk,
            offset,
            total,
            entry.controller.signal,
          ),
        complete: (uploadId) =>
          api.completeUpload(entry.nodeId, entry.mountId, uploadId),
        abort: (uploadId) =>
          api.abortUpload(entry.nodeId, entry.mountId, uploadId),
        session: (uploadId) =>
          api.uploadSession(entry.nodeId, entry.mountId, uploadId),
      };
      try {
        const session = await uploadResumable(
          {
            ...transport,
            create: async (input) => {
              const created = await transport.create(input);
              entry.session = created;
              if (
                entry.controller.signal.aborted &&
                pending.current.get(id) !== entry
              ) {
                await transport.abort(created.upload_id);
                throw new UploadAbortedError();
              }
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
        patch(id, {
          uploaded: entry.file.size,
          status: "done",
          error: undefined,
          needsFile: false,
        });
        await onFinished();
      } catch (error) {
        if (
          error instanceof UploadAbortedError ||
          entry.controller.signal.aborted
        ) {
          patch(id, { status: "cancelled", resumable: !!entry.session });
          return;
        }
        patch(id, {
          status: isConflict(error) ? "conflict" : "failed",
          resumable: !!entry.session,
          error: error instanceof Error ? error.message : "Falha no envio.",
        });
        if (!isConflict(error)) onError(error);
      }
    },
    [onError, onFinished, patch],
  );

  const start = useCallback(
    (file: File, path: string, overwrite = false) => {
      if (!mountId) return;
      const id = `${nodeId}:${mountId}:${path}:${file.size}:${file.lastModified}`;
      const existing = pending.current.get(id);
      // A repeated selection cannot leave an invisible concurrent writer.
      if (
        existing &&
        !uploads.some((item) => item.id === id && item.status === "done")
      )
        return;
      const entry: Pending = {
        nodeId,
        mountId,
        file,
        path,
        overwrite,
        controller: new AbortController(),
      };
      pending.current.set(id, entry);
      setUploads((current) => [
        ...current.filter((item) => item.id !== id),
        {
          id,
          name: file.name,
          destination: [destinationLabel, path].filter(Boolean).join(" / "),
          uploaded: 0,
          total: file.size,
          status: "uploading",
        },
      ]);
      void run(id, entry);
    },
    [mountId, nodeId, run, uploads, destinationLabel],
  );
  const cancel = useCallback(
    (id: string) => pending.current.get(id)?.controller.abort(),
    [],
  );

  const retry = useCallback(
    async (id: string, overwrite?: boolean) => {
      const entry = pending.current.get(id);
      if (!entry?.file) return;
      const resumed = {
        ...entry,
        controller: new AbortController(),
        overwrite: overwrite ?? entry.overwrite,
      };
      pending.current.set(id, resumed);
      if (overwrite && entry.session) {
        try {
          await api.abortUpload(
            entry.nodeId,
            entry.mountId,
            entry.session.upload_id,
          );
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
          resumable: !!resumed.session,
        });
        return;
      }
      patch(id, { status: "uploading", error: undefined, resumable: false });
      void run(id, resumed);
    },
    [onError, patch, run],
  );

  const reselect = useCallback(
    async (id: string, file: File) => {
      const entry = pending.current.get(id);
      if (!entry?.session) return;
      const resumed = { ...entry, controller: new AbortController() };
      pending.current.set(id, resumed);
      patch(id, { status: "verifying", error: undefined });
      try {
        const current = await api.uploadSession(
          entry.nodeId,
          entry.mountId,
          entry.session.upload_id,
        );
        if (current.state === "completed") {
          patch(id, {
            status: "done",
            uploaded: current.size,
            needsFile: false,
          });
          await onFinished();
          return;
        }
        await verifyUploadSource(
          file,
          current,
          (after) =>
            api.uploadVerification(
              entry.nodeId,
              entry.mountId,
              current.upload_id,
              after,
              resumed.controller.signal,
            ),
          resumed.controller.signal,
        );
        if (
          pending.current.get(id) !== resumed ||
          resumed.controller.signal.aborted
        )
          return;
        resumed.file = file;
        resumed.session = current;
        patch(id, { status: "uploading", needsFile: false, error: undefined });
        void run(id, resumed);
      } catch (error) {
        patch(id, {
          status: resumed.controller.signal.aborted ? "cancelled" : "failed",
          needsFile: true,
          error:
            error instanceof Error
              ? error.message
              : "Não foi possível verificar o arquivo.",
        });
      }
    },
    [onFinished, patch, run],
  );
  const replace = useCallback((id: string) => retry(id, true), [retry]);
  const dismiss = useCallback(
    async (id: string) => {
      const entry = pending.current.get(id);
      const visible = uploads.find((item) => item.id === id);
      entry?.controller.abort();
      pending.current.delete(id);
      setUploads((current) => current.filter((item) => item.id !== id));
      if (entry?.session && visible?.status !== "done") {
        try {
          await api.abortUpload(
            entry.nodeId,
            entry.mountId,
            entry.session.upload_id,
          );
        } catch (error) {
          if (!pending.current.has(id)) {
            pending.current.set(id, entry);
            if (visible)
              setUploads((current) => [
                ...current.filter((item) => item.id !== id),
                {
                  ...visible,
                  status: "failed",
                  error: "Não foi possível descartar o envio. Tente novamente.",
                },
              ]);
          }
          onError(error);
        }
      }
    },
    [onError, uploads],
  );
  return {
    uploads,
    start,
    cancel,
    retry,
    replace,
    dismiss,
    reselect,
    recoveryError,
    refreshSessions,
  };
}
