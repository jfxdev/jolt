import { useEffect } from "react";
import { api } from "@/lib/api";
import type { Job } from "@/lib/types";

/**
 * Subscribes to the node's Server-Sent job stream while `enabled`. Each "job"
 * event upserts into the jobs list, which is re-sorted by created_at (desc) and
 * capped at 100 — mirroring openJobEvents() in the original Vue app. The
 * EventSource is closed on unmount or when the node changes.
 */
export function useJobEvents(
  nodeId: string | undefined,
  enabled: boolean,
  setJobs: (updater: (previous: Job[]) => Job[]) => void,
) {
  useEffect(() => {
    if (!nodeId || !enabled) return;
    const source = new EventSource(api.jobEventsURL(nodeId), {
      withCredentials: true,
    });
    const onJob = (message: MessageEvent) => {
      try {
        const payload = JSON.parse(message.data);
        const job: Job | undefined = payload.job;
        if (!job?.job_id) return;
        setJobs((previous) => {
          const index = previous.findIndex(
            (item) => item.job_id === job.job_id,
          );
          const next =
            index >= 0
              ? previous.map((item, i) => (i === index ? job : item))
              : [job, ...previous];
          return [...next]
            .sort((left, right) =>
              String(right.created_at).localeCompare(String(left.created_at)),
            )
            .slice(0, 100);
        });
      } catch {
        // A malformed event is ignored; EventSource resumes with the next id.
      }
    };
    source.addEventListener("job", onJob);
    return () => {
      source.removeEventListener("job", onJob);
      source.close();
    };
  }, [nodeId, enabled, setJobs]);
}
