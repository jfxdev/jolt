import type { Job, NodeInfo } from "./types";

export interface NetworkJob {
  node: NodeInfo;
  job: Job;
}

export interface NodeJobs {
  node: NodeInfo;
  jobs: Job[];
}

function timestamp(job: Job): number {
  const value = job.created_at ? Date.parse(job.created_at) : NaN;
  return Number.isNaN(value) ? 0 : value;
}

// Newest first. Jobs without a usable timestamp sort last; job IDs break ties so
// the order is stable across refreshes.
export function mergeNetworkJobs(results: NodeJobs[]): NetworkJob[] {
  return results
    .flatMap(({ node, jobs }) => jobs.map((job) => ({ node, job })))
    .sort(
      (a, b) =>
        timestamp(b.job) - timestamp(a.job) ||
        b.job.job_id.localeCompare(a.job.job_id),
    );
}

export function pageCount(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(total / pageSize));
}

export function pageSlice<T>(items: T[], page: number, pageSize: number): T[] {
  const start = (Math.min(Math.max(page, 1), pageCount(items.length, pageSize)) - 1) * pageSize;
  return items.slice(start, start + pageSize);
}
