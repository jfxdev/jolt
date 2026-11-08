import assert from "node:assert/strict";
import { test } from "node:test";
import { mergeNetworkJobs, pageCount, pageSlice } from "../src/lib/jobs-list.ts";
import type { Job, NodeInfo } from "../src/lib/types.ts";

const a = { node_id: "a", name: "Node A" } as NodeInfo;
const b = { node_id: "b", name: "Node B" } as NodeInfo;
const job = (job_id: string, created_at?: string) => ({ job_id, created_at }) as Job;

test("jobs from every node are merged newest first", () => {
  const merged = mergeNetworkJobs([
    { node: a, jobs: [job("a2", "2026-11-08T10:00:00Z"), job("a1", "2026-11-08T08:00:00Z")] },
    { node: b, jobs: [job("b1", "2026-11-08T09:00:00Z")] },
  ]);
  assert.deepEqual(merged.map((item) => item.job.job_id), ["a2", "b1", "a1"]);
  assert.equal(merged[1].node, b);
});

test("jobs without a timestamp sort last and ties are stable", () => {
  const merged = mergeNetworkJobs([
    { node: a, jobs: [job("a-none"), job("a-tie", "2026-11-08T10:00:00Z")] },
    { node: b, jobs: [job("b-tie", "2026-11-08T10:00:00Z")] },
  ]);
  assert.deepEqual(merged.map((item) => item.job.job_id), ["b-tie", "a-tie", "a-none"]);
});

test("pages are clamped to the available range", () => {
  const items = [1, 2, 3, 4, 5];
  assert.equal(pageCount(0, 2), 1);
  assert.equal(pageCount(5, 2), 3);
  assert.deepEqual(pageSlice(items, 1, 2), [1, 2]);
  assert.deepEqual(pageSlice(items, 3, 2), [5]);
  assert.deepEqual(pageSlice(items, 9, 2), [5]);
  assert.deepEqual(pageSlice(items, 0, 2), [1, 2]);
});
