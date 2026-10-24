import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyUploadSource } from "../src/lib/upload-verification.ts";
import { summarizeNetworkJobs } from "../src/lib/network-summary.ts";
import { runLimited } from "../src/lib/concurrency.ts";
import { uploadResumable } from "../src/lib/resumable-upload.ts";
import type { UploadSession } from "../src/lib/types.ts";

const session: UploadSession = {
  upload_id: "test",
  mount_id: "media",
  destination_path: "file.txt",
  size: 7,
  offset: 3,
  overwrite: false,
  chunk_size: 8,
  created_at: "",
  updated_at: "",
  expires_at: "",
};
const digest = async (text: string) =>
  Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)),
    ),
    (value) => value.toString(16).padStart(2, "0"),
  ).join("");

test("source re-selection verifies actual durable bytes, not only name/size", async () => {
  const sha256 = await digest("pay");
  const page = async () => ({
    offset: 3,
    next_after: 0,
    blocks: [{ offset: 0, size: 3, sha256 }],
  });
  await verifyUploadSource(new Blob(["payload"]), session, page);
  await assert.rejects(
    verifyUploadSource(new Blob(["badload"]), session, page),
    /conteúdo.*diferente/,
  );
  await assert.rejects(
    verifyUploadSource(new Blob(["payload"]), session, async () => ({
      offset: 3,
      next_after: 0,
      blocks: [],
    })),
    /incompleta/,
  );
});
test("lost completion response retries the receipt without resending bytes", async () => {
  let completed = 0,
    appended = 0;
  await uploadResumable(
    {
      create: async () => ({ ...session, offset: 7 }),
      append: async () => {
        appended++;
        return session;
      },
      complete: async () => {
        completed++;
        if (completed === 1) throw new Error("lost response");
      },
      abort: async () => undefined,
    },
    new Blob(["payload"]),
    "file.txt",
    false,
    { sleep: async () => undefined },
  );
  assert.equal(completed, 2);
  assert.equal(appended, 0);
});
test("network totals distinguish unavailable/restricted data from zero", () => {
  assert.deepEqual(summarizeNetworkJobs([undefined]), {
    active: null,
    partial: true,
  });
  assert.deepEqual(
    summarizeNetworkJobs([
      {
        value: {
          counts: { running: 4, queued: 5, paused: 2 },
          observed_at: "",
        },
      },
      { restricted: true },
    ]),
    { active: 4, partial: true },
  );
  assert.deepEqual(
    summarizeNetworkJobs([{ value: { counts: {}, observed_at: "" } }]),
    { active: 0, partial: false },
  );
});
test("diagnostic requests never exceed four simultaneous calls", async () => {
  let active = 0,
    maximum = 0,
    completed = 0;
  await runLimited(
    Array.from({ length: 24 }, () => async () => {
      maximum = Math.max(maximum, ++active);
      await new Promise((resolve) => setTimeout(resolve, 1));
      active--;
      completed++;
    }),
  );
  assert.equal(maximum, 4);
  assert.equal(completed, 24);
});
