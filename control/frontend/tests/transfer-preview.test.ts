import assert from "node:assert/strict";
import { test } from "node:test";
import { transferPreviewEntries } from "../src/lib/transfer-preview.ts";
import type { FileEntry, TransferPlan } from "../src/lib/types.ts";

const selection: FileEntry[] = [
  { path: "photos/trip/photo.png", name: "photo.png", type: "file", size: 36 },
  { path: "documents/reports", name: "reports", type: "directory" },
];

test("selected roots keep their names directly inside the chosen destination folder", () => {
  const items = transferPreviewEntries(selection, "incoming", null);
  assert.deepEqual(items.map(({ path, type }) => ({ path, type })), [
    { path: "incoming/photo.png", type: "file" },
    { path: "incoming/reports", type: "directory" },
  ]);
  assert.equal(items[0].action, undefined);
  assert.equal(transferPreviewEntries(selection, "", null)[0].path, "photo.png");
  assert.equal(transferPreviewEntries(selection, ".", null)[0].path, "photo.png");
  assert.equal(transferPreviewEntries(selection, "incoming\\temp\\..\\final", null)[0].path, "incoming/final/photo.png");
  assert.deepEqual(transferPreviewEntries(selection, "../outside", null), []);
  assert.deepEqual(transferPreviewEntries(selection, "/absolute", null), []);
});

test("the plan replaces estimates with exact destination names, nested content and conflict outcomes", () => {
  const plan: TransferPlan = {
    files_total: 4, bytes_total: 64, copy_count: 1, rename_count: 1, skip_count: 1, conflict_count: 1,
    items: [
      { ordinal: 0, source_path: "photo.png", destination_path: "incoming/photo (1).png", action: "rename", type: "file", size: 36 },
      { ordinal: 1, source_path: "reports", destination_path: "incoming/reports", action: "merge", type: "directory" },
      { ordinal: 2, source_path: "reports/summary.txt", destination_path: "incoming/reports/summary.txt", action: "copy", type: "file", size: 28 },
      { ordinal: 3, source_path: "reports/old.txt", destination_path: "incoming/reports/old.txt", action: "skip", type: "file", size: 4 },
      { ordinal: 4, source_path: "reports/conflict.txt", destination_path: "incoming/reports/conflict.txt", action: "conflict", type: "file", size: 8 },
    ],
  };
  const items = transferPreviewEntries(selection, "different-folder", plan);
  assert.equal(items.length, 5);
  assert.equal(items[0].name, "photo (1).png");
  assert.equal(items[0].path, "incoming/photo (1).png");
  assert.equal(items[0].originalName, "photo.png");
  assert.equal(items[1].type, "directory");
  assert.equal(items[2].path, "incoming/reports/summary.txt");
  assert.deepEqual(items.map((item) => item.action), ["rename", "merge", "copy", "skip", "conflict"]);
});

test("empty and truncated plans never fall back to unverified selected roots", () => {
  const empty: TransferPlan = { files_total: 0, bytes_total: 0, copy_count: 0, conflict_count: 0, items: [] };
  assert.deepEqual(transferPreviewEntries(selection, "incoming", empty), []);
  const limited: TransferPlan = {
    ...empty, files_total: 1000, truncated: true,
    items: [{ ordinal: 0, destination_path: "incoming/first.png", action: "overwrite", type: "file", size: 0 }],
  };
  const items = transferPreviewEntries(selection, "incoming", limited);
  assert.equal(items.length, 1);
  assert.equal(items[0].size, 0);
  assert.equal(items[0].action, "overwrite");
});
