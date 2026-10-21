import assert from "node:assert/strict";
import { setImmediate } from "node:timers/promises";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";
import type { UploadSession } from "../src/lib/resumable-upload.ts";

// Load the actual hook with the app's aliases. Server rendering supplies React's
// hook dispatcher; these tests exercise the ref-backed lifecycle, not the UI.
const server = await createServer({
  configFile: false,
  root: fileURLToPath(new URL("..", import.meta.url)),
  resolve: { alias: { "@": fileURLToPath(new URL("../src", import.meta.url)) } },
  server: { middlewareMode: true, hmr: false, watch: null },
  appType: "custom",
  logLevel: "silent",
});
after(() => server.close());
const { useResumableUploads } = await server.ssrLoadModule("/src/hooks/useResumableUploads.ts") as
  typeof import("../src/hooks/useResumableUploads.ts");
const { api } = await server.ssrLoadModule("/src/lib/api.ts") as
  typeof import("../src/lib/api.ts");

async function conflictedUpload() {
  const abort = Promise.withResolvers<unknown>();
  const created: boolean[] = [];
  const errors: unknown[] = [];
  let finished = 0;
  const file = new File(["payload"], "file.txt", { lastModified: 1 });
  const session: UploadSession = {
    upload_id: "old-session", mount_id: "media", destination_path: file.name,
    size: file.size, offset: 0, overwrite: false, chunk_size: 8,
    created_at: "", updated_at: "", expires_at: "",
  };
  api.createUpload = async (_node, _mount, input) => {
    created.push(input.overwrite);
    return { ...session, overwrite: input.overwrite };
  };
  api.appendUploadChunk = async () => ({ ...session, offset: file.size });
  api.completeUpload = async () => {
    if (created.length === 1) throw Object.assign(new Error("exists"), { status: 409 });
    return { upload_id: session.upload_id, destination_path: file.name, size: file.size, checksum: "" };
  };
  api.abortUpload = () => abort.promise;

  let uploads!: ReturnType<typeof useResumableUploads>;
  function Harness() {
    uploads = useResumableUploads({
      nodeId: "node", mountId: "media",
      onFinished: () => { finished++; }, onError: (error) => errors.push(error),
    });
    return null;
  }
  renderToStaticMarkup(createElement(Harness));
  uploads.start(file, file.name);
  await setImmediate();
  assert.deepEqual(created, [false]);
  return {
    uploads, id: `${file.name}:${file.size}:${file.lastModified}`, abort, created, errors,
    finished: () => finished,
  };
}

test("cancelling a replacement while its old session is aborting prevents a new upload", async () => {
  const { uploads, id, abort, created, errors, finished } = await conflictedUpload();
  uploads.cancel(id); // The controller from the original upload is already aborted.
  const replacement = uploads.replace(id);
  uploads.cancel(id);
  abort.resolve({});
  await replacement;
  await setImmediate();
  assert.deepEqual(created, [false]);
  assert.equal(finished(), 0);
  assert.deepEqual(errors, []);
});

test("dismissing a replacement during abort does not restore it or start a new upload", async () => {
  const { uploads, id, abort, created, finished } = await conflictedUpload();
  const replacement = uploads.replace(id);
  uploads.dismiss(id);
  abort.resolve({});
  await replacement;
  await uploads.retry(id);
  await setImmediate();
  assert.deepEqual(created, [false]);
  assert.equal(finished(), 0);
});

test("a replacement waits for abort, then opens a session with overwrite enabled", async () => {
  const { uploads, id, abort, created, errors, finished } = await conflictedUpload();
  const replacement = uploads.replace(id);
  assert.deepEqual(created, [false]);
  abort.resolve({});
  await replacement;
  await setImmediate();
  assert.deepEqual(created, [false, true]);
  assert.equal(finished(), 1);
  assert.deepEqual(errors, []);
});

test("a failed abort reports the error without starting a replacement", async () => {
  const { uploads, id, abort, created, errors } = await conflictedUpload();
  const replacement = uploads.replace(id);
  const error = new Error("abort failed");
  abort.reject(error);
  await replacement;
  assert.deepEqual(created, [false]);
  assert.deepEqual(errors, [error]);
});
