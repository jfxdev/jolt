import assert from "node:assert/strict";
import { test } from "node:test";
import { authorizeUploadIfEnabled } from "../src/lib/upload-authorization.ts";

test("only an explicitly disabled signed-upload feature permits legacy resume", async () => {
  await authorizeUploadIfEnabled(async () => null);
  await authorizeUploadIfEnabled(async () => {
    throw Object.assign(new Error("disabled"), { status: 409, code: "signed_upload_unavailable" });
  });
  for (const failure of [
    { status: 403, code: "permission_denied" },
    { status: 409, code: "node_upgrade_required" },
    { status: 404, code: "upload_not_found" },
    { status: 500, code: "internal_error" },
  ]) {
    await assert.rejects(authorizeUploadIfEnabled(async () => {
      throw Object.assign(new Error("rejected"), failure);
    }));
  }
});
