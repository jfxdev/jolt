import assert from "node:assert/strict";
import { test } from "node:test";
import { destructivePlanDescription, planRequired, planUnavailable, type DestructivePlan } from "../src/lib/destructive-plan.ts";

const base: DestructivePlan = {
  plan_id: "plan_1",
  token: "t",
  expires_at: "2026-11-05T12:00:00Z",
  operation: "delete",
  mount_id: "files",
  source_path: "tree",
  files: 2,
  directories: 3,
  bytes: 2048,
};

test("a delete plan states what is removed and that a change cancels it", () => {
  const text = destructivePlanDescription(base);
  assert.match(text, /2 arquivos em 3 pastas \(2\.0 KB\)/);
  assert.match(text, /removidos permanentemente/);
  assert.match(text, /nada é alterado/);
  assert.doesNotMatch(text, /substituído/);
});

test("singular counts and a replaced destination are spelled out", () => {
  const move = destructivePlanDescription({ ...base, operation: "move", files: 1, directories: 1, bytes: 10, destination_exists: true, destination_files: 4, destination_bytes: 1024 });
  assert.match(move, /1 arquivo em 1 pasta/);
  assert.match(move, /movidos/);
  assert.match(move, /destino existente, com 4 arquivos \(1\.0 KB\), será substituído/);
});

test("only the exact error codes select a fallback or a plan", () => {
  assert.equal(planUnavailable({ code: "resource_not_found", status: 404 }), true);
  assert.equal(planUnavailable({ code: "not_found", status: 404 }), false);
  assert.equal(planUnavailable({ code: "resource_not_found", status: 500 }), false);
  assert.equal(planUnavailable(undefined), false);
  assert.equal(planRequired({ code: "plan_required" }), true);
  assert.equal(planRequired({ code: "conflict" }), false);
});

import { omittedSourcesNotice } from "../src/lib/transfer-preview.ts";

test("a preview that left entries out says so, by count only", () => {
  const plan = { files_total: 2, bytes_total: 10, copy_count: 2, conflict_count: 0 };
  assert.equal(omittedSourcesNotice(null), "");
  assert.equal(omittedSourcesNotice(plan), "");
  assert.equal(omittedSourcesNotice({ ...plan, sources_omitted: 0 }), "");
  assert.equal(omittedSourcesNotice({ ...plan, sources_omitted: 1 }), "1 entrada da origem não está acessível para você e não será copiada.");
  assert.equal(omittedSourcesNotice({ ...plan, sources_omitted: 3 }), "3 entradas da origem não estão acessíveis para você e não serão copiadas.");
  assert.equal(omittedSourcesNotice({ ...plan, sources_omitted: -2 }), "");
});
