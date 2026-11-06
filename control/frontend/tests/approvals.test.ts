import assert from "node:assert/strict";
import { test } from "node:test";
import { asPendingApproval, decisionMessage, describePending, pendingToast, remainingLabel, stateLabel, treeSize } from "../src/lib/approvals.ts";
import {
  canAskApproval,
  describeApproval,
  describeRule,
  pruneApproval,
  setApproval,
  validateApproval,
} from "../src/lib/policy-rules.ts";
import type { PolicyRule } from "../src/lib/types.ts";

test("only the 202 for approval is recognised, not a job", () => {
  const notice = { pending_operation_id: "pop_1", state: "pending_approval", expires_at: "2026-11-05T12:05:00Z", operation: "delete" };
  assert.deepEqual(asPendingApproval(notice), notice);
  assert.equal(asPendingApproval({ job_id: "j", state: "queued" }), null);
  assert.equal(asPendingApproval({ state: "pending_approval" }), null);
  assert.equal(asPendingApproval(null), null);
  assert.equal(asPendingApproval("pending_approval"), null);
});

test("the approver is told exactly what is asked, with the names", () => {
  assert.equal(describePending({ summary: { operation: "delete", mount_id: "m", paths: ["docs/a.txt"] } }), "Apagar docs/a.txt no mount m");
  assert.equal(
    describePending({ summary: { operation: "move", mount_id: "m", paths: ["docs/a.txt", "docs/b.txt"] } }),
    "Mover docs/a.txt para docs/b.txt no mount m",
  );
  assert.equal(describePending({ summary: {} }), "Operação");
});

test("a folder waiting for approval is described by what it holds", () => {
  const tree = { operation: "delete", mount_id: "m", paths: ["obras"], tree: true, files: 1, directories: 3, bytes: 2048 };
  assert.equal(describePending({ summary: tree }), "Apagar obras no mount m — 1 arquivo em 3 pastas (2.0 KB)");
  assert.equal(treeSize({ files: 0, directories: 1, bytes: 0 }), "0 arquivos em 1 pasta (0 B)");
  const notice = { pending_operation_id: "p", state: "pending_approval" as const, expires_at: "2026-11-05T12:05:00Z", operation: "delete" as const, files: 2, directories: 1, bytes: 10 };
  assert.match(pendingToast(notice, Date.parse("2026-11-05T12:00:00Z")), /^Apagar 2 arquivos em 1 pasta \(10 B\) aguardando aprovação/);
});

test("a transfer between nodes says where it goes and how much moves", () => {
  const summary = { operation: "move", mount_id: "media", source_node: "nas", paths: ["exports/a.txt"], destination: "backup:incoming/imports", files: 1, bytes: 12 };
  assert.equal(describePending({ summary }), "Mover exports/a.txt de nas:media para backup:incoming/imports — 1 arquivo (12 B)");
});

test("the time left and the state read clearly", () => {
  const now = Date.parse("2026-11-05T12:00:00Z");
  assert.equal(remainingLabel("2026-11-05T12:04:10Z", now), "4 min 10 s");
  assert.equal(remainingLabel("2026-11-05T12:00:09Z", now), "9 s");
  assert.equal(remainingLabel("2026-11-05T11:59:00Z", now), "expirado");
  assert.equal(remainingLabel("not a date", now), "expirado");
  assert.equal(stateLabel("indeterminate"), "Indeterminado");
  assert.match(pendingToast({ pending_operation_id: "p", state: "pending_approval", expires_at: "2026-11-05T12:05:00Z", operation: "move" }, now), /^Mover aguardando aprovação.*5 min 00 s/);
});

test("an approval that ran, did not run or was repeated says so", () => {
  assert.equal(decisionMessage(202, false), "Aprovado e executado.");
  assert.match(decisionMessage(403, false), /nada foi alterado/i);
  assert.match(decisionMessage(500, false), /respondeu 500/);
  assert.match(decisionMessage(200, true), /não foi executado de novo/);
});

const rule = (capabilities: PolicyRule["capabilities"], extra: Partial<PolicyRule> = {}): PolicyRule => ({ path: "nodes/a/files/mounts/m/**", capabilities, ...extra });

test("only delete and update may ask for approval, and only when the rule grants them", () => {
  assert.equal(canAskApproval(rule(["read", "delete"]), "delete"), true);
  assert.equal(canAskApproval(rule(["read"]), "delete"), false);
  assert.equal(canAskApproval(rule(["write"]), "update"), true);
  assert.equal(canAskApproval(rule(["deny"]), "delete"), false);
  assert.equal(canAskApproval(rule(["delete"], { file_types: { extensions: ["pem"] } }), "delete"), false);
});

test("marks are added once, removed cleanly and pruned when the grant goes away", () => {
  const marked = setApproval(setApproval(rule(["delete", "update"]), "delete", true), "delete", true);
  assert.deepEqual(marked.needs_approval, ["delete"]);
  assert.equal("needs_approval" in setApproval(marked, "delete", false), false);
  const both = setApproval(marked, "update", true);
  assert.deepEqual(pruneApproval({ ...both, capabilities: ["update"] }).needs_approval, ["update"]);
  assert.equal("needs_approval" in pruneApproval({ ...both, capabilities: ["read"] }), false);
  assert.equal("needs_approval" in pruneApproval({ ...both, file_types: { names: [".env"] } }), false);
});

test("the form refuses what the server refuses about marks", () => {
  assert.equal(validateApproval(rule(["delete"])), "");
  assert.equal(validateApproval(rule(["delete"], { needs_approval: ["delete"] })), "");
  assert.match(validateApproval(rule(["read"], { needs_approval: ["delete"] })), /precisa conceder/);
  assert.match(validateApproval(rule(["deny"], { needs_approval: ["delete"] })), /negação/);
  assert.match(validateApproval(rule(["delete"], { needs_approval: ["delete", "delete"] })), /repetidas/);
  assert.match(validateApproval(rule(["delete"], { needs_approval: ["delete"], file_types: { names: ["a"] } })), /por tipo/);
  assert.match(validateApproval(rule(["delete"], { needs_approval: ["sudo" as never] })), /apagar e alterar/);
});

test("the rule sentence mentions the approval", () => {
  const text = describeRule(rule(["read", "delete"], { needs_approval: ["delete"] }));
  assert.match(text, /Permite ler o conteúdo de, apagar\./);
  assert.match(text, /Exige a aprovação de uma pessoa para apagar\./);
  assert.equal(describeApproval(rule(["delete"])), "");
  assert.match(describeApproval(rule(["delete", "update"], { needs_approval: ["delete", "update"] })), /apagar e para alterar, sobrescrever ou mover/);
});
