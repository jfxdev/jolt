import assert from "node:assert/strict";
import { test } from "node:test";
import { destructivePlanDescription } from "../src/lib/destructive-plan.ts";
import { entryFolder, entryName, remainingRetention, removeDescription, removedNotice, restoreErrorMessage, trashDays } from "../src/lib/trash.ts";

const withTrash = { trash: { enabled: true, retention_days: 30 } };

test("a mount says whether deleting is recoverable", () => {
  assert.equal(trashDays(withTrash), 30);
  assert.equal(trashDays({ trash: { enabled: false, retention_days: 30 } }), 0);
  assert.equal(trashDays({}), 0);
  assert.equal(trashDays(null), 0);
  assert.match(removeDescription(withTrash) ?? "", /lixeira.*30 dias/);
  assert.match(removeDescription({ trash: { enabled: true, retention_days: 1 } }) ?? "", /1 dia\./);
  assert.match(removeDescription({}) ?? "", /não pode ser desfeita/);
  assert.equal(removedNotice(withTrash), "Item enviado para a lixeira.");
  assert.equal(removedNotice({}), "Item removido.");
});

test("a tree delete says it goes to the trash only when it does", () => {
  const plan = { plan_id: "p", token: "t", expires_at: "", operation: "delete" as const, mount_id: "m", source_path: "x", files: 2, directories: 3, bytes: 2048 };
  assert.match(destructivePlanDescription(plan), /removidos permanentemente/);
  const kept = destructivePlanDescription(plan, 30);
  assert.match(kept, /movidos para a lixeira/);
  assert.match(kept, /30 dias/);
  assert.doesNotMatch(kept, /permanentemente/);
  assert.doesNotMatch(destructivePlanDescription({ ...plan, operation: "move" }, 30), /lixeira/);
});

test("the time left reads in the unit that matters", () => {
  const now = Date.parse("2026-11-06T12:00:00Z");
  assert.equal(remainingRetention("2026-12-06T12:00:00Z", now), "30 dias");
  assert.equal(remainingRetention("2026-11-08T12:00:00Z", now), "2 dias");
  assert.equal(remainingRetention("2026-11-07T11:00:00Z", now), "23 h");
  assert.equal(remainingRetention("2026-11-06T12:30:00Z", now), "menos de 1 h");
  assert.equal(remainingRetention("2026-11-06T11:59:00Z", now), "expirando");
  assert.equal(remainingRetention("nonsense", now), "expirando");
});

test("an entry shows its name and where it was", () => {
  assert.equal(entryName({ path: "docs/old/report.txt" }), "report.txt");
  assert.equal(entryFolder({ path: "docs/old/report.txt" }), "/docs/old");
  assert.equal(entryName({ path: "report.txt" }), "report.txt");
  assert.equal(entryFolder({ path: "report.txt" }), "/");
});

test("a failed restore explains what to do", () => {
  assert.match(restoreErrorMessage("conflict") ?? "", /Renomeie ou remova/);
  assert.match(restoreErrorMessage("trash_not_found") ?? "", /Recrie a pasta/);
  assert.equal(restoreErrorMessage("something_else"), undefined);
  assert.equal(restoreErrorMessage(undefined), undefined);
});
