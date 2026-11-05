import assert from "node:assert/strict";
import { test } from "node:test";
import { describeReason, explainCell, outcomeLabel, outcomeSymbol, suggestPath } from "../src/lib/effective-access.ts";

test("every outcome has a label and a symbol that tell them apart", () => {
  const outcomes = ["allowed", "denied", "hidden", "blocked", "approval"] as const;
  assert.equal(new Set(outcomes.map(outcomeLabel)).size, 5);
  assert.equal(new Set(outcomes.map(outcomeSymbol)).size, 5);
});

test("a cell names the policies that decided it and says when a type rule did", () => {
  const text = explainCell({ allowed: false, denied: true, outcome: "blocked", policy_ids: ["p1", "p2"], typed: true }, { p1: "sem-chaves" });
  assert.match(text, /^Bloqueado\./);
  assert.match(text, /403/);
  assert.match(text, /por tipo/);
  assert.match(text, /sem-chaves, p2/);
  const plain = explainCell({ allowed: true, denied: false, outcome: "allowed", policy_ids: [], typed: false }, {});
  assert.doesNotMatch(plain, /Policies envolvidas/);
  assert.doesNotMatch(plain, /por tipo/);
});

test("suggested paths and reasons", () => {
  assert.equal(suggestPath("a", "m"), "nodes/a/files/mounts/m");
  assert.equal(suggestPath("a", undefined), "nodes/a");
  assert.equal(suggestPath(undefined, undefined), "nodes/*");
  assert.match(describeReason("node_not_in_group"), /grupo de acesso/);
  assert.equal(describeReason(undefined), "");
  assert.equal(describeReason("other"), "other");
});
