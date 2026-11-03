import assert from "node:assert/strict";
import { test } from "node:test";
import { fileEntryDisplayName, safeDisplayName, safeDisplayPath } from "../src/lib/display-name.ts";

test("file labels neutralize control and bidirectional characters while keeping canonical paths", () => {
  const entry = { name: "report\u001b[31m\u202e.txt", path: "folder/report\u001b[31m\u202e.txt" };
  assert.equal(fileEntryDisplayName(entry), "report⟦U+001B⟧[31m⟦U+202E⟧.txt");
  assert.equal(safeDisplayPath(entry.path), "folder/report⟦U+001B⟧[31m⟦U+202E⟧.txt");
  assert.equal(entry.path, "folder/report\u001b[31m\u202e.txt");
  assert.equal(fileEntryDisplayName({ ...entry, display_name: "safe\u2066label" }), "safe⟦U+2066⟧label");
});

test("file labels bound long names by Unicode code point", () => {
  assert.equal(safeDisplayName("😀".repeat(256)), "😀".repeat(255) + "…");
  assert.equal(safeDisplayName("ação.txt"), "ação.txt");
  const expanded = "⟦U+001B⟧".repeat(255);
  assert.equal(fileEntryDisplayName({ name: "\u001b".repeat(255), display_name: expanded }), expanded);
});
