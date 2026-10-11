import assert from "node:assert/strict";
import { test } from "node:test";
import { matchingTransferGrant, transferDestinations, transferGrantAuthorization, transferPeer, transferSourceAccess, transferSourceFolder } from "../src/lib/transfer-access.ts";
import type { Grant, TransferTargetNode, TrustPeer } from "../src/lib/types.ts";

test("a blocked Node A remains selectable alongside a ready destination", () => {
  const ready: TransferTargetNode = { node_id: "c", name: "Node C", available: true, state: "online", mounts: [] };
  const targets = transferDestinations({
    max_source_paths: 1000,
    targets: [ready],
    blocked_targets: [{ node_id: "a", name: "Node A", reasons: ["source_grant_missing", "destination_grant_missing"] }],
  });
  assert.deepEqual(targets.map((target) => target.node_id), ["c", "a"]);
  assert.equal(targets[1].available, false);
  assert.deepEqual(targets[1].reasons, ["source_grant_missing", "destination_grant_missing"]);
  assert.deepEqual(targets[1].mounts, []);
});

test("a blocked-only response presents the destination; refresh makes it ready without duplication", () => {
  const blocked = { node_id: "a", name: "Node A", reasons: ["source_grant_missing" as const] };
  assert.equal(transferDestinations({ max_source_paths: 1000, targets: [], blocked_targets: [blocked] })[0].node_id, "a");
  const ready: TransferTargetNode = { node_id: "a", name: "Node A", available: true, state: "online", mounts: [] };
  assert.deepEqual(transferDestinations({ max_source_paths: 1000, targets: [ready], blocked_targets: [blocked] }), [ready]);
});

test("the suggested source folder covers the entire selection at its common parent", () => {
  assert.equal(transferSourceFolder(["exports/one.txt", "exports/folder/two.txt"]), "exports");
  assert.equal(transferSourceFolder(["exports/one.txt", "other/two.txt"]), "");
  assert.equal(transferSourceFolder(["exports/folder"]), "exports");
  assert.equal(transferSourceFolder(["file.txt"]), "");
  assert.equal(transferSourceFolder(["exports\\one.txt", "exports\\two.txt"]), "exports");
});

test("grant creation uses the authenticated peer identity mapped to the registered destination", () => {
  const peers = [{ node_id: "a-current", registered_node_id: "a", name: "Node A" }] as TrustPeer[];
  assert.equal(transferPeer(peers, "a")?.node_id, "a-current");
  assert.equal(transferPeer(peers, "different"), undefined);
  assert.equal(transferPeer([{ node_id: "a" }] as TrustPeer[], "a")?.node_id, "a");
});

test("reuse disabled or bidirectional grants only for the exact peer, mount and folder", () => {
  const grant: Grant = {
    grant_id: "existing", peer_node_id: "a-current", mount_id: "files", path: ".", direction: "send_receive",
    permissions: { read: true, write: true, rename: false, delete: false }, conflict_policies: ["fail"], visible_to_peer: false, enabled: false,
  };
  assert.equal(matchingTransferGrant([grant], "a-current", "files", "", "send"), grant);
  assert.equal(matchingTransferGrant([grant], "a-current", "files", "", "receive"), grant);
  assert.equal(matchingTransferGrant([grant], "a", "files", "", "send"), undefined);
  assert.equal(matchingTransferGrant([grant], "a-current", "other", "", "send"), undefined);
  assert.equal(matchingTransferGrant([grant], "a-current", "files", "exports", "send"), undefined);
  assert.equal(matchingTransferGrant([{ ...grant, direction: "receive" }], "a-current", "files", "", "send"), undefined);
});

test("copy authorizes reading only; move explicitly requires source deletion", () => {
  const copy = transferGrantAuthorization("a-current", "files", "exports", "send", "copy", "fail");
  assert.deepEqual(copy.permissions, { read: true, write: false, rename: false, delete: false });
  assert.deepEqual(copy.conflict_policies, []);
  assert.equal(copy.visible_to_peer, false);
  assert.equal(copy.enabled, true);
  assert.equal(transferGrantAuthorization("a-current", "files", "exports", "send", "move", "fail").permissions.delete, true);
  const receive = transferGrantAuthorization("b-current", "incoming", "imports", "receive", "move", "rename");
  assert.deepEqual(receive.permissions, { read: false, write: true, rename: false, delete: false });
  assert.deepEqual(receive.conflict_policies, ["rename"]);
});

const readableGrant: Grant = {
  grant_id: "source-read", peer_node_id: "b-current", mount_id: "files", path: ".", direction: "send",
  permissions: { read: true, write: false, rename: false, delete: false }, conflict_policies: [], visible_to_peer: false, enabled: true,
};

test("an active whole-mount sending grant permits copy and identifies the exact missing move permission", () => {
  assert.deepEqual(transferSourceAccess([readableGrant], "b-current", "files", ["photo.png"], "copy"), { status: "ready", grant: readableGrant });
  assert.deepEqual(transferSourceAccess([readableGrant], "b-current", "files", ["photo.png"], "move"), { status: "removal_missing", grant: readableGrant });
  assert.equal(readableGrant.permissions.delete, false);
  const movable = { ...readableGrant, grant_id: "source-move", path: "exports", permissions: { ...readableGrant.permissions, delete: true } };
  assert.deepEqual(transferSourceAccess([readableGrant, movable], "b-current", "files", ["exports/photo.png"], "move"), { status: "ready", grant: movable });
});

test("move diagnostics require one grant covering all roots and respect folder boundaries", () => {
  const exports = { ...readableGrant, path: "exports" };
  assert.equal(transferSourceAccess([exports], "b-current", "files", ["exports/photo.png", "exports/folder"], "move").status, "removal_missing");
  assert.equal(transferSourceAccess([exports], "b-current", "files", ["exports2/photo.png"], "move").status, "missing");
  assert.equal(transferSourceAccess([exports, { ...exports, path: "other" }], "b-current", "files", ["exports/photo.png", "other/photo.png"], "move").status, "missing");
  assert.equal(transferSourceAccess([exports], "b-current", "files", ["exports\\folder\\..\\photo.png"], "copy").status, "ready");
  assert.equal(transferSourceAccess([readableGrant], "b-current", "files", ["../photo.png"], "copy").status, "missing");
  assert.equal(transferSourceAccess([readableGrant], "b-current", "files", [], "move").status, "missing");
});

test("disabled, unreadable, receiving or unrelated grants cannot suggest that only removal is missing", () => {
  for (const grant of [
    { ...readableGrant, enabled: false },
    { ...readableGrant, peer_node_id: "other" },
    { ...readableGrant, mount_id: "other" },
    { ...readableGrant, direction: "receive" as const },
    { ...readableGrant, permissions: { ...readableGrant.permissions, read: false } },
  ]) assert.deepEqual(transferSourceAccess([grant], "b-current", "files", ["photo.png"], "move"), { status: "missing" });
});

test("updating an existing bidirectional authorization preserves its other permissions", () => {
  const existing: Grant = {
    grant_id: "existing", peer_node_id: "a-current", mount_id: "files", path: ".", direction: "send_receive",
    permissions: { read: true, write: true, rename: true, delete: false }, conflict_policies: ["fail"], visible_to_peer: true, enabled: false,
  };
  const send = transferGrantAuthorization("a-current", "files", "", "send", "move", "fail", existing);
  assert.equal(send.direction, "send_receive");
  assert.deepEqual(send.permissions, { read: true, write: true, rename: true, delete: true });
  assert.equal(send.visible_to_peer, true);
  const receive = transferGrantAuthorization("a-current", "files", "", "receive", "copy", "rename", existing);
  assert.deepEqual(receive.conflict_policies, ["fail", "rename"]);
  assert.deepEqual(transferGrantAuthorization("a-current", "files", "", "receive", "copy", "fail", existing).conflict_policies, ["fail"]);
});
