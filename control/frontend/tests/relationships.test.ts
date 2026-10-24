import assert from "node:assert/strict";
import { test } from "node:test";
import { relationshipAccessSummary, relationshipHref, relationshipKey, relationshipLinks, type RelationshipInventory } from "../src/lib/relationships.ts";
import type { Grant, NodeInfo, TrustPeer } from "../src/lib/types.ts";

const a = { node_id: "a", name: "Node A", state: "online", endpoint: "http://a" } as NodeInfo;
const b = { node_id: "b", name: "Node B", state: "online", endpoint: "http://b" } as NodeInfo;
const grant = { grant_id: "grant", peer_node_id: "b-current", mount_id: "files", path: ".", direction: "send_receive", permissions: { read: true, write: true, delete: false, rename: false }, enabled: true, visible_to_peer: false, conflict_policies: ["fail"] } as Grant;
const peer = { node_id: "b-current", registered_node_id: "b", name: "Node B", trust_status: "connected", grants: [grant] } as TrustPeer;
const entry: RelationshipInventory = { node: a, peers: [peer], canListGrants: true };

test("reciprocal peers with changed IDs produce one relationship using registered nodes", () => {
  const reciprocal = { node: b, peers: [{ ...peer, node_id: "a-current", registered_node_id: "a" }], canListGrants: true };
  const links = relationshipLinks([entry, reciprocal], [a, b]);
  assert.equal(links.length, 1);
  assert.equal(links[0].key, "a:b");
  assert.equal(links[0].target?.name, "Node B");
  assert.equal(relationshipKey("b", "a"), links[0].key);
});

test("a relationship remains visible when only one side holds its peer record", () => {
  const links = relationshipLinks([{ ...entry, peers: [{ ...peer, trust_status: "missing_on_peer" }] }], [a, b]);
  assert.equal(links.length, 1);
  assert.equal(links[0].peer.trust_status, "missing_on_peer");
  assert.equal(links[0].target?.node_id, "b");
});

test("the summary counts active readable sending and writable receiving authorizations", () => {
  assert.equal(relationshipAccessSummary(entry, "b"), "Envio: 1 · Recebimento: 1");
  const entries = { ...entry, peers: [{ ...peer, grants: [
    { ...grant, enabled: false },
    { ...grant, grant_id: "send", direction: "send" as const, permissions: { ...grant.permissions, write: false } },
    { ...grant, grant_id: "invalid", permissions: { ...grant.permissions, read: false, write: false } },
  ] }] };
  assert.equal(relationshipAccessSummary(entries, "b"), "Envio: 1 · Recebimento: 0");
});

test("restricted grants are distinguished from an empty set without leaking their counts", () => {
  assert.equal(relationshipAccessSummary({ ...entry, canListGrants: false }, "b"), "Permissões indisponíveis");
  assert.equal(relationshipAccessSummary(undefined, "b"), "Permissões indisponíveis");
  assert.equal(relationshipAccessSummary({ ...entry, peers: [{ ...peer, grants: [] }] }, "b"), "Sem acesso a arquivos");
});

test("trust links include both exact registered IDs and encode their URL parameters", () => {
  const parsed = new URL(relationshipHref("a/id", "b&id"), "http://localhost");
  assert.equal(parsed.pathname, "/relationships");
  assert.equal(parsed.searchParams.get("source"), "a/id");
  assert.equal(parsed.searchParams.get("target"), "b&id");
});

test("configured authorizations remain inactive while revoked or awaiting trust", () => {
  const inactive = { ...entry, peers: [{ ...peer, grants: [
    { ...grant, enabled: false, configured_enabled: true, inactive_reason: "revoked" },
    { ...grant, grant_id: "pending", enabled: false, configured_enabled: true, inactive_reason: "peer_untrusted" },
  ] }] };
  assert.equal(relationshipAccessSummary(inactive, "b"), "Sem acesso a arquivos");
});
