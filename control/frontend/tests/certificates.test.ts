import assert from "node:assert/strict";
import test from "node:test";
import {
  authModeLabel,
  daysLeft,
  expiryLabel,
  expiryTone,
  kindLabel,
  needsAttention,
  nodeStatus,
  nodesOnToken,
  rotationSummary,
  shortFingerprint,
  sortCertificates,
  stateLabel,
} from "../src/lib/certificates.ts";
import type { CertificateItem, NodeCertificate } from "../src/lib/types.ts";

const now = Date.parse("2026-11-06T12:00:00Z");
const day = 24 * 60 * 60 * 1000;
const item = (extra: Partial<CertificateItem> = {}): CertificateItem => ({
  kind: "https",
  subject: "Control Tower",
  state: "active",
  fingerprint: "ab".repeat(32),
  not_before: new Date(now - 30 * day).toISOString(),
  not_after: new Date(now + 60 * day).toISOString(),
  ...extra,
});
const ending = (days: number, extra: Partial<CertificateItem> = {}) => item({ not_after: new Date(now + days * day).toISOString(), ...extra });

test("labels name every kind and state in words", () => {
  assert.equal(kindLabel("root"), "Raiz");
  assert.equal(kindLabel("signing_key"), "Chave de assinatura");
  assert.equal(stateLabel("pending"), "Publicada, ainda não assina");
  assert.equal(stateLabel("retired"), "Em despedida");
});

test("days left never go negative and ignore garbage", () => {
  assert.equal(daysLeft(new Date(now + 3.9 * day).toISOString(), now), 3);
  assert.equal(daysLeft(new Date(now - day).toISOString(), now), 0);
  assert.equal(daysLeft("not a date", now), 0);
});

test("a leaf warns at 14 days and is critical at 2; an issuer warns much earlier", () => {
  assert.equal(expiryTone(ending(60), now), "ok");
  assert.equal(expiryTone(ending(14), now), "warning");
  assert.equal(expiryTone(ending(3), now), "warning");
  assert.equal(expiryTone(ending(2), now), "critical");
  assert.equal(expiryTone(ending(40, { kind: "intermediate" }), now), "warning");
  assert.equal(expiryTone(ending(70, { kind: "intermediate" }), now), "ok");
  assert.equal(expiryTone(ending(10, { kind: "intermediate" }), now), "critical");
  assert.equal(expiryTone(ending(200, { kind: "root" }), now), "warning");
});

test("something that already ended and is in use is critical; one that is leaving is not", () => {
  assert.equal(expiryTone(ending(-1), now), "critical");
  assert.equal(expiryTone(ending(-1, { state: "retired" }), now), "neutral");
  assert.equal(expiryTone(ending(1, { state: "retired" }), now), "neutral");
  assert.equal(expiryTone(ending(1, { state: "pending" }), now), "neutral");
  assert.equal(expiryTone(item({ not_after: "garbage" }), now), "critical");
});

test("the expiry reads in days, then in hours, then says it ended", () => {
  assert.equal(expiryLabel(ending(60), now), "60 dias");
  assert.equal(expiryLabel(ending(1.2), now), "1 dia");
  assert.equal(expiryLabel(ending(0.3), now), "7 horas");
  assert.equal(expiryLabel(ending(0.01), now), "1 hora");
  assert.equal(expiryLabel(ending(-2), now), "Expirado");
});

test("the list reads root, issuers, then what they issued, in-use first", () => {
  const sorted = sortCertificates([
    item({ kind: "signing_key", subject: "old", state: "retired" }),
    item({ kind: "https", subject: "web" }),
    item({ kind: "signing_key", subject: "new" }),
    item({ kind: "root", subject: "root" }),
    item({ kind: "intermediate", subject: "issuer" }),
  ]);
  assert.deepEqual(sorted.map((entry) => entry.subject), ["root", "issuer", "web", "new", "old"]);
});

test("sorting does not touch its input", () => {
  const input = [item({ kind: "signing_key" }), item({ kind: "root" })];
  sortCertificates(input);
  assert.equal(input[0].kind, "signing_key");
});

test("a fingerprint is shortened for a list and left whole when short", () => {
  assert.equal(shortFingerprint("ab".repeat(32)), "abababababababab…");
  assert.equal(shortFingerprint("abcd"), "abcd");
});

test("attention is raised for anything in use that is near its end, and only then", () => {
  assert.equal(needsAttention([ending(60), ending(400, { kind: "root" })], now), false);
  assert.equal(needsAttention([ending(60), ending(5)], now), true);
  assert.equal(needsAttention([ending(1, { state: "retired" })], now), false);
  assert.equal(needsAttention([], now), false);
});

const node = (extra: Partial<NodeCertificate> = {}): NodeCertificate => ({
  node_id: "n1",
  name: "alpha",
  bundle_version: 4,
  bundle_behind: 0,
  cert_serial: "aa",
  cert_not_after: new Date(now + 60 * day).toISOString(),
  auth_mode: "certificate",
  ...extra,
});

test("a node's row names the first thing wrong, in order of how bad it is", () => {
  assert.deepEqual(nodeStatus(node(), now), { tone: "ok", label: "Em dia" });
  assert.deepEqual(nodeStatus(node({ last_error: "send the trust bundle: node unavailable", bundle_behind: 2 }), now), {
    tone: "critical",
    label: "send the trust bundle: node unavailable",
  });
  assert.deepEqual(nodeStatus(node({ bundle_behind: 1 }), now), { tone: "warning", label: "Pacote atrasado em 1 versão" });
  assert.deepEqual(nodeStatus(node({ bundle_behind: 3 }), now), { tone: "warning", label: "Pacote atrasado em 3 versões" });
  assert.equal(nodeStatus(node({ cert_not_after: new Date(now + 5 * day).toISOString() }), now).label, "Certificado vence em 5 dias");
  assert.equal(nodeStatus(node({ cert_not_after: new Date(now + 0.2 * day).toISOString() }), now).label, "Certificado vence em 1 dia");
  assert.deepEqual(nodeStatus(node({ cert_not_after: new Date(now - day).toISOString() }), now), { tone: "critical", label: "Certificado expirado" });
  assert.equal(nodeStatus(node({ cert_not_after: "garbage" }), now).tone, "critical");
});

test("the way a node authenticates the Control Tower is named, and the ones still on the token are counted", () => {
  assert.equal(authModeLabel("certificate"), "Certificado");
  assert.equal(authModeLabel("token"), "Token compartilhado");
  assert.equal(authModeLabel(undefined), "Ainda não informado");
  assert.equal(nodesOnToken([node(), node({ auth_mode: "token" }), node({ auth_mode: undefined }), node({ auth_mode: "token" })]), 2);
});

test("a root rotation is only described while one is under way", () => {
  assert.equal(rotationSummary(undefined), undefined);
  assert.equal(rotationSummary({ phase: "none" }), undefined);
  assert.match(rotationSummary({ phase: "prepared" })?.detail ?? "", /promova/);
  assert.equal(rotationSummary({ phase: "promoted" })?.title, "Raiz nova em uso");
  assert.equal(stateLabel("next"), "Raiz nova, ainda não assina");
});

test("the next root is listed right after the active one", () => {
  const sorted = sortCertificates([item({ kind: "root", state: "retired" }), item({ kind: "root", state: "next" }), item({ kind: "root", state: "active" })]);
  assert.deepEqual(sorted.map((entry) => entry.state), ["active", "next", "retired"]);
});
