import assert from "node:assert/strict";
import test from "node:test";
import { NODE_YAML_SNIPPET, clampMinutes, enrollmentStateLabel, environmentLine, groupFingerprint, tokenStatus, tokenStatusLabel } from "../src/lib/enrollments.ts";

const now = Date.parse("2026-11-06T12:00:00Z");
const later = "2026-11-06T12:10:00Z";
const earlier = "2026-11-06T11:50:00Z";

test("a token waits for its node until it is used or runs out", () => {
  assert.equal(tokenStatus({ expires_at: later }, now), "waiting");
  assert.equal(tokenStatus({ expires_at: earlier }, now), "expired");
  assert.equal(tokenStatus({ expires_at: later, used_at: earlier }, now), "used");
  assert.equal(tokenStatus({ expires_at: earlier, used_at: earlier }, now), "used");
  assert.equal(tokenStatus({ expires_at: "garbage" }, now), "expired");
  assert.equal(tokenStatus({ expires_at: new Date(now).toISOString() }, now), "expired");
});

test("statuses and states read in words", () => {
  assert.equal(tokenStatusLabel("waiting"), "Aguardando o node");
  assert.equal(tokenStatusLabel("used"), "Usado");
  assert.equal(enrollmentStateLabel("pending"), "Aguardando aprovação");
  assert.equal(enrollmentStateLabel("issued"), "Aprovado");
  assert.equal(enrollmentStateLabel("rejected"), "Rejeitado");
});

test("the environment line and the YAML are what the node needs", () => {
  assert.equal(environmentLine("jolt-join:v1:abc"), "JOLT_JOIN_TOKEN=jolt-join:v1:abc");
  assert.match(NODE_YAML_SNIPPET, /^tls_mode: managed\n/);
  assert.match(NODE_YAML_SNIPPET, /api_public_endpoint: https:\/\//);
});

test("a fingerprint is grouped for two people to read to each other", () => {
  assert.equal(groupFingerprint("abcdef0123456789abcdef0123456789"), "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89");
  assert.equal(groupFingerprint("AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"), "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89");
  assert.equal(groupFingerprint("short"), "short");
  assert.equal(groupFingerprint("abc"), "abc");
  assert.equal(groupFingerprint(""), "");
});

test("the validity stays inside what the server accepts", () => {
  assert.equal(clampMinutes(15), 15);
  assert.equal(clampMinutes(0), 1);
  assert.equal(clampMinutes(-5), 1);
  assert.equal(clampMinutes(99999), 1440);
  assert.equal(clampMinutes(2.6), 3);
  assert.equal(clampMinutes(Number.NaN), 15);
});
