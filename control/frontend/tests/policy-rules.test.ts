import assert from "node:assert/strict";
import { test } from "node:test";
import { cleanSelector, describeRule, normalizeCapabilities, parseTokens, validateTypedRule } from "../src/lib/policy-rules.ts";
import type { PolicyRule } from "../src/lib/types.ts";

test("tokens are split on commas and whitespace, trimmed and not repeated", () => {
  assert.deepEqual(parseTokens(" pem, KEY ;p12\n pem  "), ["pem", "KEY", "p12"]);
  assert.deepEqual(parseTokens(""), []);
});

test("a selector keeps only what has entries and drops the dot of an extension", () => {
  assert.deepEqual(cleanSelector({ classes: [], extensions: [".PEM", " key "], names: [] }), { extensions: ["PEM", "key"] });
  assert.equal(cleanSelector(undefined), undefined);
});

test("the form refuses what the server refuses", () => {
  const rule = (file_types: PolicyRule["file_types"], extra: Partial<PolicyRule> = {}): PolicyRule => ({ path: "p", capabilities: ["deny", "read"], file_types, ...extra });
  assert.equal(validateTypedRule({ path: "p", capabilities: ["read"] }), "");
  assert.match(validateTypedRule({ path: "p", capabilities: ["read"], visibility: "visible" }), /só vale/);
  assert.match(validateTypedRule(rule({})), /ao menos uma/);
  assert.match(validateTypedRule(rule({ classes: ["nonsense"] })), /desconhecida/);
  assert.match(validateTypedRule(rule({ extensions: ["a b"] })), /Extensões/);
  assert.match(validateTypedRule(rule({ extensions: ["pem", ".PEM"] })), /repetidas/);
  assert.match(validateTypedRule(rule({ names: ["a/b"] })), /sem barras/);
  assert.match(validateTypedRule(rule({ names: [".."] })), /sem barras/);
  assert.match(validateTypedRule(rule({ extensions: Array.from({ length: 65 }, (_, index) => `e${index}`) })), /no máximo/);
  assert.equal(validateTypedRule(rule({ classes: ["secret"], extensions: ["pem"], names: [".env"] }), { visibility: "hidden" }), "");
});

test("a path denial stands alone but a typed denial may list capabilities", () => {
  assert.deepEqual(normalizeCapabilities(["read", "deny"], "deny", false), ["deny"]);
  assert.deepEqual(normalizeCapabilities(["deny", "read"], "read", false), ["read"]);
  assert.deepEqual(normalizeCapabilities(["deny", "read"], "read", true), ["deny", "read"]);
  assert.deepEqual(normalizeCapabilities(["deny", "read"], "deny", true), ["deny", "read"]);
});

test("a rule is described in words, including what is hidden", () => {
  assert.equal(describeRule({ path: "p", capabilities: ["deny"] }), "Nega todas as operações neste caminho.");
  assert.equal(describeRule({ path: "p", capabilities: ["read", "list"] }), "Permite ler o conteúdo de, listar.");
  const deny = describeRule({ path: "p", capabilities: ["deny", "read"], file_types: { extensions: ["pem"], classes: ["secret"] } });
  assert.match(deny, /Nega ler o conteúdo de arquivos da classe segredo ou com extensão \.pem/);
  assert.match(deny, /ficam ocultos/);
  assert.match(deny, /Pastas não são afetadas/);
  const visible = describeRule({ path: "p", capabilities: ["read", "list"], file_types: { classes: ["video"] }, visibility: "visible" });
  assert.match(visible, /somente arquivos da classe vídeo/);
  assert.match(visible, /bloqueados/);
});
