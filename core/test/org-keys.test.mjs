// The key-template and store-key grammar the declaration and every writer share.
import test from "node:test";
import assert from "node:assert/strict";
import { SCHEMA_REF_RE, expandKey, specKeyFor, templateFields } from "../src/org/keys.mjs";

test("expandKey substitutes, checks segments, and enforces the felt cap", () => {
  assert.equal(expandKey("k8s/rbac/{ns}/{name}", { ns: "team-a", name: "dr" }), "k8s/rbac/team-a/dr");
  assert.deepEqual(templateFields("k8s/rbac/{ns}/{name}"), ["ns", "name"]);
  assert.throws(() => expandKey("k8s/rbac/{ns}/{name}", { ns: "team-a" }), /missing param "name"/);
  assert.throws(() => expandKey("k8s/rbac/{ns}", { ns: "a/b" }), /not key-safe/);
  assert.throws(() => expandKey("k8s/rbac/{ns}", { ns: "x".repeat(30) }), /31/);
});

test("specKeyFor is the <value_key>/spec convention", () => {
  assert.equal(specKeyFor("k8s/rbac/team-a/dr"), "k8s/rbac/team-a/dr/spec");
});

test("a schema ref is <name>/v<N>", () => {
  assert.ok(SCHEMA_REF_RE.test("k8srbacgrant/v1"));
  assert.ok(!SCHEMA_REF_RE.test("k8srbacgrant"));
  assert.ok(!SCHEMA_REF_RE.test("K8sGrant/v1"));
});
