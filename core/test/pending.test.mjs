// The pending side channel: a proposed blob waits beside its proposal, and
// only a blob hashing to the COMMITTED digest is ever copied into place.
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { locateCommitted, pendingBlobKey, pendingParamsKey, promoteCommitted, publishPending } from "../src/pending.mjs";

const digestOf = (t) => "0x" + createHash("sha256").update(t).digest("hex");
const memStore = () => {
  const m = new Map();
  return {
    m,
    getText: async (k) => { if (!m.has(k)) throw new Error(`NoSuchKey ${k}`); return m.get(k); },
    putText: async (k, v) => { m.set(k, v); },
  };
};

test("publishPending writes the blob and params beside the proposal, never the spec", async () => {
  const store = memStore();
  await publishPending(store, "k8s/rbac", 7, "{\"v\":2}", [1n, 2n]);
  assert.equal(store.m.get(pendingBlobKey("k8s/rbac", 7)), "{\"v\":2}");
  assert.deepEqual(JSON.parse(store.m.get(pendingParamsKey("k8s/rbac", 7))), { params: ["1", "2"] });
  assert.equal([...store.m.keys()].some((k) => k.endsWith("/spec")), false);
});

test("promoteCommitted copies only the blob that hashes to the committed digest", async () => {
  const store = memStore();
  const spec = "k8s/rbac/team-a/x/spec";
  store.m.set(spec, "{\"v\":1}");
  await publishPending(store, "k8s/rbac", 8, "{\"v\":\"other\"}", []);
  await publishPending(store, "k8s/rbac", 9, "{\"v\":2}", []);
  const r = await promoteCommitted({ store, specKey: spec, digest: digestOf("{\"v\":2}"), prefixStr: "k8s/rbac", proposalIds: [8, 9], digestOf });
  assert.equal(r, 9);
  assert.equal(store.m.get(spec), "{\"v\":2}");
});

test("promoteCommitted leaves a verifying spec alone and refuses when nothing matches", async () => {
  const store = memStore();
  const spec = "k/spec";
  store.m.set(spec, "good");
  assert.equal(await promoteCommitted({ store, specKey: spec, digest: digestOf("good"), prefixStr: "k", proposalIds: [1], digestOf }), "current");
  await publishPending(store, "k", 2, "forged", []);
  assert.equal(await promoteCommitted({ store, specKey: spec, digest: digestOf("committed"), prefixStr: "k", proposalIds: [2, 3], digestOf }), null);
  assert.equal(store.m.get(spec), "good", "a non-matching candidate is never copied");
});

test("locateCommitted finds the committed bytes without writing anything", async () => {
  const store = memStore();
  const spec = "k/spec";
  store.m.set(spec, "old");
  await publishPending(store, "k", 4, "new", []);
  const before = new Map(store.m);
  const found = await locateCommitted({ store, specKey: spec, digest: digestOf("new"), prefixStr: "k", proposalIds: [4], digestOf });
  assert.deepEqual(found, { key: pendingBlobKey("k", 4), proposalId: 4, text: "new" });
  assert.deepEqual(store.m, before, "read-only");
});
