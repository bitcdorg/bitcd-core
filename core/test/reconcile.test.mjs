// Unit tests for the executor engine with fully injected IO: the derivation
// truth table, the canonical render, and every reconcileOnce/driftCheckOnce
// branch — including the two that must NEVER apply (tamper, missing spec).
// The e2e beats prove these dynamically against a devnet; this is the fast
// regression for the pure logic.
import test from "node:test";
import assert from "node:assert/strict";
import { CONDITION, deriveCondition, driftCheckOnce, reconcileOnce, renderConfig } from "../src/reconcile.mjs";
import { digestOf } from "../src/protocol.mjs";

function fakeOps({ spec = "{}", digest = digestOf("{}"), version = 3, tombstoned = false, live, specMissing = false, liveMissing = false } = {}) {
  const calls = { applied: [], status: [] };
  const state = { live: live ?? null };
  const ops = {
    getValue: async () => ({ digest, schema_ref: "s", storage_class: "S3", version, tombstoned }),
    getStatus: async () => ({ exists: false }),
    getSpecBlob: async () => {
      if (specMissing) throw new Error("NoSuchKey");
      return spec;
    },
    getLiveBlob: async () => {
      if (liveMissing) throw new Error("gone");
      return state.live ?? spec;
    },
    applyToProvider: async (text) => {
      calls.applied.push(text);
      state.live = text;
    },
    setStatus: async (s) => calls.status.push(s),
    digestOf,
  };
  return { ops, calls, state };
}

test("deriveCondition: caught up + matching digest => SYNCED", () => {
  assert.equal(
    deriveCondition({ desiredVersion: 3, desiredDigest: "0x0A", observedRevision: 3, observedDigest: "0xa", claimed: CONDITION.SYNCED }),
    CONDITION.SYNCED,
    "digest comparison is numeric, not string",
  );
});

test("deriveCondition: revision lag => OUTOFSYNC even when the executor claims SYNCED", () => {
  assert.equal(
    deriveCondition({ desiredVersion: 4, desiredDigest: "0xa", observedRevision: 3, observedDigest: "0xa", claimed: CONDITION.SYNCED }),
    CONDITION.OUTOFSYNC,
  );
});

test("deriveCondition: digest mismatch + claimed FAILED => FAILED, otherwise OUTOFSYNC", () => {
  const base = { desiredVersion: 3, desiredDigest: "0xa", observedRevision: 3, observedDigest: "0xb" };
  assert.equal(deriveCondition({ ...base, claimed: CONDITION.FAILED }), CONDITION.FAILED);
  assert.equal(deriveCondition({ ...base, claimed: CONDITION.SYNCED }), CONDITION.OUTOFSYNC);
});

test("renderConfig: recursive key sort, arrays keep order", () => {
  assert.equal(
    renderConfig({ b: { z: 1, a: [3, 1, { y: 0, x: 0 }] }, a: 2 }),
    '{"a":2,"b":{"a":[3,1,{"x":0,"y":0}],"z":1}}',
  );
});

test("reconcileOnce happy path: verify -> apply -> attest SYNCED at the desired revision", async () => {
  const spec = renderConfig({ policy: "v2" });
  const { ops, calls } = fakeOps({ spec, digest: digestOf(spec) });
  const r = await reconcileOnce(ops);
  assert.equal(r.condition, CONDITION.SYNCED);
  assert.deepEqual(calls.applied, [spec]);
  assert.equal(calls.status.length, 1);
  assert.equal(calls.status[0].condition, CONDITION.SYNCED);
  assert.equal(calls.status[0].observed_revision, 3);
  assert.equal(BigInt(calls.status[0].applied_hash), BigInt(digestOf(spec)));
});

test("verify-on-read: a tampered spec blob is NEVER applied and attests FAILED", async () => {
  const { ops, calls } = fakeOps({ spec: "tampered bytes", digest: digestOf("the real spec") });
  const r = await reconcileOnce(ops);
  assert.equal(r.condition, CONDITION.FAILED);
  assert.equal(r.reason, "spec-tamper");
  assert.deepEqual(calls.applied, [], "applyToProvider must not run");
  assert.deepEqual(calls.status, [
    { observed_revision: 3, applied_hash: "0x0", condition: CONDITION.FAILED, reason: "spec-tamper" },
  ]);
});

test("a missing spec blob attests FAILED (spec-missing), never applies", async () => {
  const { ops, calls } = fakeOps({ specMissing: true });
  const r = await reconcileOnce(ops);
  assert.equal(r.condition, CONDITION.FAILED);
  assert.equal(r.reason, "spec-missing");
  assert.deepEqual(calls.applied, []);
});

test("a tombstoned value short-circuits: no apply, no attestation", async () => {
  const { ops, calls } = fakeOps({ tombstoned: true, version: 5 });
  const r = await reconcileOnce(ops);
  assert.deepEqual(r, { condition: "TOMBSTONED", version: 5 });
  assert.deepEqual(calls.applied, []);
  assert.deepEqual(calls.status, []);
});

test("a failed apply attests FAILED and desired is untouched (rollback = new revision)", async () => {
  const spec = "the spec";
  const { ops, calls } = fakeOps({ spec, digest: digestOf(spec) });
  const r = await reconcileOnce(ops, { failApply: true });
  assert.equal(r.condition, CONDITION.FAILED);
  assert.equal(r.reason, "apply-error");
  assert.deepEqual(calls.applied, []);
});

test("driftCheckOnce: an out-of-band live edit surfaces via the reader derivation", async () => {
  const spec = "the spec";
  const { ops, calls } = fakeOps({ spec, digest: digestOf(spec), live: "edited out of band" });
  const r = await driftCheckOnce(ops);
  // The executor attests what it OBSERVED (claimed SYNCED, the live hash)…
  assert.equal(calls.status.length, 1);
  assert.equal(BigInt(calls.status[0].applied_hash), BigInt(digestOf("edited out of band")));
  // …and the READER derives the drift; the contract never computes Synced.
  const derived = deriveCondition({
    desiredVersion: r.version,
    desiredDigest: r.desiredDigest,
    observedRevision: r.version,
    observedDigest: r.observedDigest,
    claimed: r.condition,
  });
  assert.equal(derived, CONDITION.OUTOFSYNC);
});

test("a vanished live object attests the 0x0 sentinel", async () => {
  const spec = "the spec";
  const { ops, calls } = fakeOps({ spec, digest: digestOf(spec), liveMissing: true });
  const r = await driftCheckOnce(ops);
  assert.equal(r.present, false);
  assert.equal(calls.status[0].applied_hash, "0x0");
});

test("an apply that throws is reported FAILED (apply-error), never left looking applied", async () => {
  const reports = [];
  const spec = "{\"a\":1}";
  const ops = {
    getValue: async () => ({ digest: digestOf(spec), version: 3, tombstoned: false }),
    getSpecBlob: async () => spec,
    getLiveBlob: async () => { throw new Error("unreachable"); },
    applyToProvider: async () => { throw new Error("provider down"); },
    setStatus: async (s) => { reports.push(s); },
    digestOf,
  };
  const r = await reconcileOnce(ops);
  assert.equal(r.condition, "FAILED");
  assert.equal(r.reason, "apply-error");
  assert.equal(r.error, "provider down");
  assert.deepEqual(reports, [{ observed_revision: 3, applied_hash: "0x0", condition: "FAILED", reason: "apply-error" }]);

  const again = await reconcileOnce(ops, { reportFailure: false });
  assert.equal(again.condition, "FAILED");
  assert.equal(reports.length, 1, "a repeat failure is not re-reported");
});

test("reportFailure: false also quiets a repeated document failure", async () => {
  const reports = [];
  const ops = {
    getValue: async () => ({ digest: "0x1", version: 2, tombstoned: false }),
    getSpecBlob: async () => "tampered",
    setStatus: async (s) => { reports.push(s); },
    digestOf,
  };
  assert.equal((await reconcileOnce(ops)).reason, "spec-tamper");
  assert.equal((await reconcileOnce(ops, { reportFailure: false })).reason, "spec-tamper");
  assert.equal(reports.length, 1);
});
