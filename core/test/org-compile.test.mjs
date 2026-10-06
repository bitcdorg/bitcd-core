// The org declaration — compile + orgmanifest + loader/gate unit tests
// (pure, injected IO, no chain).
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { digestOf } from "../src/protocol.mjs";
import { validateOrg } from "../src/org/schema.mjs";
import { checkInvariants } from "../src/org/invariants.mjs";
import { compileOrg } from "../src/org/compile.mjs";
import { ORG_SCHEMA_FELT, canonicalOrgManifest, orgManifestDigest, validateOrgManifest } from "../src/org/manifest.mjs";
import { loadOrgManifest, makeGate } from "../src/org/loader.mjs";

const EXAMPLE = resolve(new URL(".", import.meta.url).pathname, "../example/bitcd.yaml");
function model() {
  const r = validateOrg(parseYaml(readFileSync(EXAMPLE, "utf8")));
  assert.ok(r.ok, r.errors.join("; "));
  assert.deepEqual(checkInvariants(r.model), []);
  return r.model;
}

// ---------------------------------------------------------------------------
// compile
// ---------------------------------------------------------------------------
test("compile guarantees ceremony completeness (the sealed envelope)", () => {
  const { ceremony } = compileOrg(model());
  const rows = ceremony.policies.map((p) => `${p.prefix}·${p.action}`);
  // GLOBAL gates keep day-2 signer management reachable.
  assert.ok(rows.includes("GLOBAL·SET_ROLE") && rows.includes("GLOBAL·SET_POLICY"));
  // The constitution prefix gets SET_VALUE + TOMBSTONE + SET_POLICY.
  for (const a of ["SET_VALUE", "TOMBSTONE_VALUE", "SET_POLICY"]) assert.ok(rows.includes(`sys·${a}`));
  // The intent-type quartet (mutable: true in the example).
  for (const a of ["SET_VALUE", "TOMBSTONE_VALUE", "SET_STATUS", "SET_POLICY"]) assert.ok(rows.includes(`k8s/rbac·${a}`));
  // The reserved prefix gets ONLY its SET_POLICY gate.
  assert.deepEqual(rows.filter((r) => r.startsWith("aws/iam")), ["aws/iam·SET_POLICY"]);
  // The example org declares no fleet or lock, so nothing is open.
  assert.ok(ceremony.policies.every((p) => p.policy.allow_open === false));
});

test("SET_STATUS names the connector role; mutable SET_POLICY floors min_humans at 1", () => {
  const { ceremony } = compileOrg(model());
  const status = ceremony.policies.find((p) => p.prefix === "k8s/rbac" && p.action === "SET_STATUS");
  assert.equal(status.policy.role, "EXEC_K8S");
  assert.equal(status.policy.threshold, 1);
  const meta = ceremony.policies.find((p) => p.prefix === "k8s/rbac" && p.action === "SET_POLICY");
  assert.ok(meta.policy.min_humans >= 1);
});

test("compile is deterministic (byte-identical manifests, stable source_digest)", () => {
  const a = compileOrg(model());
  const b = compileOrg(model());
  assert.equal(canonicalOrgManifest(a.manifest), canonicalOrgManifest(b.manifest));
  assert.equal(a.manifest.source_digest, b.manifest.source_digest);
});

test("executor configs carry names, never material", () => {
  const { executorConfigs } = compileOrg(model());
  const ec = executorConfigs[0];
  assert.equal(ec.connector, "dev-cluster");
  assert.deepEqual(ec.prefixes, ["k8s/rbac"]);
  assert.ok(ec.env_required.includes("BITCD_RPC"));
  // the executor reads these exact names (it finds the store before the manifest)
  for (const k of ["BITCD_CONTRACT_ADDRESS", "BITCD_S3_ENDPOINT", "BITCD_EXECUTOR_ADDRESS", "BITCD_EXECUTOR_PK"]) assert.ok(ec.env_required.includes(k), k);
  assert.equal(ec.env.BITCD_MANIFEST_KEY, "sys/manifest");
});

// ---------------------------------------------------------------------------
// orgmanifest/v1 + loader + gate
// ---------------------------------------------------------------------------
test("the compiled manifest validates as orgmanifest/v1; decoration is rejected", () => {
  const { manifest } = compileOrg(model());
  assert.deepEqual(validateOrgManifest(manifest).errors, []);
  assert.ok(!validateOrgManifest({ ...manifest, extra: 1 }).ok);
  assert.ok(!validateOrgManifest({ ...manifest, self: { ...manifest.self, quorum: { ...manifest.self.quorum, min_humans: 0 } } }).ok);
});

function chainFixture() {
  const { manifest } = compileOrg(model());
  const blob = canonicalOrgManifest(manifest);
  const digest = orgManifestDigest(manifest);
  const value = { digest, schema_ref: ORG_SCHEMA_FELT, version: 3, tombstoned: false };
  let stored = blob;
  return {
    manifest, blob, digest, value,
    getValue: async () => value,
    getBlob: async () => stored,
    tamper: (t) => { stored = t; },
  };
}

test("loadOrgManifest: verify-on-read happy path + the key-binding check", async () => {
  const fx = chainFixture();
  const r = await loadOrgManifest({ getValue: fx.getValue, getBlob: fx.getBlob, valueKeyStr: "sys/manifest" });
  assert.ok(r.ok, r.reason);
  assert.equal(r.version, 3);
  const wrong = await loadOrgManifest({ getValue: fx.getValue, getBlob: fx.getBlob, valueKeyStr: "sys/other" });
  assert.equal(wrong.ok, false);
  assert.equal(wrong.class, "terminal");
  assert.match(wrong.reason, /key-binding/);
});

test("loadOrgManifest: the terminal ladder (tamper, non-canonical, tombstone, wrong schema)", async () => {
  const fx = chainFixture();
  fx.tamper(fx.blob.replace("chainops", "evil-org"));
  const tampered = await loadOrgManifest({ getValue: fx.getValue, getBlob: fx.getBlob });
  assert.equal(tampered.class, "terminal");
  assert.match(tampered.reason, /TAMPERED/);

  const fx2 = chainFixture();
  const pretty = JSON.stringify(JSON.parse(fx2.blob), null, 2);
  fx2.value.digest = digestOf(pretty); // digest matches, but bytes are decorated
  fx2.tamper(pretty);
  const nc = await loadOrgManifest({ getValue: fx2.getValue, getBlob: fx2.getBlob });
  assert.equal(nc.class, "terminal");
  assert.match(nc.reason, /canonical/);

  const fx3 = chainFixture();
  fx3.value.tombstoned = true;
  assert.match((await loadOrgManifest({ getValue: fx3.getValue, getBlob: fx3.getBlob })).reason, /TOMBSTONED/);

  const fx4 = chainFixture();
  fx4.value.schema_ref = "0x1234";
  assert.match((await loadOrgManifest({ getValue: fx4.getValue, getBlob: fx4.getBlob })).reason, /schema_ref/);
});

test("makeGate: RUN / stale-RUN inside grace / HALT on terminal, HOLD at cold start", async () => {
  const fx = chainFixture();
  let now = 1000;
  let fail = null;
  const load = async () => {
    if (fail) return fail;
    return loadOrgManifest({ getValue: fx.getValue, getBlob: fx.getBlob });
  };
  const gate = makeGate({ load, graceMs: 5000, now: () => now });
  assert.equal((await gate.check()).action, "RUN");
  fail = { ok: false, class: "transient", reason: "chain read failed" };
  now += 4000;
  const stale = await gate.check();
  assert.equal(stale.action, "RUN");
  assert.equal(stale.stale, true);
  now += 6000;
  assert.equal((await gate.check()).action, "HALT");
  fail = { ok: false, class: "terminal", reason: "TAMPERED" };
  assert.equal((await gate.check()).action, "HALT");
  // Cold start under a transient: HOLD inside grace, never RUN.
  let now2 = 0;
  const gate2 = makeGate({ load: async () => ({ ok: false, class: "transient", reason: "s3 down" }), graceMs: 5000, now: () => now2 });
  assert.equal((await gate2.check()).action, "HOLD");
  now2 = 6000;
  assert.equal((await gate2.check()).action, "HALT");
});
