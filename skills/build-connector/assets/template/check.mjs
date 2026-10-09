#!/usr/bin/env node
// check.mjs — proves the connector against an organization on a local devnet.
//
// It drives the governed side with development keys (two human operators
// sign readable approvals and anyone commits), runs the executor's pass in
// process, and derives the condition the way a reader would. Six checks:
//
//   [1] apply        a quorum commits a document; the pass applies it; derived SYNCED
//   [2] drift        the system is edited behind the executor's back; a drift
//                    scan derives OUTOFSYNC with desired unchanged; the next pass repairs it
//   [3] revision     a quorum commits a new document; derived OUTOFSYNC until the
//                    pass applies it, then SYNCED at the new version
//   [4] failed apply the provider throws; attested FAILED, desired unchanged;
//                    the next pass recovers
//   [5] tombstone    a quorum deletes the value; the pass revokes and attests it
//   [6] gate         a tampered manifest blob halts the executor; restored, it runs
//
// Defaults fit the proof rig in bitcd-core (e2e/bitcd.yaml, onboarded):
//   BITCD_KEYS_FILE         ../bitcd-core/e2e/.onboard-tmp/keys.json
//   BITCD_DEPLOYMENT_FILE   ../bitcd-core/e2e/deployment.json
//   BITCD_CHECK_SIGNERS     agent1,agent2     the approving quorum (keystore names)
//   BITCD_CHECK_EXECUTOR    exec1             the executor (keystore name)
//   BITCD_PREFIX / BITCD_VALUE_KEY / BITCD_SCHEMA / BITCD_SPEC_KEY
//                           iam/acct / iam/acct/pset / iampolicyset/v1 / iam/acct/spec
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { num } from "starknet";
import { account, applyNoProxy, approveWithSigs, bitcdContract, str, waitSucceeded } from "@bitcd/core/client";
import { ACTION, STORAGE_CLASS, digestOf } from "@bitcd/core/protocol";
import { driftCheckOnce, renderConfig } from "@bitcd/core/reconcile";
import { SELECTORS } from "@bitcd/core/events";
import { DEFAULT_MANIFEST_KEY, manifestSpecKey } from "@bitcd/core/org/manifest";
import { sampleDocuments } from "./provider.mjs";

applyNoProxy();
const env = (k, d) => process.env[k] ?? d;
const KEYS_FILE = resolve(env("BITCD_KEYS_FILE", "../bitcd-core/e2e/.onboard-tmp/keys.json"));
process.env.BITCD_DEPLOYMENT_FILE = resolve(env("BITCD_DEPLOYMENT_FILE", "../bitcd-core/e2e/deployment.json"));
const keys = JSON.parse(readFileSync(KEYS_FILE, "utf8"));
const signers = env("BITCD_CHECK_SIGNERS", "agent1,agent2").split(",").map((n) => {
  if (!keys[n]) throw new Error(`no signer "${n}" in ${KEYS_FILE}`);
  return keys[n];
});
const executor = keys[env("BITCD_CHECK_EXECUTOR", "exec1")];
if (!executor) throw new Error(`no executor in ${KEYS_FILE}`);
process.env.BITCD_EXECUTOR_ADDRESS ??= executor.address;
process.env.BITCD_EXECUTOR_PK ??= executor.pk;
process.env.BITCD_LIVE_FILE ??= "./live/check.json";

const PREFIX = env("BITCD_PREFIX", "iam/acct");
const VALUE_KEY = env("BITCD_VALUE_KEY", "iam/acct/pset");
const SCHEMA = env("BITCD_SCHEMA", "iampolicyset/v1");
const SPEC_KEY = env("BITCD_SPEC_KEY", "iam/acct/spec");
const MANIFEST_KEY = env("BITCD_MANIFEST_KEY", DEFAULT_MANIFEST_KEY);
process.env.BITCD_VALUE_KEY = VALUE_KEY;
process.env.BITCD_SPEC_KEY = SPEC_KEY;

const { wire, pass, derived } = await import("./executor.mjs");
const quiet = () => {};
const ctx = wire({ log: quiet });
const { p, dep, view, store, ops, prov } = ctx;
const state = { applied: 0, revokedAt: 0 };

// --- the governed side, with development keys -------------------------------
async function govern(action, params) {
  const proposer = bitcdContract(dep.address, account(signers[0], p));
  const { transaction_hash } = await proposer.propose(action, str(PREFIX), params);
  await waitSucceeded(p, transaction_hash, "propose");
  const receipt = await p.getTransactionReceipt(transaction_hash);
  const events = receipt.events ?? receipt.value?.events ?? [];
  const created = events.find((e) => BigInt(num.toHex(e.keys?.[0])) === BigInt(SELECTORS.ProposalCreated));
  if (!created) throw new Error("no ProposalCreated event in the propose receipt");
  const id = BigInt(created.keys[1]);
  await approveWithSigs({
    contractAddress: dep.address, proposalId: id, action, prefix: str(PREFIX), params,
    signers, relayer: signers[0], p,
  });
  const commit = await proposer.commit(id);
  await waitSucceeded(p, commit.transaction_hash, "commit");
  return id;
}
async function commitDocument(doc) {
  const blob = renderConfig(doc);
  await store.putText(SPEC_KEY, blob);
  const cur = await ops.getValue();
  await govern(ACTION.SET_VALUE, [str(VALUE_KEY), digestOf(blob), str(SCHEMA), STORAGE_CLASS.S3, cur.version]);
  return digestOf(blob);
}
async function tombstone() {
  const cur = await ops.getValue();
  await govern(ACTION.TOMBSTONE_VALUE, [str(VALUE_KEY), cur.version]);
}

// --- the checks ---------------------------------------------------------------
let ok = true;
const check = (cond, msg) => { console.log(`  ${cond ? "PASS" : "FAIL"}  ${msg}`); ok = ok && cond; };
const show = async (label) => {
  const d = await derived(ops);
  console.log(`      => ${d.condition}  desired v${d.desired.version}  observed v${d.observed.observed_revision} (${d.observed.condition || "none"})  ${label}`);
  return d;
};
const [doc1, doc2, doc3] = sampleDocuments();

console.log(`check: ${VALUE_KEY} on ${dep.address} via executor ${executor.address.slice(0, 10)}…`);
await store.ensureBucket();

console.log("\n[1] apply");
const digest1 = await commitDocument(doc1);
const r1 = await pass(ctx, state);
const d1 = await show("after the pass");
check(r1.outcome === "SYNCED" && d1.condition === "SYNCED", "committed document applied and derived SYNCED");
check(await prov.liveExists(), "the managed object exists");

console.log("\n[2] drift");
await prov.applyToProvider(renderConfig({ ...doc1, rogue: "s3:*" })); // behind the executor's back
const before = (await ops.getValue()).digest;
await driftCheckOnce(ops);
const d2 = await show("after a drift scan");
check(d2.condition === "OUTOFSYNC", "an edit behind the executor's back derives OUTOFSYNC");
check(before === (await ops.getValue()).digest, "desired is unchanged by drift");
const r2 = await pass(ctx, state);
const d2b = await show("after the next pass");
check(r2.outcome.startsWith("drift repaired") && d2b.condition === "SYNCED", "the next pass puts it back");

console.log("\n[3] revision");
await commitDocument(doc2);
const lag = await show("committed, executor not yet run");
check(lag.condition === "OUTOFSYNC" && lag.observed.observed_revision < lag.desired.version, "a new revision lags as OUTOFSYNC");
const r3 = await pass(ctx, state);
const d3 = await show("after the pass");
check(r3.outcome === "SYNCED" && d3.condition === "SYNCED" && d3.observed.observed_revision === d3.desired.version, "applied at the new version");

console.log("\n[4] failed apply");
await commitDocument(doc3);
const beforeFail = (await ops.getValue()).digest;
const throwing = { ...ctx, ops: { ...ops, applyToProvider: async () => { throw new Error("system unreachable"); } } };
const r4 = await pass(throwing, state);
const d4 = await show("after a throwing apply");
check(r4.outcome === "FAILED" && r4.reason === "apply-error" && d4.condition === "FAILED", "a throwing provider is attested FAILED");
check(beforeFail === (await ops.getValue()).digest, "desired is unchanged by the failure");
const r4b = await pass(ctx, state);
check(r4b.outcome === "SYNCED" && (await show("after the system is back")).condition === "SYNCED", "recovers on the next pass");

console.log("\n[5] tombstone");
await tombstone();
const r5 = await pass(ctx, state);
const s5 = await ops.getStatus();
check(r5.outcome === "revoked" && !(await prov.liveExists()), "the pass revokes in the system");
check(s5.exists && s5.observed_revision === (await ops.getValue()).version && s5.condition === "SYNCED", "the revoke is attested at the tombstone's version");
const r5b = await pass(ctx, state);
check(r5b.outcome === "revoked" && r5b.version === r5.version, "a second pass does not revoke again");

console.log("\n[6] gate");
const manifestKey = manifestSpecKey(MANIFEST_KEY);
const good = await store.getText(manifestKey);
await store.putText(manifestKey, good + "\n");
const r6 = await pass(ctx, state);
check(r6.action === "HALT", `a tampered manifest halts the executor (${r6.reason ?? ""})`);
await store.putText(manifestKey, good);
const r6b = await pass(ctx, state);
check(r6b.action === "RUN", "the executor runs again once the manifest verifies");

console.log(`\n${ok ? "PASS" : "FAIL"}: apply, drift, revision, failed apply, tombstone and the gate behaved`);
process.exit(ok ? 0 : 1);
