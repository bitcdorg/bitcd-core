// Reconcile, single provider. The control-plane loop closes:
// a GOVERNED desired state (consensus-written) is driven onto a live provider by an
// off-chain executor that ATTESTS what it observed (single-writer, executor-role).
// Five beats, each PASS/FAIL:
//
//   [1] reconcile     — quorum commits desired v1 -> executor applies -> SYNCED
//   [2] drift         — out-of-band edit to the live provider -> OUTOFSYNC, the
//                       on-chain DESIRED unchanged
//   [3] reconverge    — executor re-applies -> SYNCED again
//   [4] new revision  — quorum commits desired v2; BEFORE the executor runs the
//                       derived state is OUTOFSYNC (observed_revision lag), then
//                       the executor applies -> SYNCED at v2
//   [5] failed apply  — executor's apply fails -> FAILED, desired NEVER rewritten
//                       (rollback would be a new governed revision), then recovers
//
// Provider surface = ministack S3 (reproducible; a real IAM adapter is a
// daemon-only swap — see the chainops aws-iam provider). The chain stores only
// digests; verify-on-read gates the spec blob. Spec writes are a 2-of
// quorum (agent1+agent2); status writes are the EXEC_IAM executor (account #4).
import { hash, num } from "starknet";
import {
  ACTION, AGENTS, EXECUTOR, IAM_LIVE_S3_KEY, IAM_PREFIX, IAM_SCHEMA, IAM_SPEC_S3_KEY,
  IAM_VALUE, STORAGE_CLASS_S3,
  account, bitcd, loadDeployment, provider,
} from "./config.mjs";
import { sampleConfig } from "@bitcd/core/fixtures";
import { CONDITION as C, driftCheckOnce, makeChainOps, reconcileOnce, renderConfig } from "@bitcd/core/reconcile";
import { digestOf, s3Store } from "@bitcd/core/store";
import { approveWithSigs } from "./config.mjs";

const p = provider();
const dep = loadDeployment();
const view = bitcd(dep.address, p);
const exec = bitcd(dep.address, account(EXECUTOR, p));
const store = s3Store();
const putObj = (Key, Body) => store.putText(Key, Body);
const ensureBucket = () => store.ensureBucket();

// --- injected ops the shared reconcile core uses (@bitcd/core/reconcile) ---------
const ops = makeChainOps({
  view, writer: exec, provider: p, valueKey: IAM_VALUE,
  store, specKey: IAM_SPEC_S3_KEY, liveKey: IAM_LIVE_S3_KEY,
  log: (m) => console.log(`      · ${m}`),
});

// Governed (consensus-written) desired-state commit: agent1 proposes, agent1+agent2
// approve, anyone commits — the 2-of-OPERATOR quorum on (iam/acct, SET_VALUE) IS the
// write capability. The executor has NO path to write desired.
async function commitDesired(config) {
  const blob = renderConfig(config);
  await putObj(IAM_SPEC_S3_KEY, blob); // the bytes live off-chain
  const digest = digestOf(blob);
  const cur = await view.get_value(IAM_VALUE);
  const expected = Number(cur.version);
  const params = [IAM_VALUE, digest, IAM_SCHEMA, STORAGE_CLASS_S3, expected];

  const a1 = bitcd(dep.address, account(AGENTS.agent1, p));
  const { transaction_hash } = await a1.propose(ACTION.SET_VALUE, IAM_PREFIX, params);
  await p.waitForTransaction(transaction_hash);
  const receipt = await p.getTransactionReceipt(transaction_hash);
  const sel = "0x" + hash.starknetKeccak("ProposalCreated").toString(16);
  const evs = receipt.events ?? receipt.value?.events ?? [];
  const id = BigInt(evs.find((ev) => num.toHex(ev.keys?.[0]) === sel).keys[1]);
  // A governed (min_humans>=1) SET_VALUE is approved by HUMANS signing
  // readable intent (SNIP-12) — raw approve() does not count toward min_humans.
  // An untrusted relayer submits the collected signatures; then anyone commits.
  await approveWithSigs({
    contractAddress: dep.address, proposalId: id, action: ACTION.SET_VALUE, prefix: IAM_PREFIX,
    params, signers: [AGENTS.agent1, AGENTS.agent2], relayer: AGENTS.agent1, p,
  });
  const cm = await a1.commit(id);
  await p.waitForTransaction(cm.transaction_hash);
  return { digest, version: expected + 1 };
}

// The indexer/reader's DERIVED truth (independent of the executor's self-report):
// Synced iff observed caught up to desired AND observed digest == desired digest.
async function derived() {
  const v = await ops.getValue();
  const s = await ops.getStatus();
  const caughtUp = s.exists && s.observed_revision >= v.version;
  const matches = s.exists && BigInt(s.observed_digest) === BigInt(v.digest);
  let state = "OUTOFSYNC";
  if (s.exists && s.condition === "DISAGREE") state = "DISAGREE";
  else if (caughtUp && matches) state = "SYNCED";
  else if (s.exists && s.condition === "FAILED") state = "FAILED";
  return { state, desiredVersion: v.version, observedRevision: s.observed_revision, claimed: s.condition };
}
const show = async (label) => {
  const d = await derived();
  console.log(`      => derived=${d.state}  desiredRev=${d.desiredVersion} observedRev=${d.observedRevision} claimed=${d.claimed}  (${label})`);
  return d;
};

console.log(`reconcile demo on ${dep.address}`);
console.log(`  prefix=iam/acct  key=iam/acct/pset  provider=S3(${store.bucket})  executor=${EXECUTOR.address.slice(0, 10)}`);
await ensureBucket();

let pass = true;
const check = (cond, msg) => { console.log(`  ${cond ? "PASS" : "FAIL"}  ${msg}`); pass = pass && cond; };

console.log("\n[1] reconcile — quorum commits desired v1, executor applies");
const d1 = await commitDesired(sampleConfig({ serial: 1 }));
console.log(`  desired committed: digest=${d1.digest.slice(0, 12)} v${d1.version} (2-of-OPERATOR quorum)`);
const r1 = await reconcileOnce(ops);
const s1 = await show("after reconcile");
check(s1.state === "SYNCED", "executor applied -> SYNCED (derived)");

console.log("\n[2] drift — overwrite the live provider out-of-band (desired untouched)");
await putObj(IAM_LIVE_S3_KEY, renderConfig({ ...sampleConfig({ serial: 1 }), DRIFTED: true, rogue: "s3:*" }));
const desiredBefore = (await ops.getValue()).digest;
await driftCheckOnce(ops);
const s2 = await show("after drift scan");
const desiredAfter = (await ops.getValue()).digest;
check(s2.state === "OUTOFSYNC", "drift detected -> OUTOFSYNC (derived; executor attested the live hash)");
check(desiredBefore === desiredAfter, "desired digest UNCHANGED across drift");

console.log("\n[3] reconverge — executor re-applies the verified desired");
await reconcileOnce(ops);
const s3v = await show("after reconverge");
check(s3v.state === "SYNCED", "re-apply -> SYNCED");

console.log("\n[4] new revision — quorum commits desired v2; lag shows before the executor runs");
const d4 = await commitDesired(sampleConfig({ serial: 2, allowDelete: true }));
console.log(`  desired bumped: digest=${d4.digest.slice(0, 12)} v${d4.version}`);
const lag = await show("desired v2, executor not yet run");
check(lag.state === "OUTOFSYNC" && lag.observedRevision < lag.desiredVersion, "revision lag -> OUTOFSYNC");
await reconcileOnce(ops);
const s4 = await show("after reconcile v2");
check(s4.state === "SYNCED" && s4.observedRevision === d4.version, "applied v2 -> SYNCED");

console.log("\n[5] failed apply — executor errors; desired is NEVER rewritten");
const desiredBeforeFail = (await ops.getValue()).digest;
const r5 = await reconcileOnce(ops, { failApply: true });
const s5 = await show("after failed apply");
const desiredAfterFail = (await ops.getValue()).digest;
check(r5.condition === C.FAILED && s5.claimed === "FAILED", "apply error -> FAILED reported");
check(desiredBeforeFail === desiredAfterFail, "desired digest UNCHANGED across failure");
const r5b = await reconcileOnce(ops);
check(r5b.condition === C.SYNCED, "recovers on next successful reconcile");

console.log("\n[5b] a provider that throws — reported FAILED on chain, never left looking applied");
const throwing = { ...ops, applyToProvider: async () => { throw new Error("provider unreachable"); } };
const r5c = await reconcileOnce(throwing);
const s5c = await show("after a throwing apply");
check(r5c.condition === C.FAILED && r5c.reason === "apply-error" && s5c.claimed === "FAILED",
  "an exception from applyToProvider is attested FAILED (apply-error), not swallowed");
const r5d = await reconcileOnce(ops);
check(r5d.condition === C.SYNCED && (await show("after the provider is back")).state === "SYNCED", "recovers once the provider answers again");

console.log(`\n${pass ? "PASS" : "FAIL"}: reconcile + drift + new-revision + failed-apply all behaved`);
process.exit(pass ? 0 : 1);
