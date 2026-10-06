// Governed-state demo: the untrusted-storage boundary, end-to-end.
//   1. agent1 holds the lock, writes a state blob to S3 (ministack) and commits
//      its digest + version on-chain via set_value (single-writer fast path).
//   2. verify-on-read: re-fetch the blob, recompute the digest, compare to chain
//      -> VERIFIED.
//   3. tamper the S3 object out-of-band (chain digest untouched) and verify again
//      -> MISMATCH, the boundary rejects it.
// The chain is a control plane, not a data plane: only the digest lives
// on-chain; the bytes live in S3.
import { digestOf, s3Store } from "@bitcd/core/store";
import {
  AGENTS, PREFIX, SCHEMA_REF, STORAGE_CLASS_S3, VALUE,
  account, bitcd, loadDeployment, provider, str,
} from "./config.mjs";

// Dedicated lock key for the storage demo, under the same governed PREFIX (open
// ACQUIRE + SET_VALUE). Distinct from the contention LOCK so this step is
// independent of where `contend` left that lock (held by the expiry handover).
const LOCK = str("tf/state/store");

const S3_KEY = process.env.BITCD_S3_KEY ?? "tf/lock/state";

const p = provider();
const dep = loadDeployment();
const conn = (a) => bitcd(dep.address, account(a, p));
const view = bitcd(dep.address, p);

const store = s3Store();
const putBlob = (body) => store.putText(S3_KEY, body);
const getBlob = () => store.getText(S3_KEY);
const ensureBucket = () => store.ensureBucket();

// verify-on-read: chain digest is canonical; recompute the blob's and compare.
async function verify(label) {
  const rec = await view.get_value(VALUE);
  const blob = await getBlob();
  const chain = BigInt(rec.digest);
  const have = BigInt(digestOf(blob));
  const ok = chain === have;
  console.log(`  ${ok ? "VERIFIED" : "MISMATCH"}  ${label}  chain=${chain.toString(16).slice(0, 12)} blob=${have.toString(16).slice(0, 12)} v${rec.version}`);
  return ok;
}

console.log(`governed-state demo on ${dep.address}  (S3 ${store.bucket}/${S3_KEY})`);
await ensureBucket();

console.log("\n[1] agent1 acquires the lock, writes state to S3 + commits the digest");
const c = conn(AGENTS.agent1);
{
  const { transaction_hash } = await c.acquire_lock(LOCK, PREFIX, 0n, 0n);
  await p.waitForTransaction(transaction_hash);
}
const blob = JSON.stringify({ version: 4, serial: 1, lineage: "harness-demo", outputs: {}, resources: [] });
await putBlob(blob);
{
  const prev = await view.get_value(VALUE);
  const { transaction_hash } = await c.set_value(VALUE, LOCK, digestOf(blob), SCHEMA_REF, STORAGE_CLASS_S3, prev.version);
  await p.waitForTransaction(transaction_hash);
  console.log(`  committed digest=${digestOf(blob).slice(0, 12)} -> on-chain v${Number(prev.version) + 1}`);
}

console.log("\n[2] verify-on-read (honest blob)");
const okHonest = await verify("after write");

console.log("\n[3] tamper the S3 blob out-of-band (chain digest unchanged), verify again");
await putBlob(JSON.stringify({ version: 4, serial: 666, TAMPERED: true }));
const okTampered = await verify("after tamper");

// release the lock so the demo leaves a clean slot.
{
  const rec = await view.get_lock(LOCK);
  const { transaction_hash } = await c.release_lock(LOCK, rec.version);
  await p.waitForTransaction(transaction_hash);
}

const pass = okHonest && !okTampered;
console.log(`\n${pass ? "PASS" : "FAIL"}: honest=VERIFIED(${okHonest}) tampered=REJECTED(${!okTampered})`);
process.exit(pass ? 0 : 1);
