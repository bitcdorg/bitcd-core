// Redundancy & the trust tier. OBSERVED status for a HIGH-TRUST prefix is
// k-of-n: N independent executors each attest, and the aggregate is promoted to Synced
// only when a (prefix, SET_STATUS) policy quorum AGREES on the same live hash — the
// enforcement layer is consensus (reusing the policy evaluator). Three beats,
// each PASS/FAIL:
//
//   [1] agreement   — exec1 attests (pending, below k); exec2 agrees -> 2-of -> SYNCED
//   [2] dissent     — new desired; exec1 (honest) vs exec3 (lying hash) -> DISAGREE
//   [3] out-voted   — exec2 (honest) joins -> 2 diverse honest agree -> SYNCED
//                     (the lone Byzantine executor is out-voted, never blocks)
//
// Prefix iam/prod (SET_STATUS = 2-of-EXEC_IAM, <=1 per operator). Desired is governed
// (consensus-written, 2-of-OPERATOR). Provider surface = ministack S3; the contract
// stores only digests; Synced/OutOfSync is derived off-chain.
import { hash, num, shortString } from "starknet";
import {
  ACTION, AGENTS, EXECUTORS, HT_LIVE_S3_KEY, HT_PREFIX, HT_SPEC_S3_KEY, HT_VALUE, IAM_SCHEMA,
  STORAGE_CLASS_S3, account, bitcd, loadDeployment, provider,
} from "./config.mjs";
import { sampleConfig } from "@bitcd/core/fixtures";
import { renderConfig } from "@bitcd/core/reconcile";
import { digestOf, s3Store } from "@bitcd/core/store";
import { approveWithSigs } from "./config.mjs";

const p = provider();
const dep = loadDeployment();
const view = bitcd(dep.address, p);
const execConn = (e) => bitcd(dep.address, account(e, p));
const dec = (felt) => {
  try {
    return shortString.decodeShortString(num.toHex(felt)) || "0x0";
  } catch {
    return num.toHex(felt);
  }
};

const store = s3Store();
const putObj = (Key, Body) => store.putText(Key, Body);
const getObj = (Key) => store.getText(Key);
const ensureBucket = () => store.ensureBucket();

// Governed desired commit (2-of-OPERATOR quorum) — the executor cannot write desired.
async function commitDesired(config) {
  const blob = renderConfig(config);
  await putObj(HT_SPEC_S3_KEY, blob);
  const digest = digestOf(blob);
  const cur = await view.get_value(HT_VALUE);
  const expected = Number(cur.version);
  const params = [HT_VALUE, digest, IAM_SCHEMA, STORAGE_CLASS_S3, expected];
  const a1 = bitcd(dep.address, account(AGENTS.agent1, p));
  const { transaction_hash } = await a1.propose(ACTION.SET_VALUE, HT_PREFIX, params);
  await p.waitForTransaction(transaction_hash);
  const receipt = await p.getTransactionReceipt(transaction_hash);
  const sel = "0x" + hash.starknetKeccak("ProposalCreated").toString(16);
  const evs = receipt.events ?? receipt.value?.events ?? [];
  const id = BigInt(evs.find((ev) => num.toHex(ev.keys?.[0]) === sel).keys[1]);
  // Humans approve the governed desired by signing readable intent (SNIP-12).
  await approveWithSigs({
    contractAddress: dep.address, proposalId: id, action: ACTION.SET_VALUE, prefix: HT_PREFIX,
    params, signers: [AGENTS.agent1, AGENTS.agent2], relayer: AGENTS.agent1, p,
  });
  const cm = await a1.commit(id);
  await p.waitForTransaction(cm.transaction_hash);
  return { digest, version: expected + 1, blob };
}

// One executor attests (observed_revision, applied_hash, condition).
async function attest(execName, rev, applied_hash, condition) {
  const c = execConn(EXECUTORS[execName]);
  const { transaction_hash } = await c.set_status(
    HT_VALUE, rev, applied_hash, shortString.encodeShortString(condition), shortString.encodeShortString("attest"),
  );
  await p.waitForTransaction(transaction_hash);
}

// The aggregate + the per-executor votes (the indexer's agreement tally, in miniature).
async function snapshot(label) {
  const st = await view.get_status(HT_VALUE);
  const v = await view.get_value(HT_VALUE);
  const votes = [];
  for (const [name, e] of Object.entries(EXECUTORS)) {
    const a = await view.get_attestation(HT_VALUE, e.address);
    if (Boolean(a.seen)) votes.push(`${name}=${("0x" + a.applied_hash.toString(16)).slice(0, 8)}@v${Number(a.observed_revision)}`);
  }
  const cond = Boolean(st.exists) ? dec(st.condition) : "(none)";
  const digest = "0x" + st.observed_digest.toString(16);
  console.log(`      agg=${cond} observed_digest=${digest.slice(0, 10)} sv=${Number(st.status_version)} desired=v${Number(v.version)} | votes: ${votes.join(", ")}  (${label})`);
  return { exists: Boolean(st.exists), condition: cond, observed_digest: digest, desired_digest: "0x" + v.digest.toString(16) };
}

console.log(`k-of-n redundancy demo on ${dep.address}`);
console.log(`  prefix=iam/prod  key=iam/prod/pset  SET_STATUS=2-of-EXEC_IAM (<=1/operator)  executors=exec1/2/3`);
await ensureBucket();

let pass = true;
const check = (cond, msg) => { console.log(`  ${cond ? "PASS" : "FAIL"}  ${msg}`); pass = pass && cond; };

console.log("\n[1] agreement — quorum commits desired; executors apply + attest");
const d1 = await commitDesired(sampleConfig({ serial: 1 }));
await putObj(HT_LIVE_S3_KEY, d1.blob); // the provider converges to desired
const live1 = digestOf(await getObj(HT_LIVE_S3_KEY));
await attest("exec1", d1.version, live1, "SYNCED");
const s1a = await snapshot("exec1 only");
check(!s1a.exists, "below k (1 of 2) -> NOT promoted");
await attest("exec2", d1.version, live1, "SYNCED");
const s1b = await snapshot("exec1 + exec2 agree");
check(s1b.condition === "SYNCED" && s1b.observed_digest === live1, "2 diverse executors agree -> SYNCED");

console.log("\n[2] dissent — new desired; one executor reports a different (lying) hash");
const d2 = await commitDesired(sampleConfig({ serial: 2, allowDelete: true }));
await putObj(HT_LIVE_S3_KEY, d2.blob);
const live2 = digestOf(await getObj(HT_LIVE_S3_KEY));
const bogus = digestOf("rogue-iam-policy-set");
await attest("exec1", d2.version, live2, "SYNCED"); // honest
await attest("exec3", d2.version, bogus, "SYNCED"); // Byzantine / misconfigured
const s2 = await snapshot("exec1 honest vs exec3 lying");
check(s2.condition === "DISAGREE", "executors disagree -> DISAGREE (no silent Synced)");

console.log("\n[3] out-voted — a second honest executor joins the true hash");
await attest("exec2", d2.version, live2, "SYNCED");
const s3v = await snapshot("exec1 + exec2 honest quorum");
check(s3v.condition === "SYNCED" && s3v.observed_digest === live2, "honest k-of-n wins; Byzantine out-voted");
check(s3v.observed_digest !== bogus, "the lying hash never became authoritative");

console.log(`\n${pass ? "PASS" : "FAIL"}: k-of-n agreement, disagreement, and Byzantine-tolerance all behaved`);
process.exit(pass ? 0 : 1);
