// Human interface: provable intent→calldata binding (SNIP-12).
//
// A raw `approve(proposal_id)` tx is a human "rubber-stamping a number". The
// intent-bound path makes a human approve *readable intent*: they
// sign a SNIP-12 typed-data `Approval` (a wallet renders the action, prefix and params hash),
// and the signature is provably bound to the EXACT operation that commits. Humans
// sign OFF-CHAIN (gasless); an untrusted relayer submits the collected signatures via
// `approve_sigs`. A human vote counts toward `min_humans` ONLY through this path.
//
// Two beats, each PASS/FAIL (the SNIP-12 machinery is action-agnostic):
//   [A] governed SET_VALUE (iam/prod desired-state change) — a bot/raw quorum is
//       BLOCKED on min_humans; the same humans then sign readable intent and it commits
//   [B] force_unlock (break a stuck tf/lock) — the highest-risk action, approved by
//       humans reviewing exactly what they're breaking
import { digestOf, s3Store } from "@bitcd/core/store";
import { hash, num, shortString } from "starknet";
import {
  ACTION, AGENTS, HT_PREFIX, HT_SPEC_S3_KEY, HT_VALUE, IAM_SCHEMA, LOCK, PREFIX, STORAGE_CLASS_S3,
  account, bitcd, loadDeployment, provider,
} from "./config.mjs";
import { approveWithSigs } from "./config.mjs";


const p = provider();
const dep = loadDeployment();
const view = bitcd(dep.address, p);
const dec = (felt) => {
  try { return shortString.decodeShortString(num.toHex(felt)) || num.toHex(felt); }
  catch { return num.toHex(felt); }
};

const store = s3Store();
const putObj = (Key, Body) => store.putText(Key, Body);
const ensureBucket = () => store.ensureBucket();

// Render a proposal as plain-English intent — what the human reviews. The signed
// typed data carries the action, the prefix and the hash of these params; here the
// params are decoded for the terminal narrative.
function describeIntent(action, prefix, params) {
  const a = dec(action), pre = dec(prefix);
  if (action === ACTION.SET_VALUE) {
    return `SET_VALUE  key=${dec(params[0])}  (prefix ${pre})\n        digest=${String(params[1]).slice(0, 14)}…  schema=${dec(params[2])}  class=${dec(params[3])}  → v${Number(params[4]) + 1}`;
  }
  if (action === ACTION.FORCE_UNLOCK) {
    return `FORCE_UNLOCK  key=${dec(params[0])}  (prefix ${pre}; break the current holder's lease)`;
  }
  return `${a}  ${pre}  [${params.map(dec).join(", ")}]`;
}

async function propose(spec, action, prefix, params) {
  const c = bitcd(dep.address, account(spec, p));
  const { transaction_hash } = await c.propose(action, prefix, params);
  await p.waitForTransaction(transaction_hash);
  const rcpt = await p.getTransactionReceipt(transaction_hash);
  const sel = "0x" + hash.starknetKeccak("ProposalCreated").toString(16);
  const evs = rcpt.events ?? rcpt.value?.events ?? [];
  return BigInt(evs.find((e) => num.toHex(e.keys?.[0]) === sel).keys[1]);
}
const commit = async (id) => {
  // commit is permissionless — any account may relay it.
  const c = bitcd(dep.address, account(AGENTS.agent1, p));
  const { transaction_hash } = await c.commit(id);
  await p.waitForTransaction(transaction_hash);
};
const rawApprove = async (spec, id) => {
  const c = bitcd(dep.address, account(spec, p));
  const { transaction_hash } = await c.approve(id);
  await p.waitForTransaction(transaction_hash);
};

console.log(`Human interface (SNIP-12) demo on ${dep.address}`);
await ensureBucket();
let pass = true;
const check = (cond, msg) => { console.log(`  ${cond ? "PASS" : "FAIL"}  ${msg}`); pass = pass && cond; };

// ---------------------------------------------------------------------------
console.log("\n[A] governed SET_VALUE (iam/prod) — readable intent, relayed human signatures");
const cfg = `# iam/prod desired policy-set\nserial = 7\nallow = ["s3:GetObject"]\n`;
await store.putText(HT_SPEC_S3_KEY, cfg);
const digest = digestOf(cfg);
const cur = await view.get_value(HT_VALUE);
const params = [HT_VALUE, digest, IAM_SCHEMA, STORAGE_CLASS_S3, Number(cur.version)];
const idA = await propose(AGENTS.agent1, ACTION.SET_VALUE, HT_PREFIX, params);
console.log(`  proposal #${idA} — the human reviews:\n        ${describeIntent(ACTION.SET_VALUE, HT_PREFIX, params)}`);

// NEGATIVE: agent1 + agent2 are humans, but raw approve() is not intent-bound.
await rawApprove(AGENTS.agent1, idA);
await rawApprove(AGENTS.agent2, idA);
let blocked = false;
try { await commit(idA); }
catch (e) { blocked = /policy unmet/.test(e.message ?? ""); }
check(blocked, "raw human approvals BLOCKED on min_humans (no rubber-stamping)");

// POSITIVE: the same humans sign the readable intent (SNIP-12) — relayer submits,
// upgrading their votes to intent-bound — then it commits.
await approveWithSigs({
  contractAddress: dep.address, proposalId: idA, action: ACTION.SET_VALUE, prefix: HT_PREFIX,
  params, signers: [AGENTS.agent1, AGENTS.agent2], relayer: AGENTS.agent1, p,
});
await commit(idA);
const v = await view.get_value(HT_VALUE);
check(BigInt(v.digest) === BigInt(digest) && Number(v.version) === Number(cur.version) + 1,
  "intent-bound human quorum COMMITTED the governed value");

// ---------------------------------------------------------------------------
console.log("\n[B] force_unlock (tf/lock) — humans approve breaking a stuck lease");
const c3 = bitcd(dep.address, account(AGENTS.agent3, p));
if (!(await view.get_lock(LOCK)).holder || (await view.get_lock(LOCK)).tombstoned !== false) {
  try { const t = await c3.acquire_lock(LOCK, PREFIX, num.toHex(99), 0); await p.waitForTransaction(t.transaction_hash); }
  catch (e) { console.log(`      · lock already held (${(e.message ?? "").slice(0, 40)})`); }
}
const held = await view.get_lock(LOCK);
console.log(`      · lock held by ${String(held.holder).slice(0, 10)}… v${Number(held.version)}`);
const fuParams = [LOCK];
const idB = await propose(AGENTS.agent1, ACTION.FORCE_UNLOCK, PREFIX, fuParams);
console.log(`  proposal #${idB} — the human reviews:\n        ${describeIntent(ACTION.FORCE_UNLOCK, PREFIX, fuParams)}`);
await approveWithSigs({
  contractAddress: dep.address, proposalId: idB, action: ACTION.FORCE_UNLOCK, prefix: PREFIX,
  params: fuParams, signers: [AGENTS.agent1, AGENTS.agent2], relayer: AGENTS.agent2, p,
});
await commit(idB);
const freed = await view.get_lock(LOCK);
check(Boolean(freed.tombstoned), "intent-bound human quorum FORCE-UNLOCKED the lock");

console.log(`\n${pass ? "PASS" : "FAIL"}: human SNIP-12 intent-binding — blocked raw, committed signed, action-agnostic`);
process.exit(pass ? 0 : 1);
