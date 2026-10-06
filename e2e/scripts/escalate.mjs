// Dynamic escalation: a predicate-agent in doubt forces a human into the loop.
//
// `demo/preflight` is an AGENT-AUTONOMY prefix: its (SET_VALUE) policy is a
// 2-of-OPERATOR quorum with min_humans=0, so a quorum of agents commits a routine
// config change with NO human. This beat proves the escalation knob: a non-human
// "predicate-agent" (agent3) that, on doubt, calls `request_human_review` — the SAME
// agent quorum is then BLOCKED until a human signs the readable intent (SNIP-12).
// Escalation only ever RAISES the bar (never lowers it) and is checked at commit, so a
// confident agent sub-quorum that already voted cannot out-vote the demand.
//
// Three beats:
//   [1] baseline   — two agents auto-approve (no human) -> COMMITS        (min_humans 0)
//   [2] escalated  — agent3 (a predicate-agent in doubt) requests human review; the same
//                    two raw agent approvals are BLOCKED on the forced min_humans
//   [3] resolved   — a human signs the readable intent (SNIP-12) -> COMMITS
import { digestOf, s3Store } from "@bitcd/core/store";
import { hash, num, shortString } from "starknet";
import {
  ACTION, AGENTS, PREFLIGHT_PREFIX, PREFLIGHT_SCHEMA, PREFLIGHT_SPEC_S3_KEY, PREFLIGHT_VALUE,
  STORAGE_CLASS_S3, account, approveWithSigs, bitcd, loadDeployment, provider,
} from "./config.mjs";


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

async function propose(spec, action, prefix, params) {
  const c = bitcd(dep.address, account(spec, p));
  const { transaction_hash } = await c.propose(action, prefix, params);
  await p.waitForTransaction(transaction_hash);
  const rcpt = await p.getTransactionReceipt(transaction_hash);
  const sel = "0x" + hash.starknetKeccak("ProposalCreated").toString(16);
  const evs = rcpt.events ?? rcpt.value?.events ?? [];
  return BigInt(evs.find((e) => num.toHex(e.keys?.[0]) === sel).keys[1]);
}
const send = async (spec, fn) => {
  const c = bitcd(dep.address, account(spec, p));
  const { transaction_hash } = await fn(c);
  await p.waitForTransaction(transaction_hash);
};
const rawApprove = (spec, id) => send(spec, (c) => c.approve(id));
const requestHumanReview = (spec, id) => send(spec, (c) => c.request_human_review(id));
// commit is permissionless — any account may relay it.
const commit = (id) => send(AGENTS.agent1, (c) => c.commit(id));

const describe = (params) =>
  `SET_VALUE  key=${dec(params[0])}  (prefix ${dec(PREFLIGHT_PREFIX)})  digest=${String(params[1]).slice(0, 14)}…  → v${Number(params[4]) + 1}`;

console.log(`Dynamic escalation demo on ${dep.address}`);
await ensureBucket();
let pass = true;
const check = (cond, msg) => { console.log(`  ${cond ? "PASS" : "FAIL"}  ${msg}`); pass = pass && cond; };

// ---------------------------------------------------------------------------
// [1] Baseline — the agent-autonomy tier: two automated signers (raw approve, NOT
// intent-bound) reach the 2-of quorum and commit with min_humans=0. No human.
console.log("\n[1] baseline — demo/preflight is min_humans=0: agents auto-approve a routine change");
const cfg1 = `# preflight desired config\nserial = 1\nflag = "on"\n`;
await store.putText(PREFLIGHT_SPEC_S3_KEY, cfg1);
const cur0 = await view.get_value(PREFLIGHT_VALUE);
const params1 = [PREFLIGHT_VALUE, digestOf(cfg1), PREFLIGHT_SCHEMA, STORAGE_CLASS_S3, Number(cur0.version)];
const id1 = await propose(AGENTS.agent1, ACTION.SET_VALUE, PREFLIGHT_PREFIX, params1);
console.log(`  proposal #${id1}: ${describe(params1)}`);
await rawApprove(AGENTS.agent1, id1); // automated signer (OP_A), raw -> not intent-bound
await rawApprove(AGENTS.agent2, id1); // automated signer (OP_B), raw -> not intent-bound
await commit(id1);
const v1 = await view.get_value(PREFLIGHT_VALUE);
check(Number(v1.version) === Number(cur0.version) + 1, "two agents auto-approved (no human) -> COMMITTED");

// ---------------------------------------------------------------------------
// [2] Escalated — a predicate-agent (agent3, a non-human bot eligible on ROLE_OP) is in
// doubt about the NEXT change and demands a human reviewer. The two agents still cast a
// full raw quorum, but the demand is enforced at commit, so they cannot route around it.
console.log("\n[2] escalated — a predicate-agent in doubt calls request_human_review");
const cfg2 = `# preflight desired config\nserial = 2\nflag = "off"\n`;
await store.putText(PREFLIGHT_SPEC_S3_KEY, cfg2);
const cur1 = await view.get_value(PREFLIGHT_VALUE);
const params2 = [PREFLIGHT_VALUE, digestOf(cfg2), PREFLIGHT_SCHEMA, STORAGE_CLASS_S3, Number(cur1.version)];
const id2 = await propose(AGENTS.agent1, ACTION.SET_VALUE, PREFLIGHT_PREFIX, params2);
console.log(`  proposal #${id2}: ${describe(params2)}`);
await rawApprove(AGENTS.agent1, id2);
await rawApprove(AGENTS.agent2, id2);
await requestHumanReview(AGENTS.agent3, id2); // agent3: the predicate-agent in doubt
console.log("      · agent3 (predicate-agent) demanded a human reviewer");
let blocked = false;
try { await commit(id2); }
catch (e) { blocked = /policy unmet/.test(e.message ?? ""); }
check(blocked, "same agent quorum BLOCKED after escalation (can't out-vote the demand)");

// ---------------------------------------------------------------------------
// [3] Resolved — a human signs the READABLE intent (SNIP-12), upgrading their vote to
// intent-bound. That satisfies the forced min_humans=1; the change then commits.
console.log("\n[3] resolved — a human signs the readable intent (SNIP-12)");
await approveWithSigs({
  contractAddress: dep.address, proposalId: id2, action: ACTION.SET_VALUE, prefix: PREFLIGHT_PREFIX,
  params: params2, signers: [AGENTS.agent1], relayer: AGENTS.agent1, p,
});
await commit(id2);
const v2 = await view.get_value(PREFLIGHT_VALUE);
check(
  Number(v2.version) === Number(cur1.version) + 1 && BigInt(v2.digest) === BigInt(digestOf(cfg2)),
  "human-signed intent satisfied the forced floor -> COMMITTED",
);

console.log(`\n${pass ? "PASS" : "FAIL"}: dynamic escalation — agents auto-approve, a doubting agent forces a human, who can't be out-voted`);
process.exit(pass ? 0 : 1);
