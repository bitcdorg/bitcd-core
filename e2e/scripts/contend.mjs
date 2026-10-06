// Three wallets race for one lock:
//   1. agent1 acquires on empty            -> wins, version 1
//   2. agent2 & agent3 try while held      -> both rejected ('acquire: held')
//   3. after TTL expiry, agent2 acquires   -> handover, version 2
// Devnet block timestamps advance in coarse, unpredictable jumps, so we hold with
// a long TTL and cross it deterministically with devnet_increaseTime rather than
// relying on a wall-clock sleep.
import { AGENTS, LOCK, PREFIX, RPC_URL, account, bitcd, loadDeployment, provider, str } from "./config.mjs";

const TTL = 3600n; // long enough that block-timestamp drift never expires it on its own
const OP = str("op");
const p = provider();
const dep = loadDeployment();

const conn = (a) => bitcd(dep.address, account(a, p));
const view = bitcd(dep.address, p);

async function rpc(method, params) {
  const r = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return (await r.json()).result;
}

async function acquire(a, ttl) {
  try {
    const { transaction_hash } = await conn(a).acquire_lock(LOCK, PREFIX, OP, ttl);
    await p.waitForTransaction(transaction_hash);
    return { ok: true };
  } catch (e) {
    const m = String(e.message ?? e);
    return { ok: false, reason: m.includes("acquire: held") ? "acquire: held" : m.slice(0, 90) };
  }
}

async function show(label) {
  const r = await view.get_lock(LOCK);
  const holder = "0x" + r.holder.toString(16);
  console.log(`  lock: holder=${holder.slice(0, 12)} version=${r.version} ttl=${r.ttl} tombstoned=${r.tombstoned}  <- ${label}`);
  return r;
}

const norm = (a) => BigInt(a);

console.log(`contention demo on ${dep.address}`);

console.log("\n[1] agent1 acquires on empty lock");
const r1 = await acquire(AGENTS.agent1, TTL);
console.log(`  agent1: ${r1.ok ? "WON" : "rejected (" + r1.reason + ")"}`);
const a1rec = await show("after agent1");

console.log("\n[2] agent2 and agent3 contend while held");
const r2 = await acquire(AGENTS.agent2, TTL);
const r3 = await acquire(AGENTS.agent3, TTL);
console.log(`  agent2: ${r2.ok ? "WON (BUG)" : "REJECTED (" + r2.reason + ")"}`);
console.log(`  agent3: ${r3.ok ? "WON (BUG)" : "REJECTED (" + r3.reason + ")"}`);
await show("still agent1");

console.log(`\n[3] advancing chain time past TTL (+${TTL + 1n}s), then agent2 retries`);
await rpc("devnet_increaseTime", { time: Number(TTL) + 1 });
const r4 = await acquire(AGENTS.agent2, 0n);
console.log(`  agent2: ${r4.ok ? "WON (handover)" : "rejected (" + r4.reason + ")"}`);
const final = await show("after expiry handover");

const pass =
  r1.ok && !r2.ok && !r3.ok && r4.ok &&
  a1rec.version === 1n && final.version === 2n &&
  norm(final.holder) === norm(AGENTS.agent2.address);
console.log(`\n${pass ? "PASS" : "FAIL"}: win=${r1.ok} reject2=${!r2.ok} reject3=${!r3.ok} handover=${r4.ok} v1=${a1rec.version} v2=${final.version}`);
process.exit(pass ? 0 : 1);
