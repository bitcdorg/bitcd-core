// bitcd indexer — the off-chain materialized view. The chain is a control
// plane, NOT a query plane: "is
// everything Synced?", drift dashboards, and history are answered from the EVENT
// STREAM, not by per-request on-chain reads. The folds themselves (per-key desired
// vs observed + derived Synced/OutOfSync/Failed, per-proposal approvals vs
// intent-bound votes vs escalations) live in @bitcd/core/events; this daemon is
// the CLI/table presentation over them.
//
// Usage:
//   node src/index.mjs            print the current view (table), exit
//   node src/index.mjs --json     print the view as JSON
//   node src/index.mjs --watch    re-poll and reprint every few seconds
//
// Config via env (defaults match the e2e dev stack): BITCD_RPC,
// BITCD_DEPLOYMENT_FILE.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { RpcProvider } from "starknet";
import { applyNoProxy } from "@bitcd/core/client";
import { fetchAllEvents, projectKeys, projectProposals } from "@bitcd/core/events";

applyNoProxy("localhost,127.0.0.1,0.0.0.0,devnet,ministack");

const HERE = dirname(fileURLToPath(import.meta.url));
const RPC = process.env.BITCD_RPC ?? "http://localhost:5051";
const DEPLOYMENT_FILE = process.env.BITCD_DEPLOYMENT_FILE
  ?? resolve(HERE, "../../e2e/deployment.json");
const dep = JSON.parse(readFileSync(DEPLOYMENT_FILE, "utf8"));
const p = new RpcProvider({ nodeUrl: RPC });

// A coarse, prefix-derived KIND label so heterogeneous keys group in the view (the
// projection itself stays generic — the contract never tags a key by domain). The
// k8s/rbac/* keys surface here automatically; this only labels them.
const kindOf = (prefix) => {
  const s = String(prefix ?? "");
  if (s.startsWith("k8s/rbac")) return "rbac";
  if (s.startsWith("k8s/lease")) return "lease";
  if (s.startsWith("iam/")) return "iam";
  if (s.startsWith("tf/")) return "tfstate";
  if (s.startsWith("fleet/")) return "fleet";
  if (s.startsWith("demo/notarygate")) return "notary";
  return "kv";
};

// Machine approvers = the raw roster minus the SNIP-12 intent-bound set. On the
// peer-quorum prefixes (fleet/*, demo/notarygate) these are the predicate
// votes — intentSigned ⊆ approvers on-chain, so the difference is exact.
const machineOf = (p) => [...p.approvers].filter((a) => !p.intentSigned.has(a));

function printProposals(rows) {
  if (!rows.length) return;
  console.log("");
  console.log(`bitcd governance proposals  (${rows.length})`);
  console.log("─".repeat(96));
  console.log(["ID".padEnd(4), "ACTION".padEnd(16), "PREFIX".padEnd(18), "MACHINE".padEnd(8), "INTENT(human)".padEnd(14), "ESCALATED".padEnd(10), "COMMITTED"].join(" "));
  for (const r of rows) {
    console.log([
      String(r.id).padEnd(4),
      String(r.action ?? "—").padEnd(16),
      String(r.prefix ?? "—").padEnd(18),
      String(machineOf(r).length).padEnd(8),
      String(r.intentSigned.size).padEnd(14),
      (r.escalatedBy.size ? "⚠ human" : "—").padEnd(10),
      r.committed ? "yes" : "no",
    ].join(" "));
  }
  console.log("─".repeat(96));
  console.log("MACHINE = approvals that are NOT intent-bound — the peer/predicate votes (mutual gating)");
  console.log("INTENT(human) = SNIP-12 intent-bound approvals — the votes that count toward min_humans");
  console.log("ESCALATED = an eligible signer demanded a human reviewer; commit forces min_humans>=1");
}

function printTable(rows) {
  const fmt = (v) => (v ?? "—");
  console.log(`bitcd materialized view  (contract ${dep.address.slice(0, 12)}…, ${rows.length} key${rows.length === 1 ? "" : "s"})`);
  console.log("─".repeat(96));
  console.log(["KEY".padEnd(20), "KIND".padEnd(8), "PREFIX".padEnd(18), "DESIRED".padEnd(8), "STATE".padEnd(10), "AGREEMENT".padEnd(16), "CLAIMED"].join(" "));
  for (const r of rows) {
    const ag = r.agreement;
    // k-of-n agreement: how many votes agree on the leading hash, out of voters at rev.
    const agreement = ag && ag.voters
      ? `${ag.lead ? ag.lead.count : 0}/${ag.voters} on ${ag.lead ? ag.lead.hash.slice(0, 8) : "—"}${ag.distinct > 1 ? " ⚠split" : ""}`
      : "—";
    console.log([
      String(r.valueKey).padEnd(20),
      String(r.kind).padEnd(8),
      String(fmt(r.prefix)).padEnd(18),
      ("v" + (r.desired?.version ?? "?")).padEnd(8),
      String(r.state).padEnd(10),
      String(agreement).padEnd(16),
      String(r.observed?.claimed ?? "—"),
    ].join(" "));
  }
  const synced = rows.filter((r) => r.state === "SYNCED").length;
  console.log("─".repeat(96));
  console.log(`is everything Synced? ${synced === rows.length && rows.length > 0 ? "YES" : "NO"}  (${synced}/${rows.length} Synced)`);
}

async function once() {
  const events = await fetchAllEvents(p, dep.address);
  const rows = projectKeys(events, { labelKey: kindOf });
  const proposals = projectProposals(events);
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify({
      keys: rows,
      proposals: proposals.map((p) => ({ ...p, approvers: [...p.approvers], machine: machineOf(p), intentSigned: [...p.intentSigned], escalatedBy: [...p.escalatedBy], escalated: p.escalatedBy.size > 0 })),
    }, null, 2));
  } else {
    printTable(rows);
    printProposals(proposals);
  }
  return rows;
}

if (process.argv.includes("--watch")) {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  // eslint-disable-next-line no-constant-condition
  while (true) {
    console.clear();
    try {
      await once();
    } catch (e) {
      console.error(`indexer error: ${e?.message ?? e}`);
    }
    await sleep(4000);
  }
} else {
  await once();
}
