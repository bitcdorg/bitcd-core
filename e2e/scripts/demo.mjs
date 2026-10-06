// One-shot orchestrator: onboard (the declared org, via the bitcd CLI) ->
// every substrate proof, against a running devnet.
// Start the chain first:  starknet-devnet --seed 0 --host 0.0.0.0 --port 5051
import { spawnSync } from "node:child_process";
import { RPC_URL } from "./config.mjs";

async function up() {
  try {
    const r = await fetch(RPC_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "starknet_chainId", params: [] }),
    });
    return r.ok;
  } catch {
    return false;
  }
}

if (!(await up())) {
  console.error(`devnet not reachable at ${RPC_URL}`);
  console.error("start it: starknet-devnet --seed 0 --host 0.0.0.0 --port 5051");
  process.exit(1);
}

// Core chain proofs — every substrate property end-to-end. The use-case showcases
// (Terraform backend, k8s lease/RBAC, agentgate fleet/notary) live in their own
// repos and run against their own deployments. `onboard` = deploy + the
// ceremony from e2e/bitcd.yaml + renounce + manifest + diff CLEAN.
for (const step of ["onboard", "contend", "store", "reconcile", "redundancy", "human-approve", "escalate"]) {
  console.log(`\n===== ${step} =====`);
  const r = spawnSync("node", [`scripts/${step}.mjs`], { stdio: "inherit" });
  if (r.status !== 0) process.exit(r.status ?? 1);
}
console.log("\ndemo complete");
