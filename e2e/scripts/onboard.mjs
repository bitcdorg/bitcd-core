// DSL onboarding: the dev org is DECLARED in e2e/bitcd.yaml and onboarded
// through @bitcd/core's `bitcd` CLI — deploy -> ceremony -> renounce ->
// the governed org manifest (sys/manifest), then `bitcd diff` as the read-back
// verification (trust nothing you did not read back). The compiled policy
// table is the lock / governed-value / executor surface the proofs run
// against, plus the constitution gates every DSL org carries.
//
// Needs a FRESH devnet, and ministack (S3) for the manifest blob.
// BITCD_DSL_CLI points the step at another build of the CLI.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { AGENTS, DEPLOYMENT_FILE, EXECUTORS, GENESIS, E2E_DIR, RPC_URL } from "./config.mjs";

const CLI = process.env.BITCD_DSL_CLI
  ?? resolve(E2E_DIR, "../core/bin/bitcd.mjs");
const ORG = process.env.BITCD_ORG_FILE ?? resolve(E2E_DIR, "bitcd.yaml");
const S3_ENDPOINT = process.env.BITCD_S3_ENDPOINT ?? "http://localhost:4566";

if (!existsSync(CLI)) {
  console.error(`bitcd CLI not found at ${CLI}`);
  console.error("BITCD_DSL_CLI must point at a bitcd entry point (default: ../core/bin/bitcd.mjs)");
  process.exit(2);
}

// The dev keystore: the cast config.mjs declares (BITCD_ACCOUNTS_FILE
// overrides flow through). Names must match the yaml's signer names.
const TMP = resolve(E2E_DIR, ".onboard-tmp");
mkdirSync(TMP, { recursive: true });
const KEYS_FILE = resolve(TMP, "keys.json");
writeFileSync(KEYS_FILE, JSON.stringify(Object.fromEntries(
  [GENESIS, ...Object.values(AGENTS), ...Object.values(EXECUTORS)]
    .map((a) => [a.name, { address: a.address, pk: a.pk }]),
), null, 2));

// Fresh-devnet discipline: a deployment record left by an earlier devnet names
// a contract this one does not have, and apply-ceremony refuses to resume
// against it — remove the record so this run deploys afresh.
rmSync(DEPLOYMENT_FILE, { force: true });

const run = (args) => {
  console.log(`\n----- bitcd ${args[0]} -----`);
  execFileSync("node", [
    CLI, ...args,
    "--rpc", RPC_URL, "--deployment", DEPLOYMENT_FILE, "--keys", KEYS_FILE, "--s3-endpoint", S3_ENDPOINT,
  ], { stdio: "inherit" });
};

console.log(`onboard (bitcd-core dev): ${ORG} via ${CLI}`);
run(["validate", ORG]);
run(["apply-ceremony", ORG]);   // deploy + seed + renounce (owner -> 0x0)
run(["publish-manifest", ORG]); // the governed constitution at sys/manifest
run(["diff", ORG]);             // read-back verification: must end CLEAN
console.log("\nonboard complete: org seeded from the declaration, manifest committed, diff CLEAN");
