// Refresh the artifacts EMBEDDED in @bitcd/core from a local `scarb build`, and
// stamp MANIFEST.json — the staleness guard tying the embedded class to a specific
// commit (the deep-audit gate applies to a class hash, not a directory). CI
// recomputes the class hash from a fresh build and compares.
//
// Usage: node core/scripts/sync-artifacts.mjs   (or `pnpm sync-artifacts` at root)
import { execSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { hash } from "starknet";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "../..");
const TARGET = resolve(REPO, "contracts/target/dev");
const OUT = resolve(HERE, "../artifacts");

const SIERRA = "bitcd_Bitcd.contract_class.json";
const CASM = "bitcd_Bitcd.compiled_contract_class.json";

mkdirSync(OUT, { recursive: true });
const sierra = JSON.parse(readFileSync(resolve(TARGET, SIERRA), "utf8"));
// The Cairo compiler version is recorded in the CASM file; the Sierra class
// carries none. JSON.stringify drops an undefined field, so refuse to stamp
// a manifest without it.
const { compiler_version: compilerVersion } = JSON.parse(readFileSync(resolve(TARGET, CASM), "utf8"));
if (!compilerVersion) throw new Error(`${CASM} carries no compiler_version`);
copyFileSync(resolve(TARGET, SIERRA), resolve(OUT, SIERRA));
copyFileSync(resolve(TARGET, CASM), resolve(OUT, CASM));

const classHash = hash.computeContractClassHash(sierra);
const gitCommit = execSync("git rev-parse HEAD", { cwd: REPO }).toString().trim();
const manifest = {
  classHash,
  gitCommit,
  compilerVersion,
  syncedAt: new Date().toISOString(),
};
writeFileSync(resolve(OUT, "MANIFEST.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(`embedded ${SIERRA} + ${CASM}`);
console.log(`class hash ${classHash} @ ${gitCommit}`);
