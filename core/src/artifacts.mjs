// @bitcd/core/artifacts — the compiled contract class (Sierra + CASM) and its ABI.
//
// Resolution order:
//   1. env override: BITCD_SIERRA / BITCD_CASM (each the path of one artifact
//      file, e.g. in a scarb build's target/dev)
//   2. a scarb build in this checkout (contracts/target/dev), when present
//   3. the artifacts EMBEDDED in this package (core/artifacts/*, refreshed by
//      `pnpm sync-artifacts` at the repo root)
//
// The embedded copy is what lets a consumer deploy + bind the contract with no
// Cairo toolchain. core/artifacts/MANIFEST.json records the class hash and the
// commit it was built from — the staleness guard tying the embedded class to the
// audited commit (the deep-audit gate applies to a class hash, not a directory).
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const EMBEDDED_DIR = resolve(HERE, "../artifacts");
// Inside this repo, prefer a fresh scarb build over the embedded snapshot.
const TARGET_DEV = resolve(HERE, "../../contracts/target/dev");

function pick(envVar, filename) {
  if (process.env[envVar]) return process.env[envVar];
  const built = resolve(TARGET_DEV, filename);
  if (existsSync(built)) return built;
  return resolve(EMBEDDED_DIR, filename);
}

/// Where the Sierra class comes from: "env" (BITCD_SIERRA), "local-build"
/// (a contracts/target/dev build in this checkout) or "bundled".
export function artifactSource() {
  if (process.env.BITCD_SIERRA) return "env";
  if (existsSync(resolve(TARGET_DEV, "bitcd_Bitcd.contract_class.json"))) return "local-build";
  return "bundled";
}

const SIERRA_FILE = () => pick("BITCD_SIERRA", "bitcd_Bitcd.contract_class.json");
const CASM_FILE = () => pick("BITCD_CASM", "bitcd_Bitcd.compiled_contract_class.json");

export const sierra = () => JSON.parse(readFileSync(SIERRA_FILE(), "utf8"));
export const casm = () => JSON.parse(readFileSync(CASM_FILE(), "utf8"));
export const abi = () => sierra().abi;

/// The manifest of the embedded artifacts (classHash, gitCommit, and what
/// sync-artifacts stamps beside them), or null when the file is absent. It
/// describes the bundled class whichever source `artifactSource()` reports.
export function manifest() {
  const f = resolve(EMBEDDED_DIR, "MANIFEST.json");
  return existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : null;
}
