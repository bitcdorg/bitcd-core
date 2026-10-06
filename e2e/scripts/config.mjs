// Shared config for the bitcd starknet-devnet e2e rig — the DEMO layer.
// Generic library code lives in @bitcd/core; this file holds the devnet cast,
// the demo prefixes/schemas, and thin re-exports so every e2e script keeps
// one import site.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  account as coreAccount,
  applyNoProxy,
  approveWithSigs as coreApproveWithSigs,
  bitcdContract,
  loadDeployment as coreLoadDeployment,
  provider as coreProvider,
} from "@bitcd/core/client";
import { ACTION as CORE_ACTION, CONDITION_FELT, GLOBAL as CORE_GLOBAL, STORAGE_CLASS, str } from "@bitcd/core/protocol";

// starknet-devnet binds on :5051 and is reached directly (NO_PROXY) — a local
// proxy gateway must not intercept localhost RPC. Explicit call: importing
// @bitcd/core never mutates the environment; the demo layer opts in here.
applyNoProxy();

export { str };

const HERE = dirname(fileURLToPath(import.meta.url));
export const E2E_DIR = resolve(HERE, "..");
export const REPO_DIR = resolve(E2E_DIR, "..");
export const RPC_URL = process.env.BITCD_RPC ?? "http://localhost:5051";
export const DEPLOYMENT_FILE =
  process.env.BITCD_DEPLOYMENT_FILE ?? resolve(E2E_DIR, "deployment.json");

// Lock fixtures (terraform state lock).
export const PREFIX = str("tf/lock");
// Reserved GLOBAL scope + protocol vocabulary — from @bitcd/core/protocol
// (ACTION tags, condition felts, the GLOBAL scope are protocol identity, not
// demo fixtures).
export const GLOBAL = CORE_GLOBAL;
export const ACTION = CORE_ACTION;
export const CONDITION = CONDITION_FELT;
export const LOCK = str("tf/lock/state");
export const ROLE_OP = str("OPERATOR");
export const OP_A = str("OP_A");
export const OP_B = str("OP_B");

// The governed value (state digest) tracked beside the lock, plus its
// schema/storage-class hints.
export const VALUE = str("tf/lock/state/value");
export const SCHEMA_REF = str("tfstate/v4");
export const STORAGE_CLASS_S3 = STORAGE_CLASS.S3;

// Reconcile (single provider). The DESIRED state of an IAM
// policy-set is a GOVERNED value (consensus-written via propose/approve/commit on
// (IAM_PREFIX, SET_VALUE) — spec is never executor-written). The OBSERVED state is
// written single-writer by the consensus-assigned executor via SET_STATUS, gated
// by the EXEC_IAM role (a distinct per-domain executor role, so one namespace's
// executor can never attest another's).
// The "provider" surface is reproducible over the same ministack S3 the storage
// layer already uses: the executor APPLIES by writing the verified desired config
// to a `live/` object, and drift = an out-of-band overwrite of that object (a
// real IAM adapter is a config swap, mirroring storage_class S3→OCI).
export const IAM_PREFIX = str("iam/acct");
export const IAM_VALUE = str("iam/acct/pset"); // the reconciled key (spec + status share it)
export const IAM_SCHEMA = str("iampolicyset/v1");
export const ROLE_EXEC = str("EXEC_IAM");
// S3 object keys for the spec blob (the governed desired bytes) and the live
// provider surface the executor actuates + re-reads for drift.
export const IAM_SPEC_S3_KEY = process.env.BITCD_IAM_SPEC_KEY ?? "iam/acct/spec";
export const IAM_LIVE_S3_KEY = process.env.BITCD_IAM_LIVE_KEY ?? "iam/acct/live";

// The executor fleet (devnet --seed 0 accounts #4/#5/#6). All non-human bots on the
// EXEC_IAM role but DISTINCT operator_ids (so a k-of-n quorum keeps operator
// diversity, max_per_operator=1). exec1 doubles as the single-writer (k=1)
// executor for iam/acct; all three back the high-trust prefix (iam/prod).
export const OP_EXEC1 = str("OP_EXEC1");
export const OP_EXEC2 = str("OP_EXEC2");
export const OP_EXEC3 = str("OP_EXEC3");
export const EXECUTORS = {
  exec1: {
    name: "exec1",
    address: "0x00d513de92c16aa42418cf7e5b60f8022dbee1b4dfd81bcf03ebee079cfb5cb5",
    pk: "0x5b4ac23628a5749277bcabbf4726b025",
    is_human: false, operator_id: OP_EXEC1, role: ROLE_EXEC,
  },
  exec2: {
    name: "exec2",
    address: "0x01e8c6c17efa3a047506c0b1610bd188aa3e3dd6c5d9227549b65428de24de78",
    pk: "0x836203aceb0e9b0066138c321dda5ae6",
    is_human: false, operator_id: OP_EXEC2, role: ROLE_EXEC,
  },
  exec3: {
    name: "exec3",
    address: "0x0557ba9ef60b52dad611d79b60563901458f2476a5c1002a8b4869fcb6654c7e",
    pk: "0x15b5e3013d752c909988204714f1ff35",
    is_human: false, operator_id: OP_EXEC3, role: ROLE_EXEC,
  },
};
// Single-writer executor (iam/acct, k=1) = exec1.
export const EXECUTOR = EXECUTORS.exec1;

// High-trust prefix (iam/prod): DESIRED governed (consensus-written), OBSERVED
// is k-of-n — (iam/prod, SET_STATUS) = 2-of-EXEC_IAM, <=1 per operator. Synced needs
// two diverse executors to agree on the same live hash; a split is DISAGREE.
export const HT_PREFIX = str("iam/prod");
export const HT_VALUE = str("iam/prod/pset");
export const HT_SPEC_S3_KEY = process.env.BITCD_HT_SPEC_KEY ?? "iam/prod/spec";
export const HT_LIVE_S3_KEY = process.env.BITCD_HT_LIVE_KEY ?? "iam/prod/live";

// Dynamic escalation demo. `demo/preflight` is an AGENT-AUTONOMY value prefix:
// its (SET_VALUE) policy is a 2-of-OPERATOR quorum with min_humans=0, so a quorum of
// agents can commit a routine config change with NO human in the loop. A predicate-
// agent in doubt calls `request_human_review`, raising the effective min_humans floor
// to >=1 for that one proposal (strengthen-only, checked at commit — can't be
// out-voted) — the same agent quorum is then blocked until a human signs the readable
// intent (SNIP-12). No human is seeded into the policy: the human is summoned
// dynamically, exactly the "agents auto-approve, escalate on doubt" pattern.
export const PREFLIGHT_PREFIX = str("demo/preflight");
export const PREFLIGHT_VALUE = str("demo/preflight/cfg");
export const PREFLIGHT_SCHEMA = str("preflight/v1");
export const PREFLIGHT_SPEC_S3_KEY = process.env.BITCD_PREFLIGHT_SPEC_KEY ?? "demo/preflight/spec";

// starknet-devnet --seed 0 deterministic predeployed accounts (RPC 0.10.2).
// genesis = transient super-admin (owner) that seeds then renounces.
// agent1/agent2 = human operators on distinct operator_ids; agent3 = bot sharing
// agent1's operator_id (exercises the max_per_operator diversity rule).
export const GENESIS = {
  name: "genesis",
  address: "0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691",
  pk: "0x71d7bb07b9a64f6f78ac4c816aff4da9",
};

export const AGENTS = {
  agent1: {
    name: "agent1",
    address: "0x078662e7352d062084b0010068b99288486c2d8b914f6e2a55ce945f8792c8b1",
    pk: "0x0e1406455b7d66b1690803be066cbe5e",
    is_human: true,
    operator_id: OP_A,
    role: ROLE_OP,
  },
  agent2: {
    name: "agent2",
    address: "0x049dfb8ce986e21d354ac93ea65e6a11f639c1934ea253e5ff14ca62eca0f38e",
    pk: "0xa20a02f0ac53692d144b20cb371a60d7",
    is_human: true,
    operator_id: OP_B,
    role: ROLE_OP,
  },
  agent3: {
    name: "agent3",
    address: "0x04f348398f859a55a0c80b1446c5fdc37edb3a8478a32f10764659fc241027d3",
    pk: "0xa641611c17d4d92bd0790074e34beeb7",
    is_human: false,
    operator_id: OP_A,
    role: ROLE_OP,
  },
};

// Production cast override: BITCD_ACCOUNTS_FILE
// points at a JSON file whose entries replace the devnet seed identities above —
// same shape, real keys, NEVER committed (e2e/accounts/ is gitignored).
// operator_id/role may be given as plain strings; they are shortstring-encoded
// here. Only the entries present in the file are overridden, so a partial cast
// leaves the rest as devnet defaults — scripts that use those defaults against
// a public chain fail on their own funding, loudly.
if (process.env.BITCD_ACCOUNTS_FILE) {
  const overrides = JSON.parse(readFileSync(process.env.BITCD_ACCOUNTS_FILE, "utf8"));
  const enc = (v) => (typeof v === "string" && !v.startsWith("0x") ? str(v) : v);
  const applyEntry = (target, src) => {
    if (!src) return;
    Object.assign(target, src);
    if (src.operator_id) target.operator_id = enc(src.operator_id);
    if (src.role) target.role = enc(src.role);
  };
  const applyMap = (target, src) => {
    for (const k of Object.keys(src ?? {})) if (target[k]) applyEntry(target[k], src[k]);
  };
  applyEntry(GENESIS, overrides.GENESIS);
  applyMap(AGENTS, overrides.AGENTS);
  applyMap(EXECUTORS, overrides.EXECUTORS);
}

// Thin wrappers over @bitcd/core/client, pinned to the e2e env defaults
// (RPC_URL / DEPLOYMENT_FILE above) so every script keeps its call shape.
export const provider = () => coreProvider(RPC_URL);
export const account = (spec, p = provider()) => coreAccount(spec, p);
export const bitcd = (addrOrConn, conn) => bitcdContract(addrOrConn, conn);
export const loadDeployment = () => coreLoadDeployment(DEPLOYMENT_FILE);

// Collect intent-bound human signatures (SNIP-12) and submit them via
// `approve_sigs` (@bitcd/core/client), pinned to the e2e provider.
export const approveWithSigs = (args) => coreApproveWithSigs({ p: provider(), ...args });
