# @bitcd/core

The reusable half of bitcd: everything a consumer needs to run a **governed
key/value control plane on Starknet** — propose/approve/commit writes gated by
on-chain quorum policy, human approvals bound to readable intent (SNIP-12),
executors that reconcile desired state onto real infrastructure and attest what
they observed, and a verify-on-read blob store so the chain never holds bytes.

The Cairo contract itself lives in [`contracts/`](../contracts/) (a standalone
Scarb package with a full snforge suite); this package **embeds its compiled artifacts**
(`artifacts/` + `MANIFEST.json` with the class hash ↔ git commit binding), so a
JS consumer can declare, deploy, and bind the contract with no Cairo toolchain.

Everything demo-shaped is deliberately **not** here: devnet accounts and
prefixes live in [`e2e/`](../e2e/); use-case schemas (Terraform state,
k8s Lease, k8s RBAC, agentgate remediations) live in the sibling product repos —
a schema over the primitive is the code *you* write.

## Subpaths

| import | what you get |
|---|---|
| `@bitcd/core/protocol` | `ACTION` / `CONDITION_FELT` felt maps, `GLOBAL`, `str()`, `digestOf()`, `SHORTSTRING_MAX` + `assertShortString()` |
| `@bitcd/core/client` | `provider()`, `account()`, `bitcdContract()` (embedded ABI), `loadDeployment()`, `approveWithSigs()`, `applyNoProxy()` |
| `@bitcd/core/snip12` | the intent-binding typed data: `paramsHash`, `approvalTypedData`, `signApproval`, `assertRoundTrip` (byte-for-byte matched to `contracts/src/snip12.cairo`) |
| `@bitcd/core/reconcile` | the executor engine: `reconcileOnce`, `driftCheckOnce`, `makeChainOps`, `deriveCondition`, `renderConfig`, `CONDITION` (strings) |
| `@bitcd/core/fleet` | the predicate-voter engine + fleet-daemon shell: `decide`, `voteOnce`, `verifiedParams`, `makeVoterOps`, `makeFleetPeer`, `composePredicates`, `VOTE` (votes are reproducible predicates, never judgments) |
| `@bitcd/core/evidence` | `evidenceLog` / `chainLine` / `verifyChain` — the hash-chained JSONL evidence log (each agent's `{verdict, reason, evidence}`, tamper-evident) |
| `@bitcd/core/store` | `s3Store()` — the verify-on-read blob store (needs the optional `@aws-sdk/client-s3` peer dep) |
| `@bitcd/core/ceremony` | `deployBitcd`, `signerSpec`/`policySpec`, `runCeremony` — declare→deploy→seed→renounce as data-driven calls |
| `@bitcd/core/events` | `fetchAllEvents`, `projectKeys`, `projectProposals` — the materialized-view folds (depend on event names, not the ABI) |
| `@bitcd/core/artifacts` | `sierra()`/`casm()`/`abi()`/`manifest()` — env override → local scarb build → embedded |
| `@bitcd/core/fixtures` | demo-only sample data (no API promise) |
| `@bitcd/core/org/schema` | the `bitcd/v1` org declaration: `validateOrg(doc)` — a parsed document in, a normalized model out — plus `parseDuration`, `validateFieldSpec`, `FIELD_TYPES` |
| `@bitcd/core/org/invariants` | `checkInvariants(model)` — the security lints, as tagged compile errors (`[operator-diversity]`, `[person-reachable]`, …) |
| `@bitcd/core/org/compile` | `compileOrg(model)` → the ceremony seed (in `@bitcd/core/ceremony`'s shape), the `orgmanifest/v1` document, per-connector executor configs |
| `@bitcd/core/org/manifest` | the governed org manifest: `validateOrgManifest`, `canonicalOrgManifest`, `orgManifestDigest`, `manifestSpecKey`, `ORG_SCHEMA` |
| `@bitcd/core/org/loader` | `loadOrgManifest` (verify-on-read; classifies, never throws) + `makeGate` (RUN / HOLD / HALT) |
| `@bitcd/core/org/keys` | the `{param}` key template (`expandKey`, `templateFields`), `specKeyFor`, `SCHEMA_REF_RE` |
| `@bitcd/core/org/lint` | `lintSecrets` — secret-shaped field names and values are refused |
| `@bitcd/core/org/approvers` | `pickApprovers(pool, quorum)` — a satisfying approver set from a keystore (the CLI's development flows) |
| `@bitcd/core/pending` | the proposal side channel `<prefix>/proposals/<id>.{blob,json}`: `publishPending`, `locateCommitted`, `promoteCommitted` |
| `@bitcd/core/cli` | `runBitcd({ argv, parseYaml, verbs })` — the `bitcd` command as a function; a host adds its own verbs beside the built-in ones |

The `bitcd` CLI is [`bin/bitcd.mjs`](bin/bitcd.mjs): `validate`, `plan`,
`apply-ceremony`, `publish-manifest`, `diff`, `propose-changes` over one
`bitcd.yaml`. It is the only entry point that parses YAML, through the optional
`yaml` peer dependency; every library subpath takes parsed objects.

`starknet` ^9 is a **peerDependency** (never bundled — two starknet instances
break typed-data hashing). Core has **zero import side effects**; call
`applyNoProxy()` from your entrypoint if a proxy shadows your RPC host.

## Quick start — your own governed namespace

```js
import { provider, account, bitcdContract, approveWithSigs, str } from "@bitcd/core/client";
import { ACTION } from "@bitcd/core/protocol";
import { s3Store, digestOf } from "@bitcd/core/store";
import { reconcileOnce, makeChainOps, renderConfig } from "@bitcd/core/reconcile";

const p = provider(process.env.RPC);
const op1 = account({ address: OP1_ADDR, pk: OP1_PK }, p);
const c = bitcdContract(BITCD_ADDR, op1);                    // embedded ABI

// Desired state = a governed value under YOUR prefix (policies seeded at ceremony)
const PREFIX = str("flags/prod"), KEY = str("flags/prod/rollout");
const spec = renderConfig({ rollout: { canary: 0.05 } });    // canonical bytes
const store = s3Store({ endpoint: S3_URL, bucket: "myapp-governed" });
await store.putText("flags/prod/spec", spec);

const params = [KEY, digestOf(spec), str("flags/v1"), str("S3"), 0];
const { transaction_hash } = await c.propose(ACTION.SET_VALUE, PREFIX, params);
await p.waitForTransaction(transaction_hash);
await approveWithSigs({ contractAddress: BITCD_ADDR, proposalId, action: ACTION.SET_VALUE,
  prefix: PREFIX, params, signers: [human1, human2], p });   // SNIP-12 readable intent
await c.commit(proposalId);

// Your executor: verify-on-read -> apply -> attest observed (never writes desired)
await reconcileOnce(makeChainOps({
  view: c, writer: execContract, provider: p, valueKey: KEY,
  store, specKey: "flags/prod/spec", liveKey: "flags/prod/live",
}));
```

Deploy + seed your own instance with `@bitcd/core/ceremony` as data-driven
calls, or declare the org in a `bitcd.yaml` and onboard it with the `bitcd` CLI
(`node bin/bitcd.mjs` — validate → apply-ceremony → publish-manifest → diff).
[`example/bitcd.yaml`](example/bitcd.yaml) is a complete org, and
[`e2e/scripts/onboard.mjs`](../e2e/scripts/onboard.mjs) drives the
whole sequence.

## Sharp edges

- **Keys are Cairo shortstrings — 31 ASCII chars max** (`assertShortString`
  throws early). Real-world names need a hash-of-name scheme on top.
- **The embedded artifacts must match the audited commit.** `pnpm
  sync-artifacts` refreshes them + `MANIFEST.json`; CI recomputes the class hash
  and fails on drift. Deploys are gated on a clean `cairo-auditor` deep run
  (see `AGENTS.md`).
- **The SNIP-12 domain (`'bitcd'`, rev 1) is protocol identity**, baked into the
  on-chain `approval_digest` — it is not rebrandable without redeploying, and
  `snip12.mjs` must stay byte-for-byte matched to `contracts/src/snip12.cairo`
  (`assertRoundTrip` is the regression).
- **Never put accounts/private keys in this package.** Casts are consumer input.
