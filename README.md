# bitcd-core

**A governed `etcd` on Starknet — the substrate.** A key/value control plane
whose **writes are gated by on-chain multisig policy**. Not a database; not a
git replacement. The contract **stores and gates — it never computes business
logic.**

Mental model: etcd's API surface (key, version, watch, lease, compare-and-set)
with **consensus-gated writes**. Starknet is the consensus layer (no Raft),
events are the `watch` stream, and large values live off-chain with only a
digest on-chain (`verify-hash-on-read` makes the storage untrusted). Humans
approve **readable intent** (SNIP-12), provably bound to the calldata that
commits — never raw hex.

## Layout

| Component | What it is |
| --- | --- |
| [`contracts/`](contracts/) | The Cairo contract: locks (lease + CAS), generic governed KV (digest on-chain, blob off-chain), bounded declarative policy (threshold · human floor · approver diversity), spec/status split with k-of-n executor attestation, SNIP-12 intent-bound human approval, dynamic escalation. |
| [`core/`](core/) | `@bitcd/core`, the reusable JS library: protocol felts, contract client, SNIP-12 typed data, reconcile engine, fleet voter engine, hash-chained evidence log, S3 verify-on-read store, deploy/seed ceremony, event folds — plus the embedded compiled contract artifacts (class hash pinned in `MANIFEST.json`, CI-gated), and the org declaration: the `bitcd/v1` schema, its security lints and compiler, the governed org manifest with its verify-on-read loader, and the `bitcd` CLI that onboards an org from one `bitcd.yaml`. |
| [`indexer/`](indexer/) | The reference materialized view: folds `ValueChanged` + `StatusChanged` into "is everything `Synced`?" and the governance tally (machine vs intent-bound human approvals). Derivation is always off-chain — the contract never computes `Synced`. |
| [`e2e/`](e2e/) | The devnet proof rig: `bitcd.yaml` (the declared dev org) onboarded through the `bitcd` CLI — deploy, ceremony, renounce, constitution, `diff` CLEAN — then PASS/FAIL beats for lock contention, governed state, reconcile, k-of-n redundancy, human approval, and escalation; one command runs them all. |

## Run

```bash
cd contracts && scarb build && snforge test                        # the contract
pnpm install                                                       # repo root, once
starknet-devnet --seed 0 --host 0.0.0.0 --port 5051 --accounts 16  # terminal 1: the chain
docker compose up -d ministack                                     # S3 blob store
cd e2e && node scripts/demo.mjs                                # terminal 2: every beat end-to-end
pnpm test                                                          # pure library tests (no devnet)
```

The onboard step drives this repo's `bitcd` CLI (`core/bin/bitcd.mjs`).
Toolchain pins and environment notes are in [`AGENTS.md`](AGENTS.md).

## Security model

**Desired state is consensus-written, observed state is executor-written, and
the two write surfaces are disjoint.** A compromised executor can attest, but
never grant itself anything; a failed apply can never rewrite desired; drift
surfaces as `OutOfSync`, never as a silent green. Policy is bounded declarative
data — there is deliberately **no on-chain scripting language**, and that is
permanent. The invariants every contract change must preserve are listed in
[`AGENTS.md`](AGENTS.md).

## Sibling repos

Everything use-case-shaped consumes `@bitcd/core` from here (filesystem
`link:` deps between side-by-side clones):

| Repo | What it is |
| --- | --- |
| `agentgate` | Peer mutual-gating agent fleets: deterministic predicate voters, pre-flight notaries, the `agentgate` CLI, and the LLM acting layer (proposes and pages — never votes). |
| `chainops` | The reconcile executor, the intent side of the DSL (the grant envelope, request forms, `bitcd intent new` / `revoke`), and reference integrations: Terraform http-backend, k8s DR leader-lease, governed k8s RBAC, AWS IAM. |
| `capability-ledger` | Governed agent capability & tool manifests. |
| `console` | The cross-product management UI (per-product panels; the products themselves are headless). |
| `docs` | The bitcd.org site — concepts, quickstart, the DSL reference, and the design record. |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and the golden rules in
[`AGENTS.md`](AGENTS.md); governance-touching changes gate on a clean
`cairo-auditor` deep run. Security reports: [`SECURITY.md`](SECURITY.md).
License: Apache-2.0.
