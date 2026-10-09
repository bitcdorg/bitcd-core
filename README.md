# bitcd-core

**A governed etcd on Starknet.** Changes to infrastructure and agent
configuration wait for sign-off under rules that live in a contract none of
the actors can edit. Executors apply what was approved and cannot change the
decision.

A key/value store with versions, leases, compare-and-set and an event stream.
A write passes its namespace's policy before it lands: a threshold, a role, a
floor of human approvals and a cap per operator. Starknet is the consensus
layer and events are the watch stream. A value is the fingerprint of a
document kept off-chain, and every bitcd reader re-hashes what it fetches and
refuses a mismatch, so the store needs no trust. People approve by signing a
readable SNIP-12 message bound to the exact change, never raw calldata. The
contract stores and gates; it never computes business logic. Not a database,
not a git replacement.

## Layout

| Component | What it is |
| --- | --- |
| [`contracts/`](contracts/) | The Cairo contract: locks (lease + CAS), generic governed KV (digest on-chain, blob off-chain), bounded declarative policy (threshold · human floor · approver diversity), spec/status split with k-of-n executor attestation, SNIP-12 intent-bound human approval, dynamic escalation. |
| [`core/`](core/) | `@bitcd/core`, the reusable JS library: protocol felts, contract client, SNIP-12 typed data, reconcile engine, fleet voter engine, hash-chained evidence log, S3 verify-on-read store, deploy/seed ceremony, event folds — plus the embedded compiled contract artifacts (class hash pinned in `MANIFEST.json`, CI-gated), and the org declaration: the `bitcd/v1` schema, its security lints and compiler, the governed org manifest with its verify-on-read loader, and the `bitcd` CLI that onboards an org from one `bitcd.yaml`. |
| [`indexer/`](indexer/) | The reference materialized view: folds `ValueChanged` + `StatusChanged` into "is everything `Synced`?" and the governance tally (machine vs intent-bound human approvals). Derivation is always off-chain — the contract never computes `Synced`. |
| [`e2e/`](e2e/) | The devnet proof rig: `bitcd.yaml` (the declared dev org) onboarded through the `bitcd` CLI — deploy, ceremony, renounce, constitution, `diff` CLEAN — then PASS/FAIL beats for lock contention, governed state, reconcile, k-of-n redundancy, human approval, and escalation; one command runs them all. |

## Install

```bash
npm install @bitcd/core starknet                        # the library; starknet ^9 is a peer dependency
npm install -g @bitcd/core starknet @aws-sdk/client-s3  # the bitcd command; the SDK is for the document store
```

`@aws-sdk/client-s3` is an optional peer: `@bitcd/core/store` needs it, and
so do the CLI commands that read or write the store (`publish-manifest`,
`diff`, `propose-changes`); `validate` and `plan` do not. Inside this
repository, and for unreleased work, consumers link the checkout instead:
`"@bitcd/core": "link:../bitcd-core/core"`.

## Release

A version tag publishes `core/` to npm through `.github/workflows/publish.yml`:
bump `core/package.json`, tag the commit `v<version>`, push the tag. The
workflow rebuilds the contract, refuses embedded artifacts that drift from it,
runs the library tests, checks the tag against the package version and
publishes with provenance. It needs the `NPM_TOKEN` repository secret, an npm
automation token for the `@bitcd` scope. Run it by hand (Actions → publish)
for a dry run that packs and lists the tarball without publishing.

## Run

```bash
cd contracts && scarb build && snforge test                        # the contract
pnpm install                                                       # repo root, once
starknet-devnet --seed 0 --host 0.0.0.0 --port 5051 --accounts 16  # terminal 1: the chain
docker compose up -d ministack                                     # S3 blob store
cd e2e && node scripts/demo.mjs                                # terminal 2: every beat end-to-end
pnpm test                                                          # pure library tests (no devnet)
```

To run the ladder without a host toolchain, use Docker:
`docker compose run --rm builder`, `docker compose up -d devnet ministack`,
then `docker compose run --rm e2e`. The
[`try-bitcd`](skills/try-bitcd/SKILL.md) skill explains the commands,
expected output and reset procedure for a newcomer or their coding agent;
[`build-connector`](skills/build-connector/SKILL.md) walks an agent
through an executor over `@bitcd/core/reconcile` for a system of your own.

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

## Building on it

A new workflow is a namespace, a document schema and an executor over
`@bitcd/core/reconcile`; the contract does not change. Use-case code lives
outside this repo. The [`build-connector`](skills/build-connector/SKILL.md)
skill walks a coding agent through an executor for a system of your own, and
[bitcd.org/connectors](https://bitcd.org/connectors/) shows the shape with the
connectors that exist for Terraform, AWS IAM and Kubernetes. The site itself,
[bitcd.org](https://bitcd.org), carries the concept, the contract reference
and the quickstart.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and the golden rules in
[`AGENTS.md`](AGENTS.md); governance-touching changes gate on a clean
`cairo-auditor` deep run. Security reports: [`SECURITY.md`](SECURITY.md).
License: Apache-2.0.
