---
name: build-connector
description: Builds a bitcd connector, the executor that governs one real system (a cloud API, a cluster, a SaaS, a config file) through a bitcd contract, and proves it on the local devnet. Use this whenever someone wants bitcd to govern, gate, apply or revoke changes to a system, asks for an executor, provider, integration or connector for bitcd, or wants to extend the proof rig to a system of their own, even if they do not say "connector".
---

# Build a bitcd connector

A connector is the system an executor manages. The contract decides which
documents are desired; the executor fetches each committed document, checks
it against the digest on chain, applies it to the system and reports what it
observed through `set_status`, an entry point that cannot change desired
state. `@bitcd/core` provides that step. This skill builds the rest around a
template that already runs: the document shape, the provider over the system,
and the proof on the devnet.

Read `references/core-api.md` before writing the provider. It lists what the
library gives, with return shapes, and the facts of the proof rig.

## Before starting

Find out, if the request does not say:

- which system is governed and through which API or CLI it is reached;
- what one governed value is (one object, one assignment, one binding);
- what the connector may ever set, the delegated set;
- what revoking means for that system;
- how the agent will reach the system during the build (credentials, a
  sandbox, a local stand-in).

Prerequisites: a `bitcd-core` checkout with `pnpm install` run at its root,
Node 22 and pnpm via corepack, a running Docker engine, ports `5051` and
`4566` free, and `export NO_PROXY="localhost,127.0.0.1,0.0.0.0,ministack"` in
every shell that talks to the devnet.

## Steps

### 1. Run the proof rig

From the `bitcd-core` root. The organization in `e2e/bitcd.yaml` already
declares a connector (`demo-iam`) on prefix `iam/acct`; the template's checks
run against it.

```bash
docker compose up -d --wait devnet ministack   # the chain on :5051, the store on :4566
pnpm install
cd e2e && pnpm onboard                         # must end: onboard complete ... diff CLEAN
```

A second onboard needs a fresh chain (`docker compose down -v` first).
Transactions take about ten seconds each; let commands finish.

### 2. Copy the template and prove the loop

Copy `assets/template/` from this skill to a directory beside the
`bitcd-core` checkout, under the connector's name; `check.mjs` finds the rig's
keystore and deployment there by default. The template depends on
`@bitcd/core` from npm; if the version in `core/package.json` is not
published yet, point the dependency at the checkout instead
(`"@bitcd/core": "link:../bitcd-core/core"`). Then:

```bash
pnpm install
pnpm check            # must end: PASS: apply, drift, revision, failed apply, tombstone and the gate behaved
```

The template is a complete connector whose provider governs one JSON file on
disk. Proving it first separates loop problems from provider problems. What
`check.mjs` does, and the environment it reads, is in its header.

### 3. Declare the connector

In the organization file, add a connector and an intent type bound to it.
`type` is a free name; the executor gives it meaning. The role belongs to
this connector alone; the lints refuse an executor that also sits in an
approving quorum. `mutable` is mandatory, and `mutable: false` needs
`immutable_ack: true`.

```yaml
connectors:
  my-system:
    type: my-system
    role: EXEC_MYSYS
    executors: [exec1]
    config: {}                       # non-secret; published in the manifest
    credentials: {}                  # environment variable names only

intent_types:
  my-grant:
    connector: my-system
    prefix: my/grant
    schema: mygrant/v1
    key: "my/grant/{name}"
    params:
      name: { type: name, label: Grant, max_len: 12 }
    quorum: { threshold: 2, role: OPERATOR, min_humans: 1, max_per_operator: 1 }
    revoke: same
    attest: { k: 1 }
    mutable: false
    immutable_ack: true
```

Check it with `node core/bin/bitcd.mjs validate <file>` from the `bitcd-core`
root and fix every error; the lints are errors, not warnings. For the first
real run, declaring it in a copy of `e2e/bitcd.yaml` and onboarding that copy
on a fresh devnet (`BITCD_ORG_FILE=<copy> pnpm onboard`) keeps the rig's
development keys usable.

### 4. Replace the provider

`provider.mjs` is the only file that changes. Keep its four functions and
`sampleDocuments()`:

- `project(live)`: reduce what the system returns to the governed fields,
  dropping ids, timestamps and revisions the system adds, so the live hash
  moves only when a governed field moves.
- `assertWithin(spec, delegated)`: refuse anything outside the delegated set
  before touching the system. Derive the set from the verified manifest the
  gate returns, never from local configuration.
- `getLiveBlob()`: read, project, `renderConfig`; throw when nothing is there.
- `applyToProvider(text)`: parse, check, write.
- `revoke()`: remove what the connector manages.
- `liveExists()`: whether the managed object exists.
- `sampleDocuments()`: three documents the system accepts, for the checks.

Test the provider alone first, against the real system or a stand-in: read,
apply, read back, remove.

### 5. Prove the connector

Run `pnpm check` again with the environment pointed at the connector's own
key, prefix, schema and store key, and at the keystore and deployment of the
organization it was declared in (the header of `check.mjs` lists the
variables). All six checks must pass: apply, drift, revision, failed apply,
tombstone, gate. If a check fails, fix the provider, not the check.

### 6. Run it for real

`node executor.mjs watch` with the executor account, the deployment record and
the store in the environment; `bitcd plan` writes a `<connector>.env.example`
with the names. `node executor.mjs observe` prints desired, observed and the
derived condition at any time. If the documents carry an expiry, compare it
with the latest block's timestamp (`await p.getBlock("latest")`), never the
wall clock, then revoke and attest `expired` the way `pass` handles a
tombstone. For several keys, fold the contract's events with
`fetchAllEvents` and `projectKeys` and keep the keys under the connector's
prefixes.

## What must hold

- The executor account holds the connector's role and sits in no quorum.
- The executor never writes desired state; its governed write on chain is its
  own attestation.
- `applyToProvider` refuses anything outside the delegated set before
  touching the system.
- A missing or tampered document and a failing apply are attested `FAILED`;
  a live read that finds nothing attests hash zero. A report that reverts
  throws; never carry on as if it landed.
- Expiry and lease checks run on block time.
- The executor's credentials for the managed system cover what the connector
  manages and nothing wider.

Do not weaken the checks, the proof scripts or the lints to make a connector
pass.

## Report

State what system is governed and what one value is, which files changed,
the summary line of each `pnpm check` run, what was tested against the real
system and what only against the stand-in, and what was not tested. Tear down
with `docker compose down -v` when done, unless the user wants the chain kept.

## Where next

- The model: [Concept](https://bitcd.org/concept/).
- The page behind this skill: [Connectors](https://bitcd.org/connectors/).
- The library, subpath by subpath: [@bitcd/core](https://bitcd.org/docs/sdk/).
- `AGENTS.md` in the checkout: the invariants every change must keep.
