# What `@bitcd/core` gives a connector

Every import is a subpath; there is no root export. `npm install @bitcd/core
starknet` installs it; against an unreleased checkout, depend on it by path
(`"@bitcd/core": "link:../bitcd-core/core"`).

## `@bitcd/core/reconcile`

The step every executor shares. It does no I/O; everything comes in through
`ops`:

```
getValue()            -> { digest, schema_ref, storage_class, version, tombstoned }
getStatus()           -> { observed_revision, observed_digest, condition, status_version, exists }
getSpecBlob()         -> string            // the desired document, from the store
getLiveBlob()         -> string            // re-read the system; throw if nothing is there
applyToProvider(text) -> void              // called only with a verified document
setStatus({ observed_revision, applied_hash, condition, reason })
digestOf(text)        -> "0x..."
log?(msg)
```

| Export | Does |
| --- | --- |
| `reconcileOnce(ops, {failApply?, reportFailure?})` | Reads the value (a tombstone returns `{condition: "TOMBSTONED", version}` and touches nothing). Fetches the document and re-hashes it; a missing or mismatched one is attested `FAILED` with reason `spec-missing` or `spec-tamper`. Calls `applyToProvider`; a throw is attested `FAILED` with `apply-error`. Then re-reads the live side and attests `SYNCED` with the live hash at the desired version. Returns `{condition, observedDigest, desiredDigest, present, version}` or `{condition: "FAILED", reason, version, error?}`. |
| `driftCheckOnce(ops)` | The re-read and attest alone. Same return shapes. |
| `deriveCondition({desiredVersion, desiredDigest, observedRevision, observedDigest, claimed})` | What a reader concludes: `SYNCED` when the observed revision has caught up and the hashes match; `FAILED` when the executor claimed a failure; `OUTOFSYNC` otherwise, including a new revision not yet applied. |
| `renderConfig(config)` | Canonical JSON (keys sorted recursively, no whitespace), so whoever proposes a document and whoever applies it hash the same bytes. |
| `makeChainOps({view, writer, provider, valueKey, store, specKey, liveKey?, getLiveBlob?, applyToProvider?, log?})` | Builds `ops` from a read-only contract handle, the executor's contract handle, the provider, the value key (a felt from `str`), a store and the document's key in it. Pass `getLiveBlob` and `applyToProvider` for a real system; without them the live side is `liveKey` in the store. `setStatus` waits for the transaction and throws if it reverted. |
| `CONDITION` | `SYNCED`, `OUTOFSYNC`, `FAILED`, `PROGRESSING` as strings. |

An executor never attests `OUTOFSYNC`; readers derive it. A live read that
finds nothing attests `SYNCED` with hash `0x0`. A failed apply never changes
desired state; a rollback is a new governed revision.

## `@bitcd/core/client`

| Export | Does |
| --- | --- |
| `provider(url?)` | An RPC provider; `BITCD_RPC`, default `http://localhost:5051`. |
| `account({address, pk}, provider)` | A starknet.js account. |
| `bitcdContract(address, providerOrAccount)` | The contract handle: `get_value`, `get_status`, `propose`, `commit`, `set_status`, ... |
| `loadDeployment(file?)` | The deployment record (`address`, class, block); `BITCD_DEPLOYMENT_FILE`. |
| `str(name)` | A Cairo short string (31 ASCII characters at most). |
| `applyNoProxy(hosts?)` | Keeps a local proxy away from `localhost`; call it first in any script that talks to the devnet. |
| `approveWithSigs({contractAddress, proposalId, action, prefix, params, signers, relayer?, p})` | Collects SNIP-12 signatures from `signers` (`{address, pk}`), checks each against the contract's `approval_digest`, relays them through `approve_sigs` and waits. |
| `waitSucceeded(provider, txHash, what)` | Waits for a transaction and throws if it reverted. |

## `@bitcd/core/store`

`s3Store({endpoint?, bucket?, region?, credentials?})` reads `BITCD_S3_ENDPOINT`
(default the dev stack on `:4566`), `BITCD_S3_BUCKET` (default `bitcd-tfstate`)
and AWS credentials from the environment. Methods: `getText(key)`,
`putText(key, text)`, `ensureBucket()`, `deleteObject(key)`. `digestOf(text)`
is the same hash the contract compares.

## `@bitcd/core/org/loader` and `/org/manifest`

`loadOrgManifest({getValue, getBlob, valueKeyStr})` reads the organization's
definition by verify-on-read and never throws: `{ok: true, manifest, version,
digest}`, `{ok: false, class: "transient", reason}` when the chain or store is
unreachable, `{ok: false, class: "terminal", reason}` for a missing manifest, a
tombstone, a wrong schema, a digest mismatch, non-canonical bytes or an invalid
manifest.

`makeGate({load, graceMs})` wraps that: `check()` answers `RUN` with the verified
manifest (`stale: true` when it is the last good one inside the grace window),
`HOLD` before anything has verified, or `HALT` on any terminal failure or a
transient one past the grace. Nothing unverified reaches `RUN`.

`DEFAULT_MANIFEST_KEY` is `sys/manifest`; `manifestSpecKey(key)` is where the
blob lives in the store (`<key>/spec`).

The manifest carries `connectors[]` (`name, type, role, executors, config,
credentials`) and `intent_types[]` (`name, connector, prefix, schema, key,
key_fields, params, ttl?, quorum, revoke, attest, summon_human, mutable`), plus
`signers[]` and `roles[]`. Take the connector's prefixes and its delegated set
from here, never from local configuration.

## `@bitcd/core/events`

`fetchAllEvents(provider, address, {fromBlock?})` pages through the contract's
events from its deployment block. `projectKeys(events)` folds them into one
record per value key (`desired`, `observed`, `votes`); `projectProposals(events)`
into one per proposal. Use them to find every key under the connector's
prefixes.

## `@bitcd/core/protocol`

`ACTION.SET_VALUE`, `ACTION.TOMBSTONE_VALUE`, `ACTION.SET_STATUS`, ... as felts;
`STORAGE_CLASS.S3`; `digestOf`; `str`.

## The proof rig (`e2e/`)

`e2e/bitcd.yaml` declares the connector `demo-iam` (type `s3-demo`, role
`EXEC_IAM`, executors `exec1`..`exec3`) and the intent type `iam-acct` on
prefix `iam/acct` with key `iam/acct/{name}`, quorum 2-of-OPERATOR with one
human and one per operator, `attest: {k: 1}`, `mutable: false`. The scripts use
the key `iam/acct/pset`, the document at `iam/acct/spec` in the bucket
`bitcd-tfstate`, and the schema `iampolicyset/v1`.

`pnpm onboard` in `e2e/` deploys it on a fresh devnet, renounces, publishes the
manifest and reads everything back (`diff` must end `CLEAN`). It writes
`e2e/deployment.json` and the development keystore
`e2e/.onboard-tmp/keys.json` (`genesis`, `agent1`..`agent3`,
`exec1`..`exec3`, each `{address, pk}`). `agent1` and `agent2` are the human
operators on different operators; `exec1` is the executor.

Transactions take about ten seconds each on the devnet. TTLs are crossed with
the `devnet_increaseTime` JSON-RPC, never a wall-clock wait. A second onboard
needs a fresh chain: `docker compose down -v` first.
