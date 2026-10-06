# AGENTS.md — bitcd-core working guide

Loaded automatically by Claude Code at the start of a session. The operating
manual for this repo: what it is, the rules that must not be broken, the
security invariants, and the environment quirks.

## What bitcd-core is

The **substrate** of bitcd, a governed `etcd` on Starknet: a key/value control
plane whose **writes are gated by on-chain multisig policy**. The contract
**stores and gates — it never computes business logic.** Mental model: etcd's
API surface (key, version, watch, lease, compare-and-set) with
**consensus-gated writes**. Starknet is the consensus layer (no Raft); events
are the `watch` stream. Locks are the first schema over the primitive; the
primitive itself is generic governed KV. **Humans approve readable intent
(SNIP-12), provably bound to the calldata that commits** — not raw hex.

This repo holds `contracts/` (the Cairo contract), `core/` (`@bitcd/core`, the
reusable JS library with the embedded compiled artifacts, the org declaration
and the `bitcd` CLI), `indexer/` (the reference read-model), and `e2e/`
(the devnet proof rig). The product repos
— **agentgate**, **chainops**, **capability-ledger**, **console** — are siblings
under `bitcdorg/` and consume `@bitcd/core` from here (`link:` filesystem deps
between side-by-side clones). Use-case code does NOT belong in this repo. An
org's *declaration* is substrate — the `bitcd/v1` schema, its compiler, the
governed org manifest, and the `bitcd` CLI that onboards an org live in `core/`;
what an org does under its intent types (grant envelopes, connectors,
executors, UIs) is use-case code. The design record and outward-facing docs
live in the `docs` repo (the bitcd.org site).

## Golden rules (never violate)

- **The contract is dumb.** It stores and gates; it never computes business logic.
  All cleverness lives in off-chain agents that *propose*. If you are tempted to
  add logic to the contract, that temptation is the signal to move it off-chain.
- **No on-chain scripting / predicate / expression language.** Policy is bounded,
  declarative data. Permanent anti-goal — a new knob is a struct field, never a language.
- **The org declaration is bounded declarative data too.** Closed field sets,
  closed enums, literal strings, durations — a new need is a new field type,
  never an expression. The compiler (`core/src/org/`) turns envelope violations
  (the single open-value slot, equal-strength recovery gates, per-domain
  executor roles, a reachable person, quorum satisfiability, 31-char keys,
  secrets) into compile errors.
- **Control plane, not data plane.** Never assume per-request reads of the chain.
- **Append-only.** Logical delete is a tombstone, never a real delete. `version`
  is monotonic; every mutating write is compare-and-set against `expected_version`.
- **Time only from `get_block_timestamp()`.** Never trust caller-supplied time.
- **Use OpenZeppelin Cairo components** for access control / ownership.

## Security invariants that MUST survive any contract change

Any change touching governance, policy, or the `commit` dispatch must preserve
**all** of these and re-run the deep audit:

1. **Scope binding.** The authorizing policy's `(prop_prefix, action)` must equal
   the operation's real target scope — `commit` asserts it per action, and
   `SET_ROLE` is confined to `GLOBAL`. Trap: a quorum over a weak prefix acting
   as a master key elsewhere (confused deputy).
2. **Governance threshold floor.** An *active* governance policy is never
   `allow_open` and has `threshold >= 1`, on both write paths (owner seed and
   governed commit); `satisfies()` also requires `eligible >= 1`. Only `ACQUIRE`
   and open-mode `SET_VALUE` may be open.
3. **Strengthen-only ratchet.** One `SET_POLICY` quorum may only *strengthen* an
   existing governance gate in its scope (its own or a sibling's), across all six
   `Policy` fields: no clearing, no role change, no lower threshold/human floor,
   no loosening a finite diversity cap. Trap: a quorum weakening the gate that
   authorized it, or clearing it into a permanent post-renounce lockout.
4. **TTL overflow safety.** `is_expired` uses `now - acquired_at >= ttl`, never
   `acquired_at + ttl`: a ttl near `u64::MAX` must not panic `acquire`.
5. **Diversity counts only eligible approvers.** `operator_count` applies the same
   `role_ok` filter as the eligibility loop, or wrong-role signers spuriously reject.
6. **First-touch prefix pin.** `key_prefix[lock_key]` / `value_prefix[value_key]`
   are write-once (`'acquire: prefix rebind'`, `'value: prefix rebind'`); prefix
   `0` is the "unbound" sentinel and is rejected. The force-unlock and status
   scope checks trust this pin, so no path may rewrite or zero it. Envelope: any
   number of open-`ACQUIRE` prefixes (each with an equal-strength `FORCE_UNLOCK`)
   but exactly **one** open-`SET_VALUE` prefix — a hijacked value has no recovery.
7. **Dual-mode value commitment.** `SET_VALUE` is **open** (the live lock *is* the
   write capability) or **governed** (the quorum is), mutually exclusive per
   prefix (`'value: governed'` / `'commit: value is open'`). It stays OUT of
   `is_governance_action`; `TOMBSTONE_VALUE` (quorum-only) is IN. `tombstoned` is
   a logical delete — put-after-delete recreates the key. The chain stores
   `{digest, schema_ref, storage_class}`, never bytes; the reader verifies on read.
8. **Spec/status disjoint authority.** Desired (the value) is consensus-written;
   observed (`StatusRecord`) is executor-written via `SET_STATUS`, which writes
   only `status_*`/`attest_*`/`attester_*` — no spec path writes them — so a failed
   apply can never rewrite desired (it reports `FAILED`; rollback is a new governed
   revision). `SET_STATUS` is never `allow_open`. The contract never computes
   `Synced`; the indexer derives it from `observed_revision`/`observed_digest`.
9. **Scope-bound executor status.** `SET_STATUS` is gated by the value's own
   write-once prefix: the `(prefix, SET_STATUS)` role must match the caller's
   active `Signer.role`; an unbound value is rejected. Use per-domain executor
   roles (e.g. `EXEC_IAM`), never a shared `EXECUTOR` — role is global identity,
   so a shared role is a cross-namespace status-write capability. `status_version`
   is its own CAS line; `observed_revision <= value.version`, monotonic per slot.
10. **k-of-n attestation integrity.** Each executor writes only its own
    `attest_*[(value_key, caller)]` slot (one executor = one vote), so re-attesting
    never self-satisfies k. Promotion needs `satisfies()` over the active,
    role-eligible executors agreeing at the current revision; the aggregate never
    regresses. `DISAGREE` is contract-set only and idempotent per revision; an
    honest diverse quorum overrides it. k=1 is single-writer — same record.
11. **Intent-bound human approval.** A human counts toward `min_humans` ONLY via
    `approve_sigs`: `_approver_set` masks `is_human` with `prop_intent_signed`, so
    `policy.cairo` stays unchanged. The SNIP-12 hash is recomputed from immutable
    stored state (`{contract, chain_id, proposal_id, action, prefix, params_hash}`
    + approver) — no replay, swap, or re-attribution; the relayer is untrusted.
    Verification is the approver's SRC6 `is_valid_signature` (exact `'VALID'`),
    fenced by CEI, all-or-nothing batches, `MAX_SIGS_PER_CALL`, and a reentrancy
    guard on `approve`/`approve_sigs`/`request_human_review`/`commit`.
    `snip12.cairo` MUST match `core/src/snip12.mjs` byte-for-byte.
12. **Strengthen-only dynamic escalation.** `prop_human_required` is
    write-once-true (only `request_human_review` sets it; nothing clears it). It
    only raises the floor — `commit` feeds `satisfies()` a local copy with
    `max(min_humans, 1)`, never touching the stored policy — and is enforced at
    commit, not as a vote, so a sub-quorum cannot out-vote it. Callers are bounded
    to eligible approvers; a rogue eligible signer costs liveness only, and there
    is no symmetric "skip the human" path.

**Acceptance gate for any governance change:** `cairo-auditor` deep run
(5 specialists incl. an adversarial pass) with no unresolved high/critical.

## Build / test / run

```bash
cd contracts && scarb build && snforge test            # the contract — must stay green
pnpm sync-artifacts                                    # after ANY contract change: re-embed + restamp MANIFEST
starknet-devnet --seed 0 --host 0.0.0.0 --port 5051 --accounts 16    # chain; + `docker compose up -d ministack` for S3
cd e2e && node scripts/demo.mjs                        # onboard (e2e/bitcd.yaml via the bitcd CLI) -> contend -> store -> reconcile -> redundancy -> human-approve -> escalate
pnpm test                                              # pure library tests (protocol, SNIP-12 binding, engines, evidence chain, the org declaration)
node core/bin/bitcd.mjs validate e2e/bitcd.yaml        # the org declaration, offline: schema + security lints
```

`pnpm install` once at the repo root (pnpm workspace, one lockfile). The onboard
step drives `core/bin/bitcd.mjs` (`BITCD_DSL_CLI` points it at another build)
and needs a FRESH devnet. The compose path does the same hermetically: `docker compose run --rm builder`, `docker compose up -d
devnet ministack`, `docker compose run --rm e2e`.

**Artifact discipline:** `core/artifacts/` embeds the compiled contract;
`MANIFEST.json` pins `classHash ↔ gitCommit`. CI rebuilds the contract and fails
if the embedded class hash drifts ("EMBEDDED ARTIFACTS ARE STALE"). A stale
embed is a silent lie — never hand-edit the artifacts, and run `pnpm
sync-artifacts` only when `contracts/src/` changed.

## Environment quirks

- Toolchain pins (`.tool-versions`): Scarb 2.19.1 / Cairo 2.19.0 / Sierra 1.9.0,
  Starknet Foundry (snforge) 0.62.1, starknet-devnet 0.9.1 (RPC 0.10.2). Install
  scarb and Starknet Foundry via their official installers if missing.
- `export NO_PROXY="localhost,127.0.0.1,0.0.0.0,ministack"` — localhost RPC must
  bypass any local proxy. `@bitcd/core` never mutates the environment; the
  e2e scripts and daemons call `applyNoProxy()` explicitly.
- TTL expiry is crossed with `devnet_increaseTime` (tests:
  `start_cheat_block_timestamp`), never wall-clock sleep — devnet block
  timestamps advance in coarse jumps.
- A stale `e2e/deployment.json` makes `apply-ceremony` "resume" against a
  contract the devnet does not have; `onboard.mjs` removes it — start from a
  fresh devnet.
- Machine-specific install notes may live in `CLAUDE.local.md` (gitignored).
- **Never commit secrets** — `*.key`, `*.pem`, `.env*`, `**/accounts/*.json`,
  `secrets/` are gitignored; keep it that way.

## Repo layout

```
contracts/      Scarb package: the Cairo contract (modules: lib / events /
                governance / locks / policy / snip12) + snforge tests
core/           @bitcd/core: protocol felts, client (+ approveWithSigs), snip12
                typed data, reconcile engine + makeChainOps, fleet voter engine +
                makeFleetPeer, hash-chained evidence log, s3Store (verify-on-read),
                ceremony (deploy/seed/renounce), event folds, EMBEDDED compiled
                artifacts (MANIFEST.json pins classHash<->commit); the org
                declaration (src/org/: bitcd/v1 schema, security lints, compiler,
                orgmanifest/v1 + its verify-on-read loader/gate, key templates),
                the proposal side channel (pending), and the bitcd CLI (src/cli.mjs
                + bin/bitcd.mjs: validate / plan / apply-ceremony /
                publish-manifest / diff / propose-changes; example/bitcd.yaml is
                a complete org). Demo casts and use-case schemas deliberately
                live OUTSIDE core.
indexer/        reference materialized view: folds ValueChanged+StatusChanged,
                derives Synced; folds ProposalApproved+ApprovalSigned -> intent tally
e2e/            starknet-devnet proof rig: bitcd.yaml (the declared dev org) +
                onboard / contend / store / reconcile / redundancy / human-approve /
                escalate / demo — onboarded through core's own bitcd CLI
.claude/skills/ bitcd-core-dev — the working-in-this-repo skill
```

Sibling repos (each consumes `@bitcd/core` via `link:`): `../agentgate` (fleet
peers, notaries, CLI), `../chainops` (executor + the intent side of the DSL —
grant envelope, request forms, `bitcd intent` — + Terraform/k8s/IAM integrations), `../capability-ledger` (capmanifest
loader/attest), `../console` (management UI), `../docs` (the bitcd.org site).

## Conventions

- **Explain non-obvious choices where they apply** — in the comment or README
  next to the code. The design record lives in the `docs` repo; do not restate
  history here.
- **Substrate non-goals are tripwires.** Use-case schemas, product daemons, and
  UI belong in the sibling repos — if a change here needs one of those, it is
  scope creep into the wrong repo.
- **Nothing here reaches into a product repo.** The library, its tests, the
  e2e rig, the images, and CI build and run from this checkout alone; CI fails
  on a path into a sibling product.
- Sibling repos consume `core/src/*` exports via `link:` — breaking an export
  surface breaks them silently; grep the siblings before removing or renaming.
  The same holds for the `bitcd` CLI's verbs, flags, and output: every repo's
  onboarding drives it.
- Voice: precise, present tense, rationale-first. The product name is lowercase
  `bitcd` (like etcd), even at sentence start; only the Cairo module `Bitcd`
  keeps its capital.
