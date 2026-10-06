---
name: bitcd-core-dev
description: Working in the bitcd-core repo — the build/test/demo loop, the artifact-sync discipline, and the pre-flight checklist for contract changes. Use when building or testing the Cairo contract, running the devnet demo, refreshing embedded artifacts, or changing anything under contracts/ or core/.
---

# bitcd-core development

The substrate repo: Cairo contract (`contracts/`) + `@bitcd/core` (`core/`) +
reference indexer + the devnet e2e rig. `AGENTS.md` holds the golden rules, the
security invariants, and the toolchain pins; this skill is the condensed
working loop.

## The build/test loop

```bash
cd contracts && scarb build && snforge test    # MUST stay green
pnpm install                                   # once, repo root (pnpm workspace)
pnpm test                                      # pure library tests (no devnet)
```

Toolchain pins (`.tool-versions`): Scarb 2.19.1 / Cairo 2.19.0 / Sierra 1.9.0,
Starknet Foundry (snforge) 0.62.1, starknet-devnet 0.9.1. Install scarb and
Starknet Foundry via their official curl installers if missing.

## The devnet proof loop

```bash
export NO_PROXY="localhost,127.0.0.1,0.0.0.0,ministack"
starknet-devnet --seed 0 --host 0.0.0.0 --port 5051 --accounts 16   # terminal 1
docker compose up -d ministack                                      # S3 on :4566
cd e2e && node scripts/demo.mjs                                 # terminal 2
```

`demo.mjs` runs onboard (the declared org `e2e/bitcd.yaml` through
`core/bin/bitcd.mjs` — deploy + ceremony + renounce + constitution
+ `diff` CLEAN) → contend → store → reconcile → redundancy → human-approve →
escalate; every beat exits non-zero on failure. Individual beats re-run à la
carte after onboard. Onboard needs a FRESH devnet (it removes a stale
`deployment.json` itself). TTL expiry is crossed with `devnet_increaseTime`
(tests: `start_cheat_block_timestamp`) — never wall-clock sleep.

## Artifact-sync discipline (every contract change)

`core/artifacts/` embeds the compiled Sierra+CASM; `MANIFEST.json` pins
`classHash ↔ gitCommit`. CI rebuilds and fails on drift ("EMBEDDED ARTIFACTS
ARE STALE").

After ANY change under `contracts/src/`:

```bash
cd contracts && scarb build && snforge test
cd .. && pnpm sync-artifacts        # re-embeds + restamps MANIFEST.json
```

Never hand-edit `core/artifacts/*`. If only docs/JS changed, do NOT run
sync-artifacts (it would restamp the commit pin for no reason).

## Pre-flight checklist for contract changes

Before touching `contracts/src/`, confirm the change survives ALL of these
(full text: `AGENTS.md` "Security invariants"):

1. Golden rules: contract stores and gates only — no business logic, no
   on-chain scripting/expression language (bounded declarative policy only),
   append-only (tombstones, monotonic `version`, CAS everywhere), time only
   from `get_block_timestamp()`, OpenZeppelin components for ownership/access.
2. Scope binding: authorizing policy scope == real target scope; `SET_ROLE`
   confined to `GLOBAL`.
3. Governance floor: active governance policy never `allow_open`,
   `threshold >= 1`, `eligible >= 1`. Only `ACQUIRE` and open-mode `SET_VALUE`
   may be open.
4. Strengthen-only ratchet: one `SET_POLICY` quorum can only strengthen an
   existing governance gate, across all six Policy fields.
5. TTL subtraction form; diversity counts only eligible approvers.
6. First-touch prefix pin is write-once — no path may rewrite or zero
   `key_prefix`/`value_prefix`; one open-`SET_VALUE` prefix max per deployment.
7. Spec/status disjoint write surfaces: no spec path writes `status_*`,
   `set_status` writes only `attest_*`/`attester_*`/`status_*`; the contract
   never computes `Synced`.
8. k-of-n attestation: one executor = one slot; promotion only via
   `satisfies()`; `DISAGREE` is contract-set only.
9. SNIP-12 intent binding: `snip12.cairo` must stay byte-for-byte matched to
   `core/src/snip12.mjs`; human votes count toward `min_humans` only when
   intent-bound; reentrancy fences on `approve`/`approve_sigs`/
   `request_human_review`/`commit`.
10. Dynamic escalation is write-once-true, strengthen-only, enforced at commit.

**Acceptance gate:** any change touching governance, policy, or `commit`
dispatch requires a `cairo-auditor` deep run (5 specialists incl. adversarial)
with zero unresolved high/critical, plus regression tests named for the
property they pin.

## Repo discipline

- This repo is the substrate. Use-case schemas, product daemons, UI → sibling
  repos (`../agentgate`, `../chainops`, `../console`). If a change here needs
  one of those, it's in the wrong repo.
- Explain non-obvious choices in the comment or README where they apply; the
  design record lives in the `docs` repo.
- Never commit secrets; `**/accounts/*.json`, `.env*`, keys are gitignored.
- Sibling repos consume `@bitcd/core` via `link:` filesystem deps — breaking a
  `core/src/*` export surface breaks them silently; grep the siblings before
  removing/renaming exports.
