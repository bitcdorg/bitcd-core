# bitcd e2e

A lean, process-based local proof rig (no docker) with **3 agent wallets** and
**3 executor wallets** driven by **starknet.js v9** scripts that onboard the
declared dev org and exercise every substrate property as PASS/FAIL beats
against a local `starknet-devnet`. Start the chain
(`starknet-devnet --seed 0 --host 0.0.0.0 --port 5051 --accounts 16`) and the
blob store (`docker compose up -d ministack`), then `node scripts/demo.mjs` —
or the steps individually: `pnpm onboard`, `pnpm contend`, …. The onboard step
drives `@bitcd/core`'s `bitcd` CLI (`../core/bin/bitcd.mjs`) over `bitcd.yaml`.
Toolchain pins and environment notes: [`AGENTS.md`](../AGENTS.md).

## Files

- `bitcd.yaml` — the declared dev org: the cast, the `tf/lock` lock with the
  one open-value slot, the `iam/acct` + `iam/prod` intent types on the
  `s3-demo` connector, the `demo/preflight` agent-autonomy value, the
  constitution.
- `scripts/config.mjs` — shared config: RPC URL, fixtures
  (prefixes/locks/roles/actions), the genesis + agent + executor wallets from
  devnet seed 0 (with `is_human` / `operator_id` / `role` for the diversity
  rule), and `approveWithSigs` (collect SNIP-12 signatures → round-trip-assert
  → relay).
- `scripts/onboard.mjs` — `bitcd validate → apply-ceremony → publish-manifest
  → diff` through the `bitcd` CLI: declare + deploy as genesis, seed signers
  and per-prefix policies, `renounce_ownership` (no single actor remains),
  commit the org manifest, and read everything back (CLEAN). Writes
  `deployment.json`.
- `scripts/contend.mjs` — lock contention: 3 wallets contend for one lock
  (win / reject / TTL handover).
- `scripts/store.mjs` — governed state over untrusted storage: acquire → write
  blob to S3 → commit digest → verify-on-read → tamper → reject.
- `scripts/reconcile.mjs` — the control-plane loop, 5 beats: reconcile / drift
  / reconverge / new-revision lag / failed-apply-never-rewrites-desired.
- `scripts/redundancy.mjs` — k-of-n executor attestation, 3 beats: agree →
  `SYNCED` / dissent → `DISAGREE` / Byzantine out-voted.
- `scripts/human-approve.mjs` — SNIP-12 intent-bound approval, 2 beats
  (governed `SET_VALUE` + `force_unlock`).
- `scripts/escalate.mjs` — dynamic escalation, 3 beats: a doubting agent
  forces a human into a `min_humans = 0` quorum.
- `scripts/demo.mjs` — orchestrates all of the above in order:
  onboard → contend → store → reconcile → redundancy → human-approve →
  escalate. Each step exits non-zero unless it passes.

The connector proofs (Terraform backend, Kubernetes lease and RBAC, AWS IAM)
and the fleet proofs live outside this repo, each with its own harness beats.

TTL expiry is crossed with the `devnet_increaseTime` JSON-RPC, never wall-clock
sleep — devnet advances block timestamps in coarse, unpredictable jumps.
